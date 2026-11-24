// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/spam"
	"github.com/gsoultan/talaria/internal/store"
)

// Deliverer files inbound messages into local mailboxes.
type Deliverer struct {
	Store    *store.Store
	Blobs    *blob.Store
	Hub      *hub.Hub
	Checker  *Checker
	Spam     *spam.Scorer // nil turns spam scoring off
	Hostname string
	TmpDir   string
	MaxSize  int64
	Log      *slog.Logger
}

// Inbound is one message for one or more local users.
type Inbound struct {
	Env   Envelope
	Rcpts []store.User
	// Proto is the transport for the Received header: ESMTP, ESMTPS, HTTP.
	Proto string
	// Trusted skips SPF/DKIM/DMARC (mail from our own authenticated users).
	Trusted bool
	// Mailbox overrides the Inbox (e.g. Sent for a copy of submitted mail).
	MailboxUse string
	Flags      store.Flag
	// Stored, if set, is called for every message filed.
	Stored func(store.Message)
}

// RejectError means the message must be refused with a permanent error.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return e.Reason }

// ErrTooLarge is returned when a message exceeds MaxSize.
var ErrTooLarge = blob.ErrTooLarge

// Deliver stores r for every recipient. It returns one error per recipient
// (nil for success), or a single error when nothing could be delivered.
func (d *Deliverer) Deliver(ctx context.Context, in Inbound, r io.Reader) ([]error, error) {
	spool, err := os.CreateTemp(d.TmpDir, "in-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(spool.Name())
	defer spool.Close()
	src := r
	if d.MaxSize > 0 {
		src = io.LimitReader(r, d.MaxSize+1)
	}
	n, err := io.Copy(spool, src)
	if err != nil {
		return nil, err
	}
	if d.MaxSize > 0 && n > d.MaxSize {
		return nil, ErrTooLarge
	}
	rewind := func() (io.ReadCloser, error) {
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		return io.NopCloser(spool), nil
	}
	rd, _ := rewind()
	sum := Summarize(rd)

	var verdict Verdict
	if !in.Trusted && d.Checker != nil {
		verdict = d.Checker.Check(ctx, in.Env, sum.FromAddr, rewind)
		if verdict.Action == Reject && in.Env.RemoteIP == nil {
			// Relayed over HTTP: SPF could not be checked here, so a DMARC
			// failure may be a false one. File it as junk instead.
			verdict.Action = Quarantine
		}
		if verdict.Action == Reject {
			return nil, &RejectError{Reason: verdict.Reason}
		}
	}

	// Spam: the shared part of the score first, so the worst mail is
	// refused before it is stored; each recipient's own filter adds to it.
	var score spam.Result
	var toks []int64
	scored := !in.Trusted && d.Spam != nil && in.MailboxUse == ""
	if scored {
		rcpts := make([]string, len(in.Rcpts))
		for i, u := range in.Rcpts {
			rcpts[i] = u.Address()
		}
		score = d.Spam.Score(ctx, spam.Message{
			RemoteIP: in.Env.RemoteIP, Helo: in.Env.Helo, MailFrom: in.Env.MailFrom, Rcpts: rcpts,
			BadHelo: in.Env.BadHelo, NoRDNS: in.Env.NoRDNS,
			Auth: verdict.Bits, AuthFail: verdict.Action == Quarantine,
			Subject: sum.Subject, FromName: sum.FromName, FromAddr: sum.FromAddr,
			MessageID: sum.MessageID, SentDate: sum.SentDate, Text: sum.Text, Raw: rewind,
		})
		if d.Spam.Rejects(score.Score) && in.Env.RemoteIP != nil && !d.allowed(ctx, in, sum.FromAddr) {
			d.log().Info("refused as spam", "from", in.Env.MailFrom, "ip", in.Env.RemoteIP, "spam", score.Header())
			return nil, &RejectError{Reason: "5.7.1 Message refused as spam"}
		}
		toks = spam.Tokens(sum.Subject, sum.FromAddr, sum.Text)
	}

	now := time.Now()
	var prefix bytes.Buffer
	if !in.Trusted {
		fmt.Fprintf(&prefix, "Return-Path: <%s>\r\n", sanitize(in.Env.MailFrom))
		if verdict.Header != "" {
			fmt.Fprintf(&prefix, "Authentication-Results: %s\r\n", verdict.Header)
		}
		ip := "unknown"
		if in.Env.RemoteIP != nil {
			ip = in.Env.RemoteIP.String()
		}
		fmt.Fprintf(&prefix, "Received: from %s ([%s])\r\n\tby %s with %s;\r\n\t%s\r\n",
			sanitize(in.Env.Helo), ip, d.Hostname, in.Proto, now.Format(time.RFC1123Z))
		if scored {
			fmt.Fprintf(&prefix, "X-Spam-Status: %s\r\n", score.Header())
		}
	}

	use := in.MailboxUse
	if use == "" {
		use = store.UseInbox
		if verdict.Action == Quarantine {
			use = store.UseJunk
		}
	}
	defer d.Blobs.Hold()()
	stored := map[int64]blob.Result{}
	errs := make([]error, len(in.Rcpts))
	seen := map[int64]bool{}
	delivered, junked := 0, 0
	for i, u := range in.Rcpts {
		if seen[u.ID] {
			continue
		}
		seen[u.ID] = true
		res, ok := stored[u.TenantID]
		if !ok {
			body, err := rewind()
			if err != nil {
				return nil, err
			}
			res, err = d.Blobs.Put(u.TenantID, io.MultiReader(bytes.NewReader(prefix.Bytes()), body), 0)
			if err != nil {
				return nil, err
			}
			stored[u.TenantID] = res
		}
		folder, total := use, score.Score
		if scored {
			if b, _ := d.Spam.Bayes(ctx, u.ID, toks); b != 0 {
				total += b
			}
			switch {
			case d.allowedFor(ctx, u.TenantID, in, sum.FromAddr):
				folder = store.UseInbox
			case total >= d.Spam.JunkScore():
				folder = store.UseJunk
			}
		}
		m, err := d.Store.InsertMessage(ctx, store.NewMessage{
			TenantID: u.TenantID, UserID: u.ID, MailboxUse: folder, SpamScore: total,
			BlobHash: res.Hash, Size: res.Size, StoredSize: res.StoredSize,
			InternalDate: now.Unix(), Flags: in.Flags, Auth: verdict.Bits,
			SentDate: sum.SentDate, Subject: sum.Subject, FromName: sum.FromName, FromAddr: sum.FromAddr,
			To: sum.To, Cc: sum.Cc, MessageID: sum.MessageID, InReplyTo: sum.InReplyTo, References: sum.References,
			Preview: sum.Preview, HasAttachments: sum.HasAttachments, SearchText: sum.Text,
		})
		if err != nil {
			errs[i] = err
			d.log().Warn("delivery failed", "user", u.ID, "err", err)
			continue
		}
		delivered++
		if folder == store.UseJunk {
			junked++
		}
		if in.Stored != nil {
			in.Stored(m)
		}
		if d.Hub != nil {
			d.Hub.Publish(u.ID, m.MailboxID)
		}
	}
	if delivered == 0 {
		for _, e := range errs {
			if e != nil {
				return errs, e
			}
		}
		return errs, errors.New("no recipients")
	}
	d.log().Info("delivered", "from", in.Env.MailFrom, "rcpts", delivered, "size", n, "junk", junked, "spam", score.Score)
	return errs, nil
}

// allowed reports whether any recipient's tenant allows the sender.
func (d *Deliverer) allowed(ctx context.Context, in Inbound, from string) bool {
	seen := map[int64]bool{}
	for _, u := range in.Rcpts {
		if !seen[u.TenantID] {
			seen[u.TenantID] = true
			if d.allowedFor(ctx, u.TenantID, in, from) {
				return true
			}
		}
	}
	return false
}

// allowedFor reports whether the tenant has an allow rule for the sender.
func (d *Deliverer) allowedFor(ctx context.Context, tenantID int64, in Inbound, from string) bool {
	var ip netip.Addr
	if in.Env.RemoteIP != nil {
		ip, _ = netip.AddrFromSlice(in.Env.RemoteIP)
	}
	v, err := d.Store.SenderVerdict(ctx, tenantID, ip, from)
	return err == nil && v == "allow"
}

func (d *Deliverer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// sanitize keeps header values on one line.
func sanitize(s string) string { return clean(s, 255) }

// Append stores a message a user uploads into one of their mailboxes (IMAP
// APPEND), with the given flags and internal date.
func (d *Deliverer) Append(ctx context.Context, u store.User, mailboxID int64, flags store.Flag, date time.Time, r io.Reader) (store.Message, error) {
	spool, err := os.CreateTemp(d.TmpDir, "app-*")
	if err != nil {
		return store.Message{}, err
	}
	defer os.Remove(spool.Name())
	defer spool.Close()
	src := r
	if d.MaxSize > 0 {
		src = io.LimitReader(r, d.MaxSize+1)
	}
	n, err := io.Copy(spool, src)
	if err != nil {
		return store.Message{}, err
	}
	if d.MaxSize > 0 && n > d.MaxSize {
		return store.Message{}, ErrTooLarge
	}
	spool.Seek(0, io.SeekStart)
	sum := Summarize(spool)
	spool.Seek(0, io.SeekStart)
	defer d.Blobs.Hold()()
	res, err := d.Blobs.Put(u.TenantID, spool, 0)
	if err != nil {
		return store.Message{}, err
	}
	if date.IsZero() {
		date = time.Now()
	}
	m, err := d.Store.InsertMessage(ctx, store.NewMessage{
		TenantID: u.TenantID, UserID: u.ID, MailboxID: mailboxID,
		BlobHash: res.Hash, Size: res.Size, StoredSize: res.StoredSize, InternalDate: date.Unix(), Flags: flags,
		SentDate: sum.SentDate, Subject: sum.Subject, FromName: sum.FromName, FromAddr: sum.FromAddr,
		To: sum.To, Cc: sum.Cc, MessageID: sum.MessageID, InReplyTo: sum.InReplyTo, References: sum.References,
		Preview: sum.Preview, HasAttachments: sum.HasAttachments, SearchText: sum.Text,
	})
	if err != nil {
		return m, err
	}
	if d.Hub != nil {
		d.Hub.Publish(u.ID, m.MailboxID)
	}
	return m, nil
}
