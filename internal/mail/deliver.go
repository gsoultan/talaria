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
	"os"
	"time"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/store"
)

// Deliverer files inbound messages into local mailboxes.
type Deliverer struct {
	Store    *store.Store
	Blobs    *blob.Store
	Hub      *hub.Hub
	Checker  *Checker
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
	delivered := 0
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
		m, err := d.Store.InsertMessage(ctx, store.NewMessage{
			TenantID: u.TenantID, UserID: u.ID, MailboxUse: use,
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
	d.log().Info("delivered", "from", in.Env.MailFrom, "rcpts", delivered, "size", n, "folder", use)
	return errs, nil
}

func (d *Deliverer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// sanitize keeps header values on one line.
func sanitize(s string) string { return clean(s, 255) }
