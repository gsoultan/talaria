// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package outbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// Submitter accepts messages from authenticated local users.
type Submitter struct {
	Store    *store.Store
	Blobs    *blob.Store
	Deliver  *mail.Deliverer
	Keys     *Keys
	Queue    *Queue // woken after enqueueing; may be nil in tests
	Hostname string
	TmpDir   string
	MaxSize  int64
	Log      *slog.Logger
}

// Submission is one message from a local user.
type Submission struct {
	User     store.User
	MailFrom string   // envelope sender; must be one of the user's addresses
	Rcpts    []string // envelope recipients
	// SaveSent files a copy in the user's Sent folder (webmail sends; mail
	// apps save their own copy over IMAP).
	SaveSent bool
	// Received describes where the submission came from, for the trace header.
	ClientIP string
	Proto    string
}

// Errors returned by Submit.
var (
	ErrSenderNotAllowed = errors.New("you cannot send as this address")
	ErrNoRecipients     = errors.New("no recipients")
)

// RecipientError is a recipient the server refuses for good.
type RecipientError struct{ Msg string }

func (e *RecipientError) Error() string { return e.Msg }

// Result says where the message went.
type Result struct {
	Local  int
	Queued int
	SentID int64 // message id of the Sent copy, if saved
}

// Submit validates, signs and routes a message.
func (s *Submitter) Submit(ctx context.Context, sub Submission, r io.Reader) (Result, error) {
	var res Result
	if !s.Store.CanSendAs(ctx, sub.User, sub.MailFrom) {
		return res, ErrSenderNotAllowed
	}
	if len(sub.Rcpts) == 0 {
		return res, ErrNoRecipients
	}
	if len(sub.Rcpts) > 100 {
		return res, &RecipientError{"too many recipients (max 100)"}
	}

	spool, err := os.CreateTemp(s.TmpDir, "out-*")
	if err != nil {
		return res, err
	}
	defer os.Remove(spool.Name())
	defer spool.Close()
	src := r
	if s.MaxSize > 0 {
		src = io.LimitReader(r, s.MaxSize+1)
	}
	br := bufio.NewReaderSize(src, 32<<10)
	hdr, err := textproto.ReadHeader(br)
	if err != nil {
		return res, fmt.Errorf("bad message header: %w", err)
	}
	h := gomail.Header{Header: message.Header{Header: hdr}}

	// The From header must also be the user's.
	from, err := h.AddressList("From")
	if err != nil || len(from) != 1 || !s.Store.CanSendAs(ctx, sub.User, from[0].Address) {
		return res, ErrSenderNotAllowed
	}
	if !h.Has("Date") {
		h.SetDate(time.Now())
	}
	if !h.Has("Message-Id") {
		h.SetMessageID(newMessageID(s.Hostname))
	}
	h.Del("Bcc") // never leaves the server
	h.Del("Return-Path")
	if sub.Proto != "" {
		// Add puts the field on top, where trace fields belong.
		h.Add("Received", fmt.Sprintf("from [%s] by %s with %s; %s", sub.ClientIP, s.Hostname, sub.Proto, time.Now().Format(time.RFC1123Z)))
	}
	hdr = h.Header.Header
	if err := textproto.WriteHeader(spool, hdr); err != nil {
		return res, err
	}
	n, err := io.Copy(spool, br)
	if err != nil {
		return res, err
	}
	if s.MaxSize > 0 && n > s.MaxSize {
		return res, mail.ErrTooLarge
	}
	if fi, err := spool.Stat(); err == nil {
		n = fi.Size()
	}

	rewind := func() io.Reader { spool.Seek(0, io.SeekStart); return spool }
	_, fromDomain, _ := store.SplitAddress(from[0].Address)
	sig, err := s.Keys.Sign(ctx, fromDomain, rewind())
	if err != nil {
		s.log().Warn("dkim sign failed, sending unsigned", "domain", fromDomain, "err", err)
	}
	signed := func() io.Reader { return io.MultiReader(strings.NewReader(sig), rewind()) }

	// Split recipients: local users get it now; the rest are queued.
	var locals []store.User
	var remote []string
	for _, rc := range sub.Rcpts {
		_, dom, err := store.SplitAddress(rc)
		if err != nil {
			return res, &RecipientError{fmt.Sprintf("bad recipient %q", rc)}
		}
		if s.Store.IsLocalDomain(ctx, dom) {
			u, err := s.Store.ResolveRecipient(ctx, rc)
			if err != nil || u.Suspended {
				return res, &RecipientError{"no such user: " + rc}
			}
			locals = append(locals, u)
		} else {
			remote = append(remote, rc)
		}
	}
	if len(remote) > 0 {
		release := s.Blobs.Hold()
		b, err := s.Blobs.Put(sub.User.TenantID, signed(), 0)
		if err == nil {
			err = s.Store.Enqueue(ctx, sub.User.TenantID, sub.User.ID, b.Hash, b.Size, b.StoredSize, sub.MailFrom, remote)
		}
		release()
		if err != nil {
			return res, err
		}
		res.Queued = len(remote)
		if s.Queue != nil {
			s.Queue.Wake()
		}
	}
	if len(locals) > 0 {
		env := mail.Envelope{MailFrom: sub.MailFrom, Helo: s.Hostname}
		if _, err := s.Deliver.Deliver(ctx, mail.Inbound{Env: env, Rcpts: locals, Trusted: true}, signed()); err != nil {
			s.log().Warn("local delivery of submitted mail", "err", err)
		} else {
			res.Local = len(locals)
		}
	}
	if sub.SaveSent {
		if _, err := s.Deliver.Deliver(ctx, mail.Inbound{Rcpts: []store.User{sub.User}, Trusted: true, MailboxUse: store.UseSent, Flags: store.FlagSeen},
			s.withBcc(signed(), sub, hdr)); err != nil {
			s.log().Warn("save to Sent", "err", err)
		}
	}
	s.log().Info("submitted", "user", sub.User.Address(), "local", res.Local, "queued", res.Queued, "size", n)
	return res, nil
}

// withBcc returns the Sent copy: the signed message, plus a Bcc header so the
// sender can still see who was blind-copied.
func (s *Submitter) withBcc(r io.Reader, sub Submission, hdr textproto.Header) io.Reader {
	listed := strings.ToLower(hdr.Get("To") + "," + hdr.Get("Cc"))
	var bcc []string
	for _, rc := range sub.Rcpts {
		if !strings.Contains(listed, strings.ToLower(rc)) {
			bcc = append(bcc, rc)
		}
	}
	if len(bcc) == 0 {
		return r
	}
	return io.MultiReader(strings.NewReader("Bcc: "+strings.Join(bcc, ", ")+"\r\n"), r)
}

func (s *Submitter) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func newMessageID(host string) string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b) + "@" + host
}
