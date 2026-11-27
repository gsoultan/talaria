// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// Retry delays after each failed attempt; the last one repeats. A message
// that still fails after MaxAge is bounced.
var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 8 * time.Hour}

// MaxAge is how long a message may wait before it is bounced.
const MaxAge = 4 * 24 * time.Hour

// Queue delivers queued messages with a small, fixed number of workers.
type Queue struct {
	Store     *store.Store
	Blobs     *blob.Store
	Transport Transport
	Deliver   *mail.Deliverer // for bounce reports
	Hostname  string
	Workers   int
	Log       *slog.Logger

	wake chan struct{}
	once sync.Once
}

func (q *Queue) init() {
	q.once.Do(func() { q.wake = make(chan struct{}, 1) })
}

// Wake makes the queue look for due items now.
func (q *Queue) Wake() {
	q.init()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// Run processes the queue until ctx is done.
func (q *Queue) Run(ctx context.Context) {
	q.init()
	workers := q.Workers
	if workers <= 0 {
		workers = 4
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		items, err := q.Store.ClaimDue(ctx, workers*4, int64(time.Hour/time.Second))
		if err != nil && ctx.Err() == nil {
			q.Log.Error("queue claim", "err", err)
		}
		for _, it := range items {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				q.attempt(ctx, it)
			}()
		}
		if len(items) == workers*4 {
			continue
		}
		wait := time.Minute
		if next := q.Store.NextDue(ctx); next > 0 {
			if d := time.Until(time.Unix(next, 0)); d < wait {
				wait = max(d, time.Second)
			}
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-q.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

func (q *Queue) attempt(ctx context.Context, it store.QueueItem) {
	// Recording the outcome must survive shutdown: a message the relay took
	// but that is not marked sent would go out twice, and a lost bounce report
	// leaves the sender never knowing.
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer rcancel()
	r, err := q.Blobs.Open(it.TenantID, it.BlobHash)
	if err != nil {
		q.Log.Error("queue: body missing", "id", it.ID, "err", err)
		q.bounce(rctx, it, "message body lost on the server")
		return
	}
	defer r.Close()
	sctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if it.RequireTLS {
		sctx = WithRequireTLS(sctx)
	}
	reply, err := q.Transport.Send(sctx, it.MailFrom, it.RcptTo, r)
	ctx = rctx
	if err == nil {
		q.Store.MarkSent(ctx, it.ID, reply)
		q.Log.Info("sent", "id", it.ID, "to", it.RcptTo, "reply", reply)
		return
	}
	var perm *PermanentError
	age := time.Since(time.Unix(it.CreatedAt, 0))
	if errors.As(err, &perm) || age > MaxAge {
		q.Log.Warn("bounced", "id", it.ID, "to", it.RcptTo, "err", err)
		q.bounce(ctx, it, err.Error())
		return
	}
	delay := retryDelays[min(it.Attempts, len(retryDelays)-1)]
	q.Store.MarkRetry(ctx, it.ID, time.Now().Add(delay).Unix(), err.Error())
	q.Log.Info("retry", "id", it.ID, "to", it.RcptTo, "in", delay, "err", err)
}

// bounce records the failure and tells the sender, unless the message was
// itself a bounce (null sender).
func (q *Queue) bounce(ctx context.Context, it store.QueueItem, reason string) {
	// The report is written before the item is marked bounced, so the
	// sender is told by the time the queue shows the failure.
	defer q.Store.MarkBounced(ctx, it.ID, reason)
	if it.MailFrom == "" || it.UserID == 0 || q.Deliver == nil {
		return
	}
	u, err := q.Store.User(ctx, it.UserID)
	if err != nil {
		return
	}
	var orig strings.Builder
	if r, err := q.Blobs.Open(it.TenantID, it.BlobHash); err == nil {
		io.Copy(&orig, io.LimitReader(r, 16<<10))
		r.Close()
	}
	headers, _, _ := strings.Cut(orig.String(), "\r\n\r\n")
	boundary := fmt.Sprintf("bounce-%d", it.ID)
	now := time.Now()
	msg := fmt.Sprintf("From: Mail Delivery System <mailer-daemon@%[1]s>\r\nTo: %[2]s\r\nSubject: Undelivered mail: %[3]s\r\n"+
		"Date: %[4]s\r\nMessage-ID: <bounce-%[5]d-%[6]d@%[1]s>\r\nAuto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: multipart/report; report-type=delivery-status; boundary=%[7]s\r\n\r\n"+
		"--%[7]s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"+
		"Your message could not be delivered to %[3]s.\r\n\r\nThe receiving server said:\r\n\r\n    %[8]s\r\n\r\n"+
		"--%[7]s\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; %[1]s\r\n\r\n"+
		"Final-Recipient: rfc822; %[3]s\r\nAction: failed\r\nStatus: 5.0.0\r\nDiagnostic-Code: smtp; %[8]s\r\n\r\n"+
		"--%[7]s\r\nContent-Type: text/rfc822-headers\r\n\r\n%[9]s\r\n\r\n--%[7]s--\r\n",
		q.Hostname, u.Address(), it.RcptTo, now.Format(time.RFC1123Z), it.ID, now.Unix(), boundary,
		strings.ReplaceAll(reason, "\n", " "), headers)
	if _, err := q.Deliver.Deliver(ctx, mail.Inbound{Rcpts: []store.User{u}, Trusted: true}, strings.NewReader(msg)); err != nil {
		q.Log.Warn("bounce report", "err", err)
	}
}
