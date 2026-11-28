// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package spam

import (
	"context"
	"log/slog"
	"time"

	"github.com/gsoultan/talaria/internal/store"
)

// TextFunc returns the subject, sender and text of a stored message.
type TextFunc func(ctx context.Context, tenantID int64, blobHash []byte) (subject, from, text string, err error)

// Learner trains each user's filter from the mail they move into and out
// of Junk, from the webmail or an IMAP app alike.
type Learner struct {
	Store *store.Store
	Text  TextFunc
	Log   *slog.Logger
}

// Run trains until ctx ends, checking for new moves every interval.
func (l *Learner) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		l.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Once trains on everything waiting.
func (l *Learner) Once(ctx context.Context) {
	for ctx.Err() == nil {
		evs, err := l.Store.PendingTraining(ctx, 100)
		if err != nil {
			l.Log.Warn("spam training", "err", err)
			return
		}
		for _, e := range evs {
			var toks []int64
			subject, from, text, err := l.Text(ctx, e.TenantID, e.BlobHash)
			if err != nil {
				l.Log.Warn("spam training: read message", "id", e.MessageID, "err", err)
			} else {
				toks = Tokens(subject, from, text)
			}
			if err := l.Store.Train(ctx, e, toks); err != nil {
				l.Log.Warn("spam training", "id", e.MessageID, "err", err)
				return
			}
		}
		if len(evs) < 100 {
			return
		}
	}
}
