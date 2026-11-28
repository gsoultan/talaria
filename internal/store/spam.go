// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// How a message trained the spam filter.
const (
	TrainedNone = 0
	TrainedSpam = 1
	TrainedHam  = 2
)

// TrainEvent is a message to learn from: moved into Junk (Spam true) or
// out of it.
type TrainEvent struct {
	ID        int64
	UserID    int64
	TenantID  int64
	MessageID int64
	Spam      bool
	BlobHash  []byte
	Trained   int // what the message already taught, TrainedNone if nothing
}

// queueTraining records moves into or out of Junk for the learner. Moving
// to Trash teaches nothing: deleting is not a verdict.
func queueTraining(ctx context.Context, tx *Tx, userID, srcID, destID int64, ids []int64, now int64) error {
	var srcUse, destUse string
	if err := tx.QueryRowContext(ctx, `SELECT (SELECT special_use FROM mailboxes WHERE id=?), (SELECT special_use FROM mailboxes WHERE id=?)`, srcID, destID).Scan(&srcUse, &destUse); err != nil {
		return err
	}
	var spam bool
	switch {
	case destUse == UseJunk && srcUse != UseJunk:
		spam = true
	case srcUse == UseJunk && destUse != UseJunk && destUse != UseTrash:
		spam = false
	default:
		return nil
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO spam_train(user_id, message_id, spam, created_at) VALUES (?, ?, ?, ?)`, userID, id, spam, now); err != nil {
			return err
		}
	}
	return nil
}

// PendingTraining returns the oldest training events.
func (s *Store) PendingTraining(ctx context.Context, limit int) ([]TrainEvent, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT e.id, e.user_id, u.tenant_id, e.message_id, e.spam, bl.hash, m.trained
		FROM spam_train e JOIN messages m ON m.id=e.message_id JOIN blobs bl ON bl.id=m.blob_id JOIN users u ON u.id=e.user_id
		ORDER BY e.id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrainEvent
	for rows.Next() {
		var e TrainEvent
		if err := rows.Scan(&e.ID, &e.UserID, &e.TenantID, &e.MessageID, &e.Spam, &e.BlobHash, &e.Trained); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Train applies one event: tokens are counted for the new verdict, and
// taken back from the old one if the message had trained the other way.
// Training the same way twice changes nothing.
func (s *Store) Train(ctx context.Context, e TrainEvent, tokens []int64) error {
	return s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM spam_train WHERE id=?`, e.ID); err != nil {
			return err
		}
		want := TrainedHam
		if e.Spam {
			want = TrainedSpam
		}
		var cur int
		err := tx.QueryRowContext(ctx, `SELECT trained FROM messages WHERE id=? FOR UPDATE`, e.MessageID).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			return nil // the message is gone; nothing to learn
		} else if err != nil {
			return err
		}
		if cur == want {
			return nil
		}
		ds, dh := 0, 0
		if want == TrainedSpam {
			ds = 1
		} else {
			dh = 1
		}
		switch cur {
		case TrainedSpam:
			ds--
		case TrainedHam:
			dh--
		}
		if len(tokens) > 0 {
			// tokens are distinct (see spam.Tokens), so each row changes once.
			args := []any{e.UserID, ds, dh, ds, dh}
			ph := make([]string, len(tokens))
			for i, t := range tokens {
				ph[i] = "(?::bigint)"
				args = append(args, t)
			}
			if _, err := tx.ExecContext(ctx, `WITH p AS (SELECT ?::bigint AS u, ?::int AS ds, ?::int AS dh, GREATEST(?::int, 0) AS s0, GREATEST(?::int, 0) AS h0)
				INSERT INTO bayes_tokens(user_id, token, spam, ham)
				SELECT p.u, t.token, p.s0, p.h0 FROM p, (VALUES `+strings.Join(ph, ",")+`) AS t(token)
				ON CONFLICT (user_id, token) DO UPDATE SET
				  spam = GREATEST(bayes_tokens.spam + (SELECT ds FROM p), 0),
				  ham = GREATEST(bayes_tokens.ham + (SELECT dh FROM p), 0)`, args...); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO bayes_users(user_id, spam, ham) VALUES (?, GREATEST(?::int,0), GREATEST(?::int,0))
			ON CONFLICT (user_id) DO UPDATE SET spam = GREATEST(bayes_users.spam + ?::int, 0), ham = GREATEST(bayes_users.ham + ?::int, 0)`,
			e.UserID, ds, dh, ds, dh); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE messages SET trained=? WHERE id=?`, want, e.MessageID)
		return err
	})
}

// BayesCounts returns a user's message totals and the counts of the given
// tokens they have seen.
func (s *Store) BayesCounts(ctx context.Context, userID int64, tokens []int64) (spamMsgs, hamMsgs int, counts map[int64][2]int, err error) {
	counts = map[int64][2]int{}
	err = s.r.QueryRowContext(ctx, `SELECT COALESCE((SELECT spam FROM bayes_users WHERE user_id=?),0), COALESCE((SELECT ham FROM bayes_users WHERE user_id=?),0)`, userID, userID).Scan(&spamMsgs, &hamMsgs)
	if err != nil || len(tokens) == 0 || spamMsgs == 0 || hamMsgs == 0 {
		return
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(tokens)), ",")
	args := []any{userID}
	for _, t := range tokens {
		args = append(args, t)
	}
	rows, err := s.r.QueryContext(ctx, `SELECT token, spam, ham FROM bayes_tokens WHERE user_id=? AND token IN (`+ph+`)`, args...)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var t int64
		var c [2]int
		if err = rows.Scan(&t, &c[0], &c[1]); err != nil {
			return
		}
		counts[t] = c
	}
	err = rows.Err()
	return
}
