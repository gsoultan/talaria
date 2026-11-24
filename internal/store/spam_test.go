// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"testing"
)

func TestSpamTraining(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	tn, u := seed(t, s, "acme", "acme.example", "ana@acme.example")
	m, err := s.InsertMessage(ctx, msg(tn, u, "h1", "cheap pills"))
	if err != nil {
		t.Fatal(err)
	}
	junk, _ := s.MailboxByUse(ctx, u.ID, UseJunk)
	inbox, _ := s.MailboxByUse(ctx, u.ID, UseInbox)
	trash, _ := s.MailboxByUse(ctx, u.ID, UseTrash)
	toks := []int64{11, 22, 33}

	learn := func(want int) {
		t.Helper()
		evs, err := s.PendingTraining(ctx, 10)
		if err != nil || len(evs) != want {
			t.Fatalf("pending: %v %+v", err, evs)
		}
		for _, e := range evs {
			if err := s.Train(ctx, e, toks); err != nil {
				t.Fatal(err)
			}
		}
	}
	// counts returns the user's totals and token 22's counts.
	counts := func() (int, int, [2]int) {
		t.Helper()
		sp, hm, _, err := s.BayesCounts(ctx, u.ID, toks)
		if err != nil {
			t.Fatal(err)
		}
		var c [2]int
		s.r.QueryRowContext(ctx, `SELECT spam, ham FROM bayes_tokens WHERE user_id=? AND token=22`, u.ID).Scan(&c[0], &c[1])
		return sp, hm, c
	}

	// Into Junk: spam.
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, junk.ID); err != nil {
		t.Fatal(err)
	}
	learn(1)
	if sp, hm, c := counts(); sp != 1 || hm != 0 || c != [2]int{1, 0} {
		t.Fatalf("after junk: %d %d %v", sp, hm, c)
	}

	// Back to the Inbox: the spam count is taken back and ham counted.
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, inbox.ID); err != nil {
		t.Fatal(err)
	}
	learn(1)
	if sp, hm, c := counts(); sp != 0 || hm != 1 || c != [2]int{0, 1} {
		t.Fatalf("after not junk: %d %d %v", sp, hm, c)
	}

	// Moving between ordinary folders, or from Junk to Trash, teaches
	// nothing; the same verdict twice counts once.
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, trash.ID); err != nil {
		t.Fatal(err)
	}
	learn(0)
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, junk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, trash.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, junk.ID); err != nil {
		t.Fatal(err)
	}
	learn(2)
	sp, hm, tok := counts()
	if sp != 1 || hm != 0 || tok != [2]int{1, 0} {
		t.Fatalf("repeat: %d %d %v", sp, hm, tok)
	}

	// A deleted message leaves no event behind.
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m.ID}, inbox.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.w.ExecContext(ctx, `DELETE FROM messages WHERE id=?`, m.ID); err != nil {
		t.Fatal(err)
	}
	learn(0)
}
