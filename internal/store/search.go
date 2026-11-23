// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"strings"
	"unicode"
)

// SearchOptions narrows a full-text search.
type SearchOptions struct {
	MailboxID int64 // 0 = all mailboxes
	From      string
	Unread    bool
	Flagged   bool
	HasAttach bool
	After     int64 // unix seconds
	Before    int64
	Limit     int
}

// ftsQuery turns free text into a safe FTS5 query: every word becomes a
// quoted prefix term, so user input can never inject FTS syntax.
func ftsQuery(text string) string {
	var terms []string
	for _, w := range strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '@' && r != '.' && r != '_' && r != '-'
	}) {
		w = strings.Trim(w, ".-_@")
		if w == "" || len(terms) >= 16 {
			continue
		}
		terms = append(terms, `"`+strings.ReplaceAll(w, `"`, ``)+`"*`)
	}
	return strings.Join(terms, " ")
}

// Search finds a user's messages, newest first.
func (s *Store) Search(ctx context.Context, userID int64, text string, o SearchOptions) ([]Message, error) {
	if o.Limit <= 0 || o.Limit > 200 {
		o.Limit = 50
	}
	q := `SELECT ` + msgCols + ` FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=?`
	args := []any{userID}
	if fq := ftsQuery(text); fq != "" {
		q += ` AND m.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)`
		args = append(args, fq)
	}
	if o.MailboxID > 0 {
		q += ` AND m.mailbox_id=?`
		args = append(args, o.MailboxID)
	}
	if o.From != "" {
		q += ` AND (m.from_addr LIKE ? ESCAPE '\' OR m.from_name LIKE ? ESCAPE '\')`
		p := "%" + likeEscape(o.From) + "%"
		args = append(args, p, p)
	}
	if o.Unread {
		q += ` AND (m.flags & 1) = 0`
	}
	if o.Flagged {
		q += ` AND (m.flags & 4) <> 0`
	}
	if o.HasAttach {
		q += ` AND m.has_attachments = 1`
	}
	if o.After > 0 {
		q += ` AND m.internal_date >= ?`
		args = append(args, o.After)
	}
	if o.Before > 0 {
		q += ` AND m.internal_date < ?`
		args = append(args, o.Before)
	}
	q += ` ORDER BY m.internal_date DESC, m.id DESC LIMIT ?`
	args = append(args, o.Limit)
	return s.queryMessages(ctx, q, args...)
}
