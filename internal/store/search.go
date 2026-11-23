// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"strings"
	"unicode"

	"golang.org/x/text/runes"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
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

// Full-text search runs on a tsvector column of messages. Text is folded
// here (lower case, accents removed) and split into words on anything that
// is not a letter or digit, the same way for the index and for queries, so
// "ana@acme.example" is found by "acme" and "café" by "cafe". Positions are
// stripped from the vector: only the words are kept, which keeps it small.

// searchVector is the SQL for the vector of one searchText argument.
const searchVector = `strip(to_tsvector('simple', ?))`

// maxIndexed caps the indexed text per message; PostgreSQL refuses vectors
// over 1 MB, and the start of a message is what people search for.
const maxIndexed = 256 << 10

var fold = transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)

// words returns the folded words of text, at most max of them (0 = no limit).
func words(text string, max int) []string {
	folded, _, err := transform.String(fold, text)
	if err != nil {
		folded = text
	}
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(folded), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if max > 0 && len(out) >= max {
			break
		}
		out = append(out, w)
	}
	return out
}

// searchText is the text indexed for a message.
func searchText(text string) string {
	if len(text) > 2*maxIndexed {
		text = text[:2*maxIndexed]
	}
	var b strings.Builder
	for _, w := range words(text, 0) {
		if len(w) > 64 {
			continue // tokens of base64 and the like, never searched for
		}
		if b.Len()+len(w)+1 > maxIndexed {
			break
		}
		b.WriteString(w)
		b.WriteByte(' ')
	}
	return b.String()
}

// ftsQuery turns free text into a safe tsquery: every word becomes a prefix
// term and all must match. Words hold only letters and digits, so user input
// can never inject query syntax.
func ftsQuery(text string) string {
	ws := words(text, 16)
	for i, w := range ws {
		ws[i] = "'" + w + "':*"
	}
	return strings.Join(ws, " & ")
}

// Search finds a user's messages, newest first.
func (s *Store) Search(ctx context.Context, userID int64, text string, o SearchOptions) ([]Message, error) {
	if o.Limit <= 0 || o.Limit > 200 {
		o.Limit = 50
	}
	q := `SELECT ` + msgCols + ` FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=?`
	args := []any{userID}
	if fq := ftsQuery(text); fq != "" {
		q += ` AND m.search @@ to_tsquery('simple', ?)`
		args = append(args, fq)
	}
	if o.MailboxID > 0 {
		q += ` AND m.mailbox_id=?`
		args = append(args, o.MailboxID)
	}
	if o.From != "" {
		q += ` AND (m.from_addr ILIKE ? ESCAPE '\' OR m.from_name ILIKE ? ESCAPE '\')`
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
		q += ` AND m.has_attachments`
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

// MatchIDs returns the ids of messages in a mailbox whose indexed text
// (subject, addresses, body) matches every term of text. IMAP SEARCH uses it
// for TEXT and BODY keys.
func (s *Store) MatchIDs(ctx context.Context, userID, mailboxID int64, text string) (map[int64]bool, error) {
	out := map[int64]bool{}
	fq := ftsQuery(text)
	if fq == "" {
		return out, nil
	}
	rows, err := s.r.QueryContext(ctx, `SELECT m.id FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
		WHERE b.user_id=? AND m.mailbox_id=? AND m.search @@ to_tsquery('simple', ?)`, userID, mailboxID, fq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
