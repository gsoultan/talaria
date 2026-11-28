// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Special-use attributes (RFC 6154), plus \Inbox for INBOX.
const (
	UseInbox   = `\Inbox`
	UseSent    = `\Sent`
	UseDrafts  = `\Drafts`
	UseJunk    = `\Junk`
	UseTrash   = `\Trash`
	UseArchive = `\Archive`
)

var defaultMailboxes = []struct{ name, use string }{
	{"INBOX", UseInbox}, {"Sent", UseSent}, {"Drafts", UseDrafts},
	{"Junk", UseJunk}, {"Trash", UseTrash}, {"Archive", UseArchive},
}

// Mailbox is a folder.
type Mailbox struct {
	ID            int64
	UserID        int64
	Name          string
	SpecialUse    string
	UIDValidity   int64
	UIDNext       int64
	HighestModSeq int64
	Subscribed    bool
	Total         int64
	Unread        int64
	Size          int64
}

func createDefaultMailboxes(ctx context.Context, tx *Tx, userID, now int64) error {
	for _, m := range defaultMailboxes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO mailboxes(user_id, name, special_use, uid_validity) VALUES (?, ?, ?, ?)`, userID, m.name, m.use, now); err != nil {
			return err
		}
	}
	return nil
}

const mailboxCols = `b.id, b.user_id, b.name, b.special_use, b.uid_validity, b.uid_next, b.highest_modseq, b.subscribed`

func scanMailbox(row interface{ Scan(...any) error }, extra ...any) (Mailbox, error) {
	var m Mailbox
	dst := append([]any{&m.ID, &m.UserID, &m.Name, &m.SpecialUse, &m.UIDValidity, &m.UIDNext, &m.HighestModSeq, &m.Subscribed}, extra...)
	err := row.Scan(dst...)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// ListMailboxes returns a user's folders with message and unread counts.
func (s *Store) ListMailboxes(ctx context.Context, userID int64) ([]Mailbox, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+mailboxCols+`,
		(SELECT COUNT(*) FROM messages m WHERE m.mailbox_id=b.id),
		(SELECT COUNT(*) FROM messages m WHERE m.mailbox_id=b.id AND (m.flags & 1)=0),
		(SELECT COALESCE(SUM(size),0)::bigint FROM messages m WHERE m.mailbox_id=b.id)
		FROM mailboxes b WHERE b.user_id=?
		ORDER BY CASE b.name WHEN 'INBOX' THEN 0 ELSE 1 END, CASE b.special_use WHEN '' THEN 1 ELSE 0 END, b.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Mailbox
	for rows.Next() {
		var total, unread, size int64
		m, err := scanMailbox(rows, &total, &unread, &size)
		if err != nil {
			return nil, err
		}
		m.Total, m.Unread, m.Size = total, unread, size
		out = append(out, m)
	}
	return out, rows.Err()
}

// Mailbox returns one of a user's folders.
func (s *Store) Mailbox(ctx context.Context, userID, id int64) (Mailbox, error) {
	return scanMailbox(s.r.QueryRowContext(ctx, `SELECT `+mailboxCols+` FROM mailboxes b WHERE b.id=? AND b.user_id=?`, id, userID))
}

// MailboxByName finds a user's folder by name. INBOX is case-insensitive.
func (s *Store) MailboxByName(ctx context.Context, userID int64, name string) (Mailbox, error) {
	if strings.EqualFold(name, "INBOX") {
		name = "INBOX"
	}
	return scanMailbox(s.r.QueryRowContext(ctx, `SELECT `+mailboxCols+` FROM mailboxes b WHERE b.user_id=? AND b.name=?`, userID, name))
}

// MailboxByUse finds a user's folder by special use.
func (s *Store) MailboxByUse(ctx context.Context, userID int64, use string) (Mailbox, error) {
	return scanMailbox(s.r.QueryRowContext(ctx, `SELECT `+mailboxCols+` FROM mailboxes b WHERE b.user_id=? AND b.special_use=? ORDER BY b.id LIMIT 1`, userID, use))
}

func validMailboxName(name string) error {
	if name == "" || len(name) > 200 || strings.EqualFold(name, "INBOX") || strings.ContainsAny(name, "\r\n\x00*%") ||
		strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return fmt.Errorf("invalid folder name %q: %w", name, ErrInvalid)
	}
	return nil
}

// CreateMailbox adds a folder. "/" separates levels.
func (s *Store) CreateMailbox(ctx context.Context, userID int64, name string) (Mailbox, error) {
	if err := validMailboxName(name); err != nil {
		return Mailbox{}, err
	}
	var id int64
	err := s.w.QueryRowContext(ctx, `INSERT INTO mailboxes(user_id, name, uid_validity) VALUES (?, ?, ?) RETURNING id`, userID, name, s.now().UnixNano()/1e6&0x7fffffff).Scan(&id)
	if isUnique(err) {
		return Mailbox{}, fmt.Errorf("folder %q: %w", name, ErrExists)
	}
	if err != nil {
		return Mailbox{}, err
	}
	return s.Mailbox(ctx, userID, id)
}

// RenameMailbox renames a folder and its children.
func (s *Store) RenameMailbox(ctx context.Context, userID, id int64, newName string) error {
	if err := validMailboxName(newName); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *Tx) error {
		var old string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM mailboxes WHERE id=? AND user_id=?`, id, userID).Scan(&old); err != nil {
			return ErrNotFound
		}
		if old == "INBOX" {
			return fmt.Errorf("INBOX cannot be renamed: %w", ErrInvalid)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE mailboxes SET name=? WHERE id=?`, newName, id); err != nil {
			if isUnique(err) {
				return fmt.Errorf("folder %q: %w", newName, ErrExists)
			}
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE mailboxes SET name = ? || substr(name, ?) WHERE user_id=? AND name LIKE ? ESCAPE '\'`,
			newName+"/", len(old)+2, userID, likeEscape(old)+"/%")
		return err
	})
}

// DeleteMailbox removes a folder that is not special-use, with its messages.
func (s *Store) DeleteMailbox(ctx context.Context, userID, id int64) error {
	return s.tx(ctx, func(tx *Tx) error {
		var use string
		if err := tx.QueryRowContext(ctx, `SELECT special_use FROM mailboxes WHERE id=? AND user_id=?`, id, userID).Scan(&use); err != nil {
			return ErrNotFound
		}
		if use != "" {
			return fmt.Errorf("special folders cannot be deleted: %w", ErrInvalid)
		}
		ids, err := queryIDs(ctx, tx, `SELECT id FROM messages WHERE mailbox_id=?`, id)
		if err != nil {
			return err
		}
		if err := expungeIDs(ctx, tx, userID, ids, false); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM mailboxes WHERE id=?`, id)
		return err
	})
}

// SetSubscribed changes a folder's subscription (IMAP LSUB).
func (s *Store) SetSubscribed(ctx context.Context, userID, id int64, on bool) error {
	res, err := s.w.ExecContext(ctx, `UPDATE mailboxes SET subscribed=? WHERE id=? AND user_id=?`, on, id, userID)
	return affected(res, err)
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func queryIDs(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, query string, args ...any) ([]int64, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
