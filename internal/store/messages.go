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

// Flag is a system message flag, stored as a bitmask.
type Flag int64

const (
	FlagSeen Flag = 1 << iota
	FlagAnswered
	FlagFlagged
	FlagDeleted
	FlagDraft
)

// Authentication result bits recorded at delivery.
const (
	AuthSPFPass   = 1
	AuthDKIMPass  = 2
	AuthDMARCPass = 4
)

// Message is a message summary. The body lives in the blob store.
type Message struct {
	ID             int64
	MailboxID      int64
	UID            int64
	ModSeq         int64
	BlobID         int64
	BlobHash       []byte
	ThreadID       int64
	Flags          Flag
	InternalDate   int64
	Size           int64
	SentDate       int64
	Subject        string
	FromName       string
	FromAddr       string
	To             string
	Cc             string
	MessageID      string
	InReplyTo      string
	Preview        string
	HasAttachments bool
	Auth           int64
}

// NewMessage describes a message to file into a mailbox.
type NewMessage struct {
	TenantID int64
	UserID   int64
	// MailboxID, or MailboxUse when MailboxID is 0 (e.g. UseInbox, UseJunk).
	MailboxID  int64
	MailboxUse string

	BlobHash     []byte
	Size         int64
	StoredSize   int64
	InternalDate int64
	Flags        Flag
	Auth         int64

	SentDate       int64
	Subject        string
	FromName       string
	FromAddr       string
	To             string
	Cc             string
	MessageID      string
	InReplyTo      string
	References     []string
	Preview        string
	HasAttachments bool
	// SearchText is indexed for full-text search, not stored.
	SearchText string
}

const msgCols = `m.id, m.mailbox_id, m.uid, m.modseq, m.blob_id, m.thread_id, m.flags, m.internal_date, m.size, m.sent_date,
	m.subject, m.from_name, m.from_addr, m.to_addrs, m.cc_addrs, m.message_id, m.in_reply_to, m.preview, m.has_attachments, m.auth_results`

func scanMessage(row interface{ Scan(...any) error }, extra ...any) (Message, error) {
	var m Message
	dst := append([]any{&m.ID, &m.MailboxID, &m.UID, &m.ModSeq, &m.BlobID, &m.ThreadID, &m.Flags, &m.InternalDate, &m.Size, &m.SentDate,
		&m.Subject, &m.FromName, &m.FromAddr, &m.To, &m.Cc, &m.MessageID, &m.InReplyTo, &m.Preview, &m.HasAttachments, &m.Auth}, extra...)
	err := row.Scan(dst...)
	if errors.Is(err, sql.ErrNoRows) {
		return m, ErrNotFound
	}
	return m, err
}

// InsertMessage files a message into a user's mailbox in one transaction:
// quota check, blob reference, UID and modseq assignment, threading and
// search indexing.
func (s *Store) InsertMessage(ctx context.Context, nm NewMessage) (Message, error) {
	var m Message
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		m, err = insertMessage(ctx, tx, nm)
		return err
	})
	return m, err
}

func checkQuota(ctx context.Context, tx *sql.Tx, tenantID, userID, add int64) error {
	var userQuota, used, tenantQuota, tenantUsed int64
	err := tx.QueryRowContext(ctx, `SELECT u.quota_bytes, u.used_bytes, t.quota_bytes, (SELECT COALESCE(SUM(used_bytes),0) FROM users WHERE tenant_id=t.id)
		FROM users u JOIN tenants t ON t.id=u.tenant_id WHERE u.id=? AND u.tenant_id=?`, userID, tenantID).Scan(&userQuota, &used, &tenantQuota, &tenantUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("user: %w", ErrNotFound)
	}
	if err != nil {
		return err
	}
	if (userQuota > 0 && used+add > userQuota) || (tenantQuota > 0 && tenantUsed+add > tenantQuota) {
		return ErrQuotaExceeded
	}
	return nil
}

func insertMessage(ctx context.Context, tx *sql.Tx, nm NewMessage) (Message, error) {
	if err := checkQuota(ctx, tx, nm.TenantID, nm.UserID, nm.Size); err != nil {
		return Message{}, err
	}
	mailboxID := nm.MailboxID
	if mailboxID == 0 {
		use := nm.MailboxUse
		if use == "" {
			use = UseInbox
		}
		if err := tx.QueryRowContext(ctx, `SELECT id FROM mailboxes WHERE user_id=? AND special_use=? ORDER BY id LIMIT 1`, nm.UserID, use).Scan(&mailboxID); err != nil {
			return Message{}, fmt.Errorf("mailbox %s: %w", use, ErrNotFound)
		}
	} else {
		var owner int64
		if err := tx.QueryRowContext(ctx, `SELECT user_id FROM mailboxes WHERE id=?`, mailboxID).Scan(&owner); err != nil || owner != nm.UserID {
			return Message{}, fmt.Errorf("mailbox: %w", ErrNotFound)
		}
	}
	var blobID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO blobs(tenant_id, hash, size, stored_size, refs) VALUES (?, ?, ?, ?, 1)
		ON CONFLICT(tenant_id, hash) DO UPDATE SET refs = refs + 1 RETURNING id`, nm.TenantID, nm.BlobHash, nm.Size, nm.StoredSize).Scan(&blobID); err != nil {
		return Message{}, err
	}
	var uid, modseq int64
	if err := tx.QueryRowContext(ctx, `UPDATE mailboxes SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1 WHERE id=?
		RETURNING uid_next - 1, highest_modseq`, mailboxID).Scan(&uid, &modseq); err != nil {
		return Message{}, err
	}
	threadID := findThread(ctx, tx, nm.UserID, append([]string{nm.InReplyTo}, nm.References...))
	res, err := tx.ExecContext(ctx, `INSERT INTO messages(mailbox_id, uid, modseq, blob_id, thread_id, flags, internal_date, size, sent_date,
		subject, from_name, from_addr, to_addrs, cc_addrs, message_id, in_reply_to, preview, has_attachments, auth_results)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		mailboxID, uid, modseq, blobID, threadID, nm.Flags, nm.InternalDate, nm.Size, nm.SentDate,
		nm.Subject, nm.FromName, nm.FromAddr, nm.To, nm.Cc, nm.MessageID, nm.InReplyTo, nm.Preview, nm.HasAttachments, nm.Auth)
	if err != nil {
		return Message{}, err
	}
	id, _ := res.LastInsertId()
	if threadID == 0 {
		threadID = id
		if _, err := tx.ExecContext(ctx, `UPDATE messages SET thread_id=? WHERE id=?`, id, id); err != nil {
			return Message{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO messages_fts(rowid, subject, addrs, body) VALUES (?, ?, ?, ?)`,
		id, nm.Subject, strings.Join([]string{nm.FromName, nm.FromAddr, nm.To, nm.Cc}, " "), nm.SearchText); err != nil {
		return Message{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET used_bytes = used_bytes + ? WHERE id=?`, nm.Size, nm.UserID); err != nil {
		return Message{}, err
	}
	return Message{ID: id, MailboxID: mailboxID, UID: uid, ModSeq: modseq, BlobID: blobID, BlobHash: nm.BlobHash, ThreadID: threadID,
		Flags: nm.Flags, InternalDate: nm.InternalDate, Size: nm.Size, SentDate: nm.SentDate, Subject: nm.Subject,
		FromName: nm.FromName, FromAddr: nm.FromAddr, To: nm.To, Cc: nm.Cc, MessageID: nm.MessageID, InReplyTo: nm.InReplyTo,
		Preview: nm.Preview, HasAttachments: nm.HasAttachments, Auth: nm.Auth}, nil
}

func findThread(ctx context.Context, tx *sql.Tx, userID int64, ids []string) int64 {
	var clean []any
	for _, id := range ids {
		if id != "" && len(clean) < 20 {
			clean = append(clean, id)
		}
	}
	if len(clean) == 0 {
		return 0
	}
	q := `SELECT m.thread_id FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=? AND m.message_id IN (?` +
		strings.Repeat(",?", len(clean)-1) + `) LIMIT 1`
	var t int64
	tx.QueryRowContext(ctx, q, append([]any{userID}, clean...)...).Scan(&t)
	return t
}

// ListOptions pages through a mailbox, newest first.
type ListOptions struct {
	Limit int
	// Cursor: return messages older than (BeforeDate, BeforeID).
	BeforeDate  int64
	BeforeID    int64
	UnreadOnly  bool
	FlaggedOnly bool
}

// ListMessages returns one page of a user's mailbox.
func (s *Store) ListMessages(ctx context.Context, userID, mailboxID int64, o ListOptions) ([]Message, error) {
	if o.Limit <= 0 || o.Limit > 500 {
		o.Limit = 100
	}
	q := `SELECT ` + msgCols + ` FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=? AND m.mailbox_id=?`
	args := []any{userID, mailboxID}
	if o.BeforeID > 0 {
		q += ` AND (m.internal_date < ? OR (m.internal_date = ? AND m.id < ?))`
		args = append(args, o.BeforeDate, o.BeforeDate, o.BeforeID)
	}
	if o.UnreadOnly {
		q += ` AND (m.flags & 1) = 0`
	}
	if o.FlaggedOnly {
		q += ` AND (m.flags & 4) <> 0`
	}
	q += ` ORDER BY m.internal_date DESC, m.id DESC LIMIT ?`
	args = append(args, o.Limit)
	return s.queryMessages(ctx, q, args...)
}

func (s *Store) queryMessages(ctx context.Context, q string, args ...any) ([]Message, error) {
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Message
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Thread returns all of a user's messages in a thread, oldest first.
func (s *Store) Thread(ctx context.Context, userID, threadID int64) ([]Message, error) {
	return s.queryMessages(ctx, `SELECT `+msgCols+` FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
		WHERE b.user_id=? AND m.thread_id=? ORDER BY m.internal_date, m.id LIMIT 500`, userID, threadID)
}

// Message returns one of a user's messages with its blob hash.
func (s *Store) Message(ctx context.Context, userID, id int64) (Message, error) {
	var hash []byte
	m, err := scanMessage(s.r.QueryRowContext(ctx, `SELECT `+msgCols+`, bl.hash FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
		JOIN blobs bl ON bl.id=m.blob_id WHERE m.id=? AND b.user_id=?`, id, userID), &hash)
	m.BlobHash = hash
	return m, err
}

// MessageByUID returns a message by mailbox and UID (IMAP).
func (s *Store) MessageByUID(ctx context.Context, userID, mailboxID, uid int64) (Message, error) {
	var hash []byte
	m, err := scanMessage(s.r.QueryRowContext(ctx, `SELECT `+msgCols+`, bl.hash FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
		JOIN blobs bl ON bl.id=m.blob_id WHERE m.mailbox_id=? AND m.uid=? AND b.user_id=?`, mailboxID, uid, userID), &hash)
	m.BlobHash = hash
	return m, err
}

// MailboxMessages returns every message in a mailbox in UID order (IMAP SELECT).
func (s *Store) MailboxMessages(ctx context.Context, userID, mailboxID int64) ([]Message, error) {
	return s.queryMessages(ctx, `SELECT `+msgCols+` FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
		WHERE b.user_id=? AND m.mailbox_id=? ORDER BY m.uid`, userID, mailboxID)
}

// Changes lists what changed in a mailbox after modseq: updated or added
// messages and expunged UIDs.
func (s *Store) Changes(ctx context.Context, userID, mailboxID, sinceModSeq int64) ([]Message, []int64, int64, error) {
	mb, err := s.Mailbox(ctx, userID, mailboxID)
	if err != nil {
		return nil, nil, 0, err
	}
	msgs, err := s.queryMessages(ctx, `SELECT `+msgCols+` FROM messages m WHERE m.mailbox_id=? AND m.modseq>? ORDER BY m.uid LIMIT 1000`, mailboxID, sinceModSeq)
	if err != nil {
		return nil, nil, 0, err
	}
	gone, err := queryIDs(ctx, s.r, `SELECT message_id FROM expunged WHERE mailbox_id=? AND modseq>? LIMIT 1000`, mailboxID, sinceModSeq)
	return msgs, gone, mb.HighestModSeq, err
}

// groupByMailbox returns the user's messages among ids, grouped by mailbox.
func groupByMailbox(ctx context.Context, tx *sql.Tx, userID int64, ids []int64) (map[int64][]int64, error) {
	out := map[int64][]int64{}
	for _, chunk := range chunks(ids, 500) {
		rows, err := tx.QueryContext(ctx, `SELECT m.id, m.mailbox_id FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id
			WHERE b.user_id=? AND m.id IN (`+placeholders(len(chunk))+`)`, append([]any{userID}, toAny(chunk)...)...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, mb int64
			if err := rows.Scan(&id, &mb); err != nil {
				rows.Close()
				return nil, err
			}
			out[mb] = append(out[mb], id)
		}
		rows.Close()
	}
	return out, nil
}

func bumpModSeq(ctx context.Context, tx *sql.Tx, mailboxID int64) (int64, error) {
	var m int64
	err := tx.QueryRowContext(ctx, `UPDATE mailboxes SET highest_modseq = highest_modseq + 1 WHERE id=? RETURNING highest_modseq`, mailboxID).Scan(&m)
	return m, err
}

// SetFlags adds and removes flags on a user's messages. It returns the
// affected mailbox ids.
func (s *Store) SetFlags(ctx context.Context, userID int64, ids []int64, add, remove Flag) ([]int64, error) {
	var mailboxes []int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		groups, err := groupByMailbox(ctx, tx, userID, ids)
		if err != nil {
			return err
		}
		for mb, mids := range groups {
			modseq, err := bumpModSeq(ctx, tx, mb)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE messages SET flags = (flags | ?) & ~?, modseq=? WHERE id IN (`+placeholders(len(mids))+`)`,
				append([]any{add, remove, modseq}, toAny(mids)...)...); err != nil {
				return err
			}
			mailboxes = append(mailboxes, mb)
		}
		return nil
	})
	return mailboxes, err
}

// SetKeywords adds and removes keywords (labels) on a user's messages.
func (s *Store) SetKeywords(ctx context.Context, userID int64, ids []int64, add, remove []string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		groups, err := groupByMailbox(ctx, tx, userID, ids)
		if err != nil {
			return err
		}
		for mb, mids := range groups {
			modseq, err := bumpModSeq(ctx, tx, mb)
			if err != nil {
				return err
			}
			for _, id := range mids {
				for _, k := range add {
					if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO message_keywords(message_id, keyword) VALUES (?, ?)`, id, k); err != nil {
						return err
					}
				}
				for _, k := range remove {
					if _, err := tx.ExecContext(ctx, `DELETE FROM message_keywords WHERE message_id=? AND keyword=?`, id, k); err != nil {
						return err
					}
				}
				if _, err := tx.ExecContext(ctx, `UPDATE messages SET modseq=? WHERE id=?`, modseq, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Keywords returns the keywords of a message.
func (s *Store) Keywords(ctx context.Context, messageID int64) ([]string, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT keyword FROM message_keywords WHERE message_id=? ORDER BY keyword`, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// MoveMessages moves a user's messages to another of their mailboxes. Each
// gets a new UID there; the source records an expunge. It returns the
// affected mailbox ids.
func (s *Store) MoveMessages(ctx context.Context, userID int64, ids []int64, destID int64) ([]int64, error) {
	var touched []int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var owner int64
		if err := tx.QueryRowContext(ctx, `SELECT user_id FROM mailboxes WHERE id=?`, destID).Scan(&owner); err != nil || owner != userID {
			return fmt.Errorf("destination: %w", ErrNotFound)
		}
		groups, err := groupByMailbox(ctx, tx, userID, ids)
		if err != nil {
			return err
		}
		for src, mids := range groups {
			if src == destID {
				continue
			}
			srcModSeq, err := bumpModSeq(ctx, tx, src)
			if err != nil {
				return err
			}
			for _, id := range mids {
				var uid, modseq int64
				if err := tx.QueryRowContext(ctx, `UPDATE mailboxes SET uid_next = uid_next + 1, highest_modseq = highest_modseq + 1 WHERE id=?
					RETURNING uid_next - 1, highest_modseq`, destID).Scan(&uid, &modseq); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO expunged(mailbox_id, uid, modseq, message_id) SELECT mailbox_id, uid, ?, id FROM messages WHERE id=?`, srcModSeq, id); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE messages SET mailbox_id=?, uid=?, modseq=? WHERE id=?`, destID, uid, modseq, id); err != nil {
					return err
				}
			}
			touched = append(touched, src)
		}
		touched = append(touched, destID)
		return nil
	})
	return touched, err
}

// CopyMessages copies a user's messages into another of their mailboxes,
// sharing the stored body. It returns the new messages.
func (s *Store) CopyMessages(ctx context.Context, tenantID, userID int64, ids []int64, destID int64) ([]Message, error) {
	var out []Message
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, id := range ids {
			var nm NewMessage
			var refsHash []byte
			err := tx.QueryRowContext(ctx, `SELECT bl.hash, m.size, bl.stored_size, m.internal_date, m.flags, m.auth_results, m.sent_date, m.subject,
				m.from_name, m.from_addr, m.to_addrs, m.cc_addrs, m.message_id, m.in_reply_to, m.preview, m.has_attachments
				FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id JOIN blobs bl ON bl.id=m.blob_id WHERE m.id=? AND b.user_id=?`, id, userID).
				Scan(&refsHash, &nm.Size, &nm.StoredSize, &nm.InternalDate, &nm.Flags, &nm.Auth, &nm.SentDate, &nm.Subject,
					&nm.FromName, &nm.FromAddr, &nm.To, &nm.Cc, &nm.MessageID, &nm.InReplyTo, &nm.Preview, &nm.HasAttachments)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			nm.TenantID, nm.UserID, nm.MailboxID, nm.BlobHash = tenantID, userID, destID, refsHash
			nm.SearchText = nm.Preview
			m, err := insertMessage(ctx, tx, nm)
			if err != nil {
				return err
			}
			out = append(out, m)
		}
		return nil
	})
	return out, err
}

// ExpungeMessages permanently removes a user's messages. It returns the
// affected mailbox ids.
func (s *Store) ExpungeMessages(ctx context.Context, userID int64, ids []int64) ([]int64, error) {
	var touched []int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		groups, err := groupByMailbox(ctx, tx, userID, ids)
		if err != nil {
			return err
		}
		for mb, mids := range groups {
			if err := expungeIDs(ctx, tx, userID, mids, true); err != nil {
				return err
			}
			touched = append(touched, mb)
		}
		return nil
	})
	return touched, err
}

// expungeIDs deletes messages already known to belong to userID.
func expungeIDs(ctx context.Context, tx *sql.Tx, userID int64, ids []int64, record bool) error {
	for _, chunk := range chunks(ids, 500) {
		in := placeholders(len(chunk))
		args := toAny(chunk)
		if record {
			rows, err := tx.QueryContext(ctx, `SELECT DISTINCT mailbox_id FROM messages WHERE id IN (`+in+`)`, args...)
			if err != nil {
				return err
			}
			var mbs []int64
			for rows.Next() {
				var mb int64
				rows.Scan(&mb)
				mbs = append(mbs, mb)
			}
			rows.Close()
			for _, mb := range mbs {
				modseq, err := bumpModSeq(ctx, tx, mb)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO expunged(mailbox_id, uid, modseq, message_id) SELECT mailbox_id, uid, ?, id FROM messages
					WHERE mailbox_id=? AND id IN (`+in+`)`, append([]any{modseq, mb}, args...)...); err != nil {
					return err
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET used_bytes = MAX(0, used_bytes - (SELECT COALESCE(SUM(size),0) FROM messages WHERE id IN (`+in+`))) WHERE id=?`,
			append(args, userID)...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE blobs SET refs = refs - (SELECT COUNT(*) FROM messages m WHERE m.blob_id=blobs.id AND m.id IN (`+in+`))
			WHERE id IN (SELECT blob_id FROM messages WHERE id IN (`+in+`))`, append(args, args...)...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages_fts WHERE rowid IN (`+in+`)`, args...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages WHERE id IN (`+in+`)`, args...); err != nil {
			return err
		}
	}
	return nil
}

// DeadBlob is a stored body no message refers to any more.
type DeadBlob struct {
	ID       int64
	TenantID int64
	Hash     []byte
}

// DeadBlobs lists up to limit unreferenced blobs.
func (s *Store) DeadBlobs(ctx context.Context, limit int) ([]DeadBlob, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, tenant_id, hash FROM blobs WHERE refs<=0 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeadBlob
	for rows.Next() {
		var b DeadBlob
		if err := rows.Scan(&b.ID, &b.TenantID, &b.Hash); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBlob removes a blob row if it is still unreferenced. It reports
// whether the row was deleted, so the caller can then delete the file.
func (s *Store) DeleteBlob(ctx context.Context, id int64) (bool, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM blobs WHERE id=? AND refs<=0`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PruneExpunged removes expunge records older than keep modseqs per mailbox.
func (s *Store) PruneExpunged(ctx context.Context, keep int64) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM expunged WHERE modseq < (SELECT highest_modseq FROM mailboxes b WHERE b.id=expunged.mailbox_id) - ?`, keep)
	return err
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return "?" + strings.Repeat(",?", n-1)
}

func toAny(ids []int64) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

func chunks(ids []int64, n int) [][]int64 {
	var out [][]int64
	for len(ids) > n {
		out = append(out, ids[:n])
		ids = ids[n:]
	}
	if len(ids) > 0 {
		out = append(out, ids)
	}
	return out
}
