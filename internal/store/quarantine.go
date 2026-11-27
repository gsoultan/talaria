// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Why mail was held.
const (
	HeldSpam    = "spam"
	HeldMalware = "malware"
)

// Held is a message in quarantine.
type Held struct {
	ID        int64
	TenantID  int64
	UserID    int64
	Recipient string // the user's address
	Reason    string // HeldSpam or HeldMalware
	Detail    string // what the scanner found
	SpamScore float64
	Auth      int64
	EnvFrom   string
	FromName  string
	FromAddr  string
	Subject   string
	Size      int64
	CreatedAt int64
	Notified  bool

	BlobHash   []byte
	StoredSize int64
}

// Hold puts a stored blob in quarantine for one user.
func (s *Store) Hold(ctx context.Context, h Held) (Held, error) {
	h.CreatedAt = s.unix()
	err := s.tx(ctx, func(tx *Tx) error {
		var blobID int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO blobs(tenant_id, hash, size, stored_size, refs) VALUES (?, ?, ?, ?, 1)
			ON CONFLICT(tenant_id, hash) DO UPDATE SET refs = blobs.refs + 1 RETURNING id`, h.TenantID, h.BlobHash, h.Size, h.StoredSize).Scan(&blobID); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `INSERT INTO quarantine(tenant_id, user_id, blob_id, reason, detail, spam_score, auth_results,
			env_from, from_name, from_addr, subject, size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			h.TenantID, h.UserID, blobID, h.Reason, h.Detail, h.SpamScore, h.Auth, h.EnvFrom, h.FromName, h.FromAddr, h.Subject, h.Size, h.CreatedAt).Scan(&h.ID)
	})
	return h, err
}

const heldCols = `q.id, q.tenant_id, q.user_id, u.local_part || '@' || d.name, q.reason, q.detail, q.spam_score, q.auth_results,
	q.env_from, q.from_name, q.from_addr, q.subject, q.size, q.created_at, q.notified, bl.hash, bl.stored_size`

const heldFrom = ` FROM quarantine q JOIN users u ON u.id=q.user_id JOIN domains d ON d.id=u.domain_id JOIN blobs bl ON bl.id=q.blob_id`

func scanHeld(r interface{ Scan(...any) error }) (Held, error) {
	var h Held
	err := r.Scan(&h.ID, &h.TenantID, &h.UserID, &h.Recipient, &h.Reason, &h.Detail, &h.SpamScore, &h.Auth,
		&h.EnvFrom, &h.FromName, &h.FromAddr, &h.Subject, &h.Size, &h.CreatedAt, &h.Notified, &h.BlobHash, &h.StoredSize)
	return h, err
}

// HeldMessage returns one quarantined message.
func (s *Store) HeldMessage(ctx context.Context, id int64) (Held, error) {
	h, err := scanHeld(s.r.QueryRowContext(ctx, `SELECT `+heldCols+heldFrom+` WHERE q.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}

// HeldFilter narrows ListHeld. TenantID or UserID must be set.
type HeldFilter struct {
	TenantID int64
	UserID   int64
	Reason   string
	// Query matches the sender, subject or recipient.
	Query  string
	Before int64 // ids below this, for paging
	Limit  int
}

// ListHeld returns quarantined mail, newest first.
func (s *Store) ListHeld(ctx context.Context, f HeldFilter) ([]Held, error) {
	var where []string
	var args []any
	if f.TenantID != 0 {
		where, args = append(where, "q.tenant_id=?"), append(args, f.TenantID)
	}
	if f.UserID != 0 {
		where, args = append(where, "q.user_id=?"), append(args, f.UserID)
	}
	if len(where) == 0 {
		return nil, errors.New("quarantine: no tenant or user")
	}
	if f.Reason != "" {
		where, args = append(where, "q.reason=?"), append(args, f.Reason)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q)) + "%"
		where = append(where, `(lower(q.from_addr) LIKE ? OR lower(q.from_name) LIKE ? OR lower(q.subject) LIKE ? OR lower(q.env_from) LIKE ? OR lower(u.local_part || '@' || d.name) LIKE ?)`)
		args = append(args, like, like, like, like, like)
	}
	if f.Before > 0 {
		where, args = append(where, "q.id<?"), append(args, f.Before)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	args = append(args, f.Limit)
	rows, err := s.r.QueryContext(ctx, `SELECT `+heldCols+heldFrom+` WHERE `+strings.Join(where, " AND ")+` ORDER BY q.id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Held
	for rows.Next() {
		h, err := scanHeld(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// DeleteHeld removes a quarantined message.
func (s *Store) DeleteHeld(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM quarantine WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PurgeHeld removes quarantined mail held since before the given time.
func (s *Store) PurgeHeld(ctx context.Context, before int64) (int64, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM quarantine WHERE created_at<?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DigestDue returns messages held since the last digest, oldest first.
func (s *Store) DigestDue(ctx context.Context, limit int) ([]Held, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+heldCols+heldFrom+` WHERE NOT q.notified ORDER BY q.user_id, q.id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Held
	for rows.Next() {
		h, err := scanHeld(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// MarkNotified records that a digest listed these messages.
func (s *Store) MarkNotified(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	_, err := s.w.ExecContext(ctx, `UPDATE quarantine SET notified=TRUE WHERE id IN (`+ph+`)`, args...)
	return err
}
