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

// Queue statuses.
const (
	QueueWaiting = 0
	QueueSending = 1
	QueueSent    = 2
	QueueBounced = 3
)

// ErrSendLimit means the tenant's daily sending limit is used up.
var ErrSendLimit = errors.New("daily sending limit reached")

// QueueItem is one remote recipient of an outbound message.
type QueueItem struct {
	ID          int64
	TenantID    int64
	UserID      int64
	BlobID      int64
	BlobHash    []byte
	MailFrom    string
	RcptTo      string
	RcptDomain  string
	Size        int64
	Status      int
	Attempts    int
	NextAttempt int64
	LastError   string
	CreatedAt   int64
	UpdatedAt   int64
}

// Enqueue adds one row per recipient, all sharing the blob (stored by the
// caller), and enforces the tenant's daily sending limit.
func (s *Store) Enqueue(ctx context.Context, tenantID, userID int64, hash []byte, size, storedSize int64, from string, rcpts []string) error {
	now := s.unix()
	return s.tx(ctx, func(tx *Tx) error {
		var limit, sent int64
		if err := tx.QueryRowContext(ctx, `SELECT daily_send_limit, (SELECT COUNT(*) FROM queue WHERE tenant_id=? AND created_at>?) FROM tenants WHERE id=?`,
			tenantID, now-86400, tenantID).Scan(&limit, &sent); err != nil {
			return fmt.Errorf("tenant: %w", ErrNotFound)
		}
		if limit > 0 && sent+int64(len(rcpts)) > limit {
			return ErrSendLimit
		}
		var blobID int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO blobs(tenant_id, hash, size, stored_size, refs) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(tenant_id, hash) DO UPDATE SET refs = blobs.refs + excluded.refs RETURNING id`, tenantID, hash, size, storedSize, len(rcpts)).Scan(&blobID); err != nil {
			return err
		}
		for _, r := range rcpts {
			dom := ""
			if i := strings.LastIndexByte(r, '@'); i >= 0 {
				dom = strings.ToLower(r[i+1:])
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO queue(tenant_id, user_id, blob_id, mail_from, rcpt_to, rcpt_domain, size, next_attempt, created_at, updated_at)
				VALUES (?, NULLIF(?, 0), ?, ?, ?, ?, ?, ?, ?, ?)`, tenantID, userID, blobID, from, r, dom, size, now, now, now); err != nil {
				return err
			}
		}
		return nil
	})
}

const queueCols = `q.id, q.tenant_id, COALESCE(q.user_id, 0), q.blob_id, b.hash, q.mail_from, q.rcpt_to, q.rcpt_domain, q.size, q.status, q.attempts,
	q.next_attempt, q.last_error, q.created_at, q.updated_at`

func scanQueue(rows *sql.Rows) ([]QueueItem, error) {
	defer rows.Close()
	var out []QueueItem
	for rows.Next() {
		var q QueueItem
		if err := rows.Scan(&q.ID, &q.TenantID, &q.UserID, &q.BlobID, &q.BlobHash, &q.MailFrom, &q.RcptTo, &q.RcptDomain, &q.Size, &q.Status,
			&q.Attempts, &q.NextAttempt, &q.LastError, &q.CreatedAt, &q.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// ClaimDue marks up to limit due items as sending and returns them. Items
// stuck in sending (a crash mid-delivery) are reclaimed after staleAfter
// seconds.
func (s *Store) ClaimDue(ctx context.Context, limit int, staleAfter int64) ([]QueueItem, error) {
	now := s.unix()
	var out []QueueItem
	err := s.tx(ctx, func(tx *Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT `+queueCols+` FROM queue q JOIN blobs b ON b.id=q.blob_id
			WHERE (q.status=0 AND q.next_attempt<=?) OR (q.status=1 AND q.updated_at<=?) ORDER BY q.next_attempt LIMIT ? FOR UPDATE OF q SKIP LOCKED`, now, now-staleAfter, limit)
		if err != nil {
			return err
		}
		if out, err = scanQueue(rows); err != nil {
			return err
		}
		for _, q := range out {
			if _, err := tx.ExecContext(ctx, `UPDATE queue SET status=1, updated_at=? WHERE id=?`, now, q.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// NextDue returns the earliest next_attempt of waiting items, or 0.
func (s *Store) NextDue(ctx context.Context) int64 {
	var t sql.NullInt64
	s.r.QueryRowContext(ctx, `SELECT MIN(next_attempt) FROM queue WHERE status=0`).Scan(&t)
	return t.Int64
}

// finishQueue sets a final status and releases the blob reference.
func (s *Store) finishQueue(ctx context.Context, id int64, status int, msg string) error {
	return s.tx(ctx, func(tx *Tx) error {
		var blobID int64
		if err := tx.QueryRowContext(ctx, `UPDATE queue SET status=?, last_error=?, attempts=attempts+1, updated_at=? WHERE id=? AND status<2 RETURNING blob_id`,
			status, truncate(msg, 500), s.unix(), id).Scan(&blobID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE blobs SET refs=refs-1 WHERE id=?`, blobID)
		return err
	})
}

// MarkSent records a successful delivery.
func (s *Store) MarkSent(ctx context.Context, id int64, reply string) error {
	return s.finishQueue(ctx, id, QueueSent, reply)
}

// MarkBounced records a permanent failure.
func (s *Store) MarkBounced(ctx context.Context, id int64, reason string) error {
	return s.finishQueue(ctx, id, QueueBounced, reason)
}

// MarkRetry schedules another attempt.
func (s *Store) MarkRetry(ctx context.Context, id int64, next int64, reason string) error {
	_, err := s.w.ExecContext(ctx, `UPDATE queue SET status=0, attempts=attempts+1, next_attempt=?, last_error=?, updated_at=? WHERE id=? AND status<2`,
		next, truncate(reason, 500), s.unix(), id)
	return err
}

// ListQueue returns a tenant's queue, newest first (tenantID 0 = all).
func (s *Store) ListQueue(ctx context.Context, tenantID int64, status int, limit int) ([]QueueItem, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.r.QueryContext(ctx, `SELECT `+queueCols+` FROM queue q JOIN blobs b ON b.id=q.blob_id
		WHERE (?=0 OR q.tenant_id=?) AND (?<0 OR q.status=?) ORDER BY q.created_at DESC, q.id DESC LIMIT ?`, tenantID, tenantID, status, status, limit)
	if err != nil {
		return nil, err
	}
	return scanQueue(rows)
}

// QueueStats counts a tenant's items by status over the last day.
func (s *Store) QueueStats(ctx context.Context, tenantID int64) (waiting, sent, bounced int64, err error) {
	err = s.r.QueryRowContext(ctx, `SELECT COUNT(*) FILTER (WHERE status IN (0,1)), COUNT(*) FILTER (WHERE status=2), COUNT(*) FILTER (WHERE status=3) FROM queue
		WHERE (?=0 OR tenant_id=?) AND (status IN (0,1) OR updated_at>?)`, tenantID, tenantID, s.unix()-86400).Scan(&waiting, &sent, &bounced)
	return
}

// RetryNow makes waiting items of a tenant due immediately (id 0 = all).
func (s *Store) RetryNow(ctx context.Context, tenantID, id int64) error {
	_, err := s.w.ExecContext(ctx, `UPDATE queue SET next_attempt=? WHERE status=0 AND (?=0 OR tenant_id=?) AND (?=0 OR id=?)`,
		s.unix(), tenantID, tenantID, id, id)
	return err
}

// CancelQueued drops a waiting item without bouncing it.
func (s *Store) CancelQueued(ctx context.Context, tenantID, id int64) error {
	var owner int64
	if err := s.r.QueryRowContext(ctx, `SELECT tenant_id FROM queue WHERE id=? AND status=0`, id).Scan(&owner); err != nil || (tenantID != 0 && owner != tenantID) {
		return ErrNotFound
	}
	return s.finishQueue(ctx, id, QueueBounced, "cancelled by admin")
}

// PruneQueue deletes finished items older than seconds.
func (s *Store) PruneQueue(ctx context.Context, olderThan int64) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM queue WHERE status>=2 AND updated_at<?`, s.unix()-olderThan)
	return err
}

// DKIMKey is a domain's signing key.
type DKIMKey struct {
	DomainID   int64
	Domain     string
	Selector   string
	Algorithm  string
	PrivateKey []byte
	CreatedAt  int64
}

// SetDKIMKey stores (or replaces) a domain's key.
func (s *Store) SetDKIMKey(ctx context.Context, k DKIMKey) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO dkim_keys(domain_id, selector, algorithm, private_key, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(domain_id) DO UPDATE SET selector=excluded.selector, algorithm=excluded.algorithm, private_key=excluded.private_key, created_at=excluded.created_at`,
		k.DomainID, k.Selector, k.Algorithm, k.PrivateKey, s.unix())
	return err
}

// DKIMKeyFor returns the key of a domain by name.
func (s *Store) DKIMKeyFor(ctx context.Context, domain string) (DKIMKey, error) {
	var k DKIMKey
	err := s.r.QueryRowContext(ctx, `SELECT k.domain_id, d.name, k.selector, k.algorithm, k.private_key, k.created_at FROM dkim_keys k JOIN domains d ON d.id=k.domain_id
		WHERE d.name=?`, strings.ToLower(domain)).Scan(&k.DomainID, &k.Domain, &k.Selector, &k.Algorithm, &k.PrivateKey, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

// IsLocalDomain reports whether a domain is hosted here.
func (s *Store) IsLocalDomain(ctx context.Context, domain string) bool {
	_, err := s.DomainByName(ctx, domain)
	return err == nil
}

// CanSendAs reports whether a user may use address as the sender: their own
// address or one of their aliases.
func (s *Store) CanSendAs(ctx context.Context, u User, address string) bool {
	local, domain, err := SplitAddress(address)
	if err != nil {
		return false
	}
	if local == u.LocalPart && domain == u.Domain {
		return true
	}
	var n int
	s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM aliases a JOIN domains d ON d.id=a.domain_id WHERE a.user_id=? AND a.local_part=? AND d.name=?`,
		u.ID, local, domain).Scan(&n)
	return n > 0
}
