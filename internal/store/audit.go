// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"strings"
)

// AuditEntry is one row of the audit log.
type AuditEntry struct {
	ID       int64
	At       int64
	TenantID int64 // 0: the platform, or an address no tenant owns
	ActorID  int64
	Actor    string // email address, or "system" or "cli"
	IP       string
	Action   string // e.g. sign_in, admin.CreateUser, policy.dlp
	Target   string
	Outcome  string // ok, or why it failed
	Detail   string // JSON object
	Hash     []byte
}

// auditLock serializes appends so the hash chain follows id order.
const auditLock = 0x7461_6c61_7269_61 // "talaria"

// chainHash is the row's hash: SHA-256 over the previous hash and the
// row's fields, each length-prefixed.
func chainHash(prev []byte, e AuditEntry) []byte {
	h := sha256.New()
	h.Write(prev)
	var n [8]byte
	for _, v := range []int64{e.At, e.TenantID, e.ActorID} {
		binary.BigEndian.PutUint64(n[:], uint64(v))
		h.Write(n[:])
	}
	for _, s := range []string{e.Actor, e.IP, e.Action, e.Target, e.Outcome, e.Detail} {
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return h.Sum(nil)
}

// Audit appends an entry. At defaults to now and Outcome to "ok".
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	if e.At == 0 {
		e.At = s.unix()
	}
	if e.Outcome == "" {
		e.Outcome = "ok"
	}
	return s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(?)`, int64(auditLock)); err != nil {
			return err
		}
		var prev []byte
		err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&prev)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		e.Hash = chainHash(prev, e)
		_, err = tx.ExecContext(ctx, `INSERT INTO audit_log(at, tenant_id, actor_id, actor, ip, action, target, outcome, detail, hash)
			VALUES (?,?,?,?,?,?,?,?,?,?)`, e.At, e.TenantID, e.ActorID, e.Actor, e.IP, e.Action, e.Target, e.Outcome, e.Detail, e.Hash)
		return err
	})
}

// AuditFilter narrows ListAudit. Zero values match everything.
type AuditFilter struct {
	// TenantID limits to one tenant; -1 means every tenant.
	TenantID int64
	// WithPlatform also includes rows with no tenant (platform admins).
	WithPlatform bool
	Action       string // prefix, e.g. "admin." or "sign_in"
	Query        string // words found in the actor, target, IP or detail
	Since, Until int64  // unix seconds, inclusive
	Before       int64  // id, for paging back
	Limit        int
}

const auditCols = `id, at, tenant_id, actor_id, actor, ip, action, target, outcome, detail, hash`

// ListAudit returns matching entries, newest first.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	var where []string
	var args []any
	switch {
	case f.TenantID >= 0 && f.WithPlatform:
		where, args = append(where, `tenant_id IN (?, 0)`), append(args, f.TenantID)
	case f.TenantID >= 0:
		where, args = append(where, `tenant_id=?`), append(args, f.TenantID)
	}
	if f.Action != "" {
		where, args = append(where, `action LIKE ?`), append(args, likeEscape(f.Action)+"%")
	}
	for _, w := range strings.Fields(f.Query) {
		where = append(where, `(actor || ' ' || ip || ' ' || action || ' ' || target || ' ' || outcome || ' ' || detail) ILIKE ?`)
		args = append(args, "%"+likeEscape(w)+"%")
	}
	if f.Since > 0 {
		where, args = append(where, `at>=?`), append(args, f.Since)
	}
	if f.Until > 0 {
		where, args = append(where, `at<=?`), append(args, f.Until)
	}
	if f.Before > 0 {
		where, args = append(where, `id<?`), append(args, f.Before)
	}
	q := `SELECT ` + auditCols + ` FROM audit_log`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 10000
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.TenantID, &e.ActorID, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Detail, &e.Hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeAudit removes entries older than before (unix seconds). The
// database refuses to remove anything younger than a day.
func (s *Store) PurgeAudit(ctx context.Context, before int64) (int64, error) {
	var n int64
	err := s.tx(ctx, func(tx *Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('talaria.audit_purge', 'on', true)`); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM audit_log WHERE at<?`, before)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n, err
}

// AuditChain reports how many entries were checked and the id of the
// first whose hash does not follow from the one before (0: intact). The
// oldest remaining entry is taken as given, since retention removes the
// ones before it.
func (s *Store) AuditChain(ctx context.Context) (checked int64, broken int64, err error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+auditCols+` FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var prev []byte
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.TenantID, &e.ActorID, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Detail, &e.Hash); err != nil {
			return checked, 0, err
		}
		if checked > 0 && !bytes.Equal(chainHash(prev, e), e.Hash) && broken == 0 {
			broken = e.ID
		}
		prev = e.Hash
		checked++
	}
	return checked, broken, rows.Err()
}
