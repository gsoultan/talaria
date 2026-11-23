// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Role is what a user may administer.
type Role int

const (
	RoleUser          Role = 0
	RoleTenantAdmin   Role = 1
	RolePlatformAdmin Role = 2
)

// User is a mailbox owner.
type User struct {
	ID           int64
	TenantID     int64
	DomainID     int64
	LocalPart    string
	Domain       string
	DisplayName  string
	PasswordHash string
	Role         Role
	QuotaBytes   int64
	UsedBytes    int64
	Suspended    bool
	CreatedAt    int64
}

// Address returns the user's primary address.
func (u User) Address() string { return u.LocalPart + "@" + u.Domain }

// SplitAddress splits and normalizes local@domain.
func SplitAddress(addr string) (local, domain string, err error) {
	addr = strings.TrimSpace(addr)
	i := strings.LastIndexByte(addr, '@')
	if i <= 0 || i == len(addr)-1 {
		return "", "", fmt.Errorf("invalid address %q: %w", addr, ErrInvalid)
	}
	domain, err = NormalizeDomain(addr[i+1:])
	if err != nil {
		return "", "", err
	}
	local = strings.ToLower(addr[:i])
	if strings.ContainsAny(local, " \t\r\n<>\"") {
		return "", "", fmt.Errorf("invalid address %q: %w", addr, ErrInvalid)
	}
	return local, domain, nil
}

// CreateUser adds a user in the tenant that owns the address's domain. The
// tenant's seat limit is enforced in the same transaction.
func (s *Store) CreateUser(ctx context.Context, tenantID int64, address, displayName, passwordHash string, role Role, quota int64) (User, error) {
	local, domain, err := SplitAddress(address)
	if err != nil {
		return User{}, err
	}
	u := User{TenantID: tenantID, LocalPart: local, Domain: domain, DisplayName: displayName, PasswordHash: passwordHash, Role: role, QuotaBytes: quota, CreatedAt: s.unix()}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT id FROM domains WHERE name=? AND tenant_id=?`, domain, tenantID).Scan(&u.DomainID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("domain %s is not in this tenant: %w", domain, ErrNotFound)
			}
			return err
		}
		var limit, count int64
		if err := tx.QueryRowContext(ctx, `SELECT seat_limit, (SELECT COUNT(*) FROM users WHERE tenant_id=?) FROM tenants WHERE id=?`, tenantID, tenantID).Scan(&limit, &count); err != nil {
			return err
		}
		if limit > 0 && count >= limit {
			return ErrSeatLimit
		}
		var taken int
		tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM aliases WHERE domain_id=? AND local_part=?`, u.DomainID, local).Scan(&taken)
		if taken > 0 {
			return fmt.Errorf("%s is an alias: %w", address, ErrExists)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO users(tenant_id, domain_id, local_part, display_name, password_hash, role, quota_bytes, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, tenantID, u.DomainID, local, displayName, passwordHash, role, quota, u.CreatedAt)
		if isUnique(err) {
			return fmt.Errorf("user %s: %w", address, ErrExists)
		}
		if err != nil {
			return err
		}
		u.ID, _ = res.LastInsertId()
		return createDefaultMailboxes(ctx, tx, u.ID, s.unix())
	})
	return u, err
}

const userCols = `u.id, u.tenant_id, u.domain_id, u.local_part, d.name, u.display_name, u.password_hash, u.role, u.quota_bytes, u.used_bytes, u.suspended OR t.suspended, u.created_at`
const userFrom = ` FROM users u JOIN domains d ON d.id=u.domain_id JOIN tenants t ON t.id=u.tenant_id `

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.DomainID, &u.LocalPart, &u.Domain, &u.DisplayName, &u.PasswordHash, &u.Role, &u.QuotaBytes, &u.UsedBytes, &u.Suspended, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

// User returns a user by id.
func (s *Store) User(ctx context.Context, id int64) (User, error) {
	return scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+userFrom+`WHERE u.id=?`, id))
}

// UserByAddress finds a user by primary address (not aliases).
func (s *Store) UserByAddress(ctx context.Context, address string) (User, error) {
	local, domain, err := SplitAddress(address)
	if err != nil {
		return User{}, ErrNotFound
	}
	return scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+userFrom+`WHERE d.name=? AND u.local_part=?`, domain, local))
}

// ResolveRecipient maps an envelope recipient to the user who receives it:
// a primary address, an alias, plus-addressing (user+tag@) or the domain's
// catch-all, in that order.
func (s *Store) ResolveRecipient(ctx context.Context, address string) (User, error) {
	local, domain, err := SplitAddress(address)
	if err != nil {
		return User{}, ErrNotFound
	}
	candidates := []string{local}
	if i := strings.IndexByte(local, '+'); i > 0 {
		candidates = append(candidates, local[:i])
	}
	for _, l := range candidates {
		u, err := scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+userFrom+`WHERE d.name=? AND u.local_part=?`, domain, l))
		if err == nil {
			return u, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return u, err
		}
		u, err = scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+userFrom+`JOIN aliases a ON a.user_id=u.id JOIN domains ad ON ad.id=a.domain_id WHERE ad.name=? AND a.local_part=?`, domain, l))
		if err == nil {
			return u, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return u, err
		}
	}
	return scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+userFrom+`JOIN domains cd ON cd.catchall_user_id=u.id WHERE cd.name=?`, domain))
}

// ListUsers returns a tenant's users.
func (s *Store) ListUsers(ctx context.Context, tenantID int64) ([]User, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+userCols+userFrom+`WHERE u.tenant_id=? ORDER BY d.name, u.local_part`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = ""
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser changes a user's display name, role, quota and suspension
// within a tenant.
func (s *Store) UpdateUser(ctx context.Context, u User) error {
	res, err := s.w.ExecContext(ctx, `UPDATE users SET display_name=?, role=?, quota_bytes=?, suspended=? WHERE id=? AND tenant_id=?`,
		u.DisplayName, u.Role, u.QuotaBytes, u.Suspended, u.ID, u.TenantID)
	return affected(res, err)
}

// SetPassword replaces a user's password hash and signs out all sessions.
func (s *Store) SetPassword(ctx context.Context, userID int64, hash string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, hash, userID)
		if err := affected(res, err); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
		return err
	})
}

// DeleteUser removes a user of a tenant and all their mail.
func (s *Store) DeleteUser(ctx context.Context, tenantID, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE blobs SET refs = refs - (SELECT COUNT(*) FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=? AND m.blob_id=blobs.id)
			WHERE id IN (SELECT m.blob_id FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=?)`, id, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages_fts WHERE rowid IN (SELECT m.id FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id WHERE b.user_id=?)`, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=? AND tenant_id=?`, id, tenantID)
		return affected(res, err)
	})
}

// Alias is an extra address delivering to a user.
type Alias struct {
	ID      int64
	Address string
	UserID  int64
}

// CreateAlias adds an alias in a domain of the same tenant as the user.
func (s *Store) CreateAlias(ctx context.Context, tenantID int64, address string, userID int64) (Alias, error) {
	local, domain, err := SplitAddress(address)
	if err != nil {
		return Alias{}, err
	}
	a := Alias{Address: local + "@" + domain, UserID: userID}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var domainID, owner int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM domains WHERE name=? AND tenant_id=?`, domain, tenantID).Scan(&domainID); err != nil {
			return fmt.Errorf("domain %s is not in this tenant: %w", domain, ErrNotFound)
		}
		if err := tx.QueryRowContext(ctx, `SELECT tenant_id FROM users WHERE id=?`, userID).Scan(&owner); err != nil || owner != tenantID {
			return fmt.Errorf("user: %w", ErrNotFound)
		}
		var taken int
		tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE domain_id=? AND local_part=?`, domainID, local).Scan(&taken)
		if taken > 0 {
			return fmt.Errorf("%s is a user: %w", a.Address, ErrExists)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO aliases(tenant_id, domain_id, local_part, user_id) VALUES (?, ?, ?, ?)`, tenantID, domainID, local, userID)
		if isUnique(err) {
			return fmt.Errorf("alias %s: %w", a.Address, ErrExists)
		}
		if err != nil {
			return err
		}
		a.ID, _ = res.LastInsertId()
		return nil
	})
	return a, err
}

// ListAliases returns a tenant's aliases, or one user's when userID > 0.
func (s *Store) ListAliases(ctx context.Context, tenantID, userID int64) ([]Alias, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT a.id, a.local_part || '@' || d.name, a.user_id FROM aliases a JOIN domains d ON d.id=a.domain_id
		WHERE a.tenant_id=? AND (?=0 OR a.user_id=?) ORDER BY 2`, tenantID, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alias
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.ID, &a.Address, &a.UserID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAlias removes an alias of a tenant.
func (s *Store) DeleteAlias(ctx context.Context, tenantID, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM aliases WHERE id=? AND tenant_id=?`, id, tenantID)
	return affected(res, err)
}

// Session is a signed-in browser or client.
type Session struct {
	UserID    int64
	CreatedAt int64
	ExpiresAt int64
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CreateSession stores a session for token. Only the token's hash is kept,
// so a database leak does not leak usable sessions.
func (s *Store) CreateSession(ctx context.Context, token string, userID, ttlSeconds int64, userAgent, clientIP string) error {
	now := s.unix()
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions(token_hash, user_id, created_at, expires_at, user_agent, client_ip) VALUES (?, ?, ?, ?, ?, ?)`,
		tokenHash(token), userID, now, now+ttlSeconds, truncate(userAgent, 256), clientIP)
	return err
}

// SessionUser returns the user of a valid, unexpired session.
func (s *Store) SessionUser(ctx context.Context, token string) (User, error) {
	return scanUser(s.r.QueryRowContext(ctx, `SELECT `+userCols+userFrom+`JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?`,
		tokenHash(token), s.unix()))
}

// DeleteSession signs a session out.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash(token))
	return err
}

// PurgeExpiredSessions removes expired sessions.
func (s *Store) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	res, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, s.unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// DeleteSessions signs a user out everywhere.
func (s *Store) DeleteSessions(ctx context.Context, userID int64) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}
