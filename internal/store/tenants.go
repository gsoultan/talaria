// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// Tenant is an organization with its own domains, users and limits.
type Tenant struct {
	ID             int64
	Name           string // short unique slug
	DisplayName    string
	SeatLimit      int64
	QuotaBytes     int64
	DailySendLimit int64
	Suspended      bool
	CreatedAt      int64
	// Filled by ListTenants.
	Domains   int64
	Users     int64
	UsedBytes int64
}

// Domain is a mail domain owned by one tenant.
type Domain struct {
	ID        int64
	TenantID  int64
	Name      string
	CreatedAt int64
	Users     int64
}

// CreateTenant adds a tenant.
func (s *Store) CreateTenant(ctx context.Context, t Tenant) (Tenant, error) {
	t.Name = strings.ToLower(strings.TrimSpace(t.Name))
	if t.Name == "" {
		return t, fmt.Errorf("tenant name is required: %w", ErrInvalid)
	}
	if t.DisplayName == "" {
		t.DisplayName = t.Name
	}
	t.CreatedAt = s.unix()
	res, err := s.w.ExecContext(ctx, `INSERT INTO tenants(name, display_name, seat_limit, quota_bytes, daily_send_limit, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, t.Name, t.DisplayName, t.SeatLimit, t.QuotaBytes, t.DailySendLimit, t.CreatedAt)
	if isUnique(err) {
		return t, fmt.Errorf("tenant %q: %w", t.Name, ErrExists)
	}
	if err != nil {
		return t, err
	}
	t.ID, _ = res.LastInsertId()
	return t, nil
}

// UpdateTenant changes a tenant's display name, limits and suspension.
func (s *Store) UpdateTenant(ctx context.Context, t Tenant) error {
	res, err := s.w.ExecContext(ctx, `UPDATE tenants SET display_name=?, seat_limit=?, quota_bytes=?, daily_send_limit=?, suspended=? WHERE id=?`,
		t.DisplayName, t.SeatLimit, t.QuotaBytes, t.DailySendLimit, t.Suspended, t.ID)
	return affected(res, err)
}

// DeleteTenant removes a tenant and everything it owns. Blob files are left
// for the garbage collector.
func (s *Store) DeleteTenant(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM tenants WHERE id=?`, id)
	return affected(res, err)
}

// Tenant returns one tenant.
func (s *Store) Tenant(ctx context.Context, id int64) (Tenant, error) {
	var t Tenant
	err := s.r.QueryRowContext(ctx, `SELECT id, name, display_name, seat_limit, quota_bytes, daily_send_limit, suspended, created_at FROM tenants WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.DisplayName, &t.SeatLimit, &t.QuotaBytes, &t.DailySendLimit, &t.Suspended, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// TenantByName finds a tenant by slug.
func (s *Store) TenantByName(ctx context.Context, name string) (Tenant, error) {
	var id int64
	err := s.r.QueryRowContext(ctx, `SELECT id FROM tenants WHERE name=?`, strings.ToLower(name)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, ErrNotFound
	}
	if err != nil {
		return Tenant{}, err
	}
	return s.Tenant(ctx, id)
}

// ListTenants returns all tenants with usage counts.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT t.id, t.name, t.display_name, t.seat_limit, t.quota_bytes, t.daily_send_limit, t.suspended, t.created_at,
		(SELECT COUNT(*) FROM domains d WHERE d.tenant_id=t.id),
		(SELECT COUNT(*) FROM users u WHERE u.tenant_id=t.id),
		(SELECT COALESCE(SUM(used_bytes),0) FROM users u WHERE u.tenant_id=t.id)
		FROM tenants t ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.SeatLimit, &t.QuotaBytes, &t.DailySendLimit, &t.Suspended, &t.CreatedAt, &t.Domains, &t.Users, &t.UsedBytes); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// NormalizeDomain lower-cases a domain and converts it to ASCII (punycode).
func NormalizeDomain(name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	a, err := idna.Lookup.ToASCII(name)
	if err != nil || a == "" || !strings.Contains(a, ".") {
		return "", fmt.Errorf("invalid domain %q: %w", name, ErrInvalid)
	}
	return strings.ToLower(a), nil
}

// CreateDomain adds a domain to a tenant.
func (s *Store) CreateDomain(ctx context.Context, tenantID int64, name string) (Domain, error) {
	n, err := NormalizeDomain(name)
	if err != nil {
		return Domain{}, err
	}
	d := Domain{TenantID: tenantID, Name: n, CreatedAt: s.unix()}
	res, err := s.w.ExecContext(ctx, `INSERT INTO domains(tenant_id, name, created_at) VALUES (?, ?, ?)`, tenantID, n, d.CreatedAt)
	if isUnique(err) {
		return d, fmt.Errorf("domain %q: %w", n, ErrExists)
	}
	if err != nil {
		return d, err
	}
	d.ID, _ = res.LastInsertId()
	return d, nil
}

// DeleteDomain removes a domain of a tenant, with its users and aliases.
func (s *Store) DeleteDomain(ctx context.Context, tenantID, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM domains WHERE id=? AND tenant_id=?`, id, tenantID)
	return affected(res, err)
}

// ListDomains returns a tenant's domains.
func (s *Store) ListDomains(ctx context.Context, tenantID int64) ([]Domain, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT d.id, d.tenant_id, d.name, d.created_at, (SELECT COUNT(*) FROM users u WHERE u.domain_id=d.id)
		FROM domains d WHERE d.tenant_id=? ORDER BY d.name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.CreatedAt, &d.Users); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DomainByName finds a domain by name across tenants.
func (s *Store) DomainByName(ctx context.Context, name string) (Domain, error) {
	n, err := NormalizeDomain(name)
	if err != nil {
		return Domain{}, ErrNotFound
	}
	var d Domain
	err = s.r.QueryRowContext(ctx, `SELECT id, tenant_id, name, created_at FROM domains WHERE name=?`, n).Scan(&d.ID, &d.TenantID, &d.Name, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
