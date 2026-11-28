// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
)

// DLPPolicy is a tenant's rule for outgoing mail.
type DLPPolicy struct {
	ID           int64
	TenantID     int64
	Name         string
	Detector     string
	Pattern      string
	MinCount     int
	Action       string
	ExternalOnly bool
	Notify       string
	Enabled      bool
	CreatedAt    int64
}

const dlpCols = `id, tenant_id, name, detector, pattern, min_count, action, external_only, notify, enabled, created_at`

// DLPPolicies lists a tenant's policies; onlyEnabled skips switched-off ones.
func (s *Store) DLPPolicies(ctx context.Context, tenantID int64, onlyEnabled bool) ([]DLPPolicy, error) {
	q := `SELECT ` + dlpCols + ` FROM dlp_policies WHERE tenant_id=?`
	if onlyEnabled {
		q += ` AND enabled`
	}
	rows, err := s.r.QueryContext(ctx, q+` ORDER BY id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DLPPolicy
	for rows.Next() {
		var p DLPPolicy
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Detector, &p.Pattern, &p.MinCount, &p.Action, &p.ExternalOnly, &p.Notify, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveDLPPolicy creates a policy (ID 0) or replaces one of the tenant's.
func (s *Store) SaveDLPPolicy(ctx context.Context, p DLPPolicy) (DLPPolicy, error) {
	if p.ID == 0 {
		p.CreatedAt = s.unix()
		err := s.w.QueryRowContext(ctx, `INSERT INTO dlp_policies(tenant_id, name, detector, pattern, min_count, action, external_only, notify, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`, p.TenantID, p.Name, p.Detector, p.Pattern, p.MinCount, p.Action, p.ExternalOnly, p.Notify, p.Enabled, p.CreatedAt).Scan(&p.ID)
		return p, err
	}
	err := s.w.QueryRowContext(ctx, `UPDATE dlp_policies SET name=?, detector=?, pattern=?, min_count=?, action=?, external_only=?, notify=?, enabled=?
		WHERE id=? AND tenant_id=? RETURNING created_at`, p.Name, p.Detector, p.Pattern, p.MinCount, p.Action, p.ExternalOnly, p.Notify, p.Enabled, p.ID, p.TenantID).Scan(&p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// DeleteDLPPolicy removes one of a tenant's policies.
func (s *Store) DeleteDLPPolicy(ctx context.Context, tenantID, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM dlp_policies WHERE id=? AND tenant_id=?`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TenantAdmins lists a tenant's admins, for policy notices.
func (s *Store) TenantAdmins(ctx context.Context, tenantID int64) ([]User, error) {
	all, err := s.ListUsers(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []User
	for _, u := range all {
		if u.Role >= RoleTenantAdmin && !u.Suspended {
			out = append(out, u)
		}
	}
	return out, nil
}
