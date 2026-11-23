// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Sender rule kinds and actions.
const (
	RuleIP      = "ip"
	RuleDomain  = "domain"
	RuleAddress = "address"

	RuleAllow = "allow"
	RuleBlock = "block"
)

// SenderRule allows or blocks inbound mail for one tenant.
type SenderRule struct {
	ID        int64
	TenantID  int64
	Kind      string
	Value     string
	Action    string
	Note      string
	CreatedAt int64
}

// NormalizeRule checks a rule and puts its value in canonical form.
func NormalizeRule(r SenderRule) (SenderRule, error) {
	r.Value = strings.ToLower(strings.TrimSpace(r.Value))
	if r.Action != RuleAllow && r.Action != RuleBlock {
		return r, fmt.Errorf("action must be allow or block: %w", ErrInvalid)
	}
	switch r.Kind {
	case RuleIP:
		if p, err := netip.ParsePrefix(r.Value); err == nil {
			r.Value = p.Masked().String()
		} else if a, err := netip.ParseAddr(r.Value); err == nil {
			r.Value = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()).String()
		} else {
			return r, fmt.Errorf("%q is not an IP address or range: %w", r.Value, ErrInvalid)
		}
	case RuleDomain:
		d, err := NormalizeDomain(strings.TrimPrefix(r.Value, "@"))
		if err != nil {
			return r, err
		}
		r.Value = d
	case RuleAddress:
		local, domain, err := SplitAddress(r.Value)
		if err != nil {
			return r, fmt.Errorf("%q is not an email address: %w", r.Value, ErrInvalid)
		}
		r.Value = local + "@" + domain
	default:
		return r, fmt.Errorf("kind must be ip, domain or address: %w", ErrInvalid)
	}
	if len(r.Note) > 200 {
		r.Note = r.Note[:200]
	}
	return r, nil
}

// CreateSenderRule adds a rule to a tenant.
func (s *Store) CreateSenderRule(ctx context.Context, r SenderRule) (SenderRule, error) {
	r, err := NormalizeRule(r)
	if err != nil {
		return r, err
	}
	r.CreatedAt = s.unix()
	err = s.w.QueryRowContext(ctx, `INSERT INTO sender_rules(tenant_id, kind, value, action, note, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		r.TenantID, r.Kind, r.Value, r.Action, r.Note, r.CreatedAt).Scan(&r.ID)
	if isUnique(err) {
		return r, fmt.Errorf("a rule for %s: %w", r.Value, ErrExists)
	}
	return r, err
}

// ListSenderRules returns a tenant's rules.
func (s *Store) ListSenderRules(ctx context.Context, tenantID int64) ([]SenderRule, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT id, tenant_id, kind, value, action, note, created_at FROM sender_rules
		WHERE tenant_id=? ORDER BY action, kind, value`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SenderRule
	for rows.Next() {
		var r SenderRule
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Kind, &r.Value, &r.Action, &r.Note, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteSenderRule removes one of a tenant's rules.
func (s *Store) DeleteSenderRule(ctx context.Context, tenantID, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM sender_rules WHERE id=? AND tenant_id=?`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SenderVerdict returns the action of the tenant's rules for a connecting
// IP and envelope sender: RuleBlock, RuleAllow, or "" when no rule
// matches. Block wins over allow, so a blocked address inside an allowed
// domain stays blocked.
func (s *Store) SenderVerdict(ctx context.Context, tenantID int64, ip netip.Addr, from string) (string, error) {
	var conds []string
	args := []any{tenantID}
	if ip.IsValid() {
		conds = append(conds, `(kind='ip' AND ?::inet <<= value::cidr)`)
		args = append(args, ip.Unmap().String())
	}
	if local, domain, err := SplitAddress(from); err == nil {
		conds = append(conds, `(kind='address' AND value=?)`)
		args = append(args, local+"@"+domain)
		// The domain and each parent: a.b.example matches b.example.
		labels := strings.Split(domain, ".")
		for i := 0; i < len(labels)-1 && i < 8; i++ {
			conds = append(conds, `(kind='domain' AND value=?)`)
			args = append(args, strings.Join(labels[i:], "."))
		}
	}
	if len(conds) == 0 {
		return "", nil
	}
	var action sql.NullString
	err := s.r.QueryRowContext(ctx, `SELECT action FROM sender_rules WHERE tenant_id=? AND (`+strings.Join(conds, " OR ")+`)
		ORDER BY action='block' DESC LIMIT 1`, args...).Scan(&action)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return action.String, err
}

// Greylist records a delivery attempt for key and reports whether it may
// pass: after delay seconds since the first attempt, and from then on until
// the triplet is unused for ttl seconds.
func (s *Store) Greylist(ctx context.Context, key []byte, delay, ttl int64) (bool, error) {
	now := s.unix()
	var first int64
	var passed bool
	err := s.w.QueryRowContext(ctx, `INSERT INTO greylist(key, first_seen, last_seen) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET
		  first_seen = CASE WHEN greylist.last_seen < ? THEN excluded.first_seen ELSE greylist.first_seen END,
		  passed = CASE WHEN greylist.last_seen < ? THEN false ELSE greylist.passed OR greylist.first_seen <= ? END,
		  last_seen = excluded.last_seen
		RETURNING first_seen, passed`, key, now, now, now-ttl, now-ttl, now-delay).Scan(&first, &passed)
	return passed, err
}

// PruneGreylist forgets triplets unused for ttl seconds.
func (s *Store) PruneGreylist(ctx context.Context, ttl int64) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM greylist WHERE last_seen < ?`, s.unix()-ttl)
	return err
}
