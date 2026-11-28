// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"strings"
)

// Certificate sources.
const (
	CertOwn       = "own"       // the user's own, published from their browser
	CertImported  = "imported"  // added by the user
	CertHarvested = "harvested" // taken from signed mail
)

// Certificate is an S/MIME certificate a user knows, for one address.
type Certificate struct {
	ID          int64
	UserID      int64
	Email       string
	DER         []byte
	Fingerprint []byte
	Subject     string
	Issuer      string
	NotBefore   int64
	NotAfter    int64
	Source      string
	CreatedAt   int64
}

const certCols = `id, user_id, email, der, fingerprint, subject, issuer, not_before, not_after, source, created_at`

func scanCerts(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]Certificate, error) {
	var out []Certificate
	for rows.Next() {
		var c Certificate
		if err := rows.Scan(&c.ID, &c.UserID, &c.Email, &c.DER, &c.Fingerprint, &c.Subject, &c.Issuer, &c.NotBefore, &c.NotAfter, &c.Source, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveCertificate stores a certificate. Saving one already there keeps
// it, upgrading a harvested one to imported or own.
func (s *Store) SaveCertificate(ctx context.Context, c Certificate) error {
	c.Email = strings.ToLower(c.Email)
	_, err := s.w.ExecContext(ctx, `INSERT INTO smime_certs(user_id, email, der, fingerprint, subject, issuer, not_before, not_after, source, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (user_id, email, fingerprint) DO UPDATE SET source = EXCLUDED.source
		WHERE smime_certs.source = 'harvested' OR EXCLUDED.source = 'own'`,
		c.UserID, c.Email, c.DER, c.Fingerprint, c.Subject, c.Issuer, c.NotBefore, c.NotAfter, c.Source, s.unix())
	return err
}

// Certificates lists a user's certificates, by address then newest.
func (s *Store) Certificates(ctx context.Context, userID int64) ([]Certificate, error) {
	rows, err := s.r.QueryContext(ctx, `SELECT `+certCols+` FROM smime_certs WHERE user_id=? ORDER BY email, not_after DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCerts(rows)
}

// CertificatesFor returns certificates for the addresses that the user
// knows, and the own certificates colleagues in the same tenant published.
func (s *Store) CertificatesFor(ctx context.Context, u User, emails []string) ([]Certificate, error) {
	if len(emails) == 0 {
		return nil, nil
	}
	args := []any{u.ID, u.TenantID}
	ph := make([]string, len(emails))
	for i, e := range emails {
		ph[i] = "?"
		args = append(args, strings.ToLower(e))
	}
	rows, err := s.r.QueryContext(ctx, `SELECT `+prefixed("c.", certCols)+` FROM smime_certs c JOIN users u ON u.id = c.user_id
		WHERE (c.user_id=? OR (c.source='own' AND u.tenant_id=?)) AND c.email IN (`+strings.Join(ph, ",")+`)
		ORDER BY c.email, c.not_after DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCerts(rows)
}

// DeleteCertificate removes one of the user's certificates.
func (s *Store) DeleteCertificate(ctx context.Context, userID, id int64) error {
	res, err := s.w.ExecContext(ctx, `DELETE FROM smime_certs WHERE id=? AND user_id=?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func prefixed(p, cols string) string {
	parts := strings.Split(cols, ", ")
	for i := range parts {
		parts[i] = p + parts[i]
	}
	return strings.Join(parts, ", ")
}
