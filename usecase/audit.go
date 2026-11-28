// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/audit"
	"github.com/gsoultan/talaria/internal/store"
)

const auditPage = 100

func (s *Admin) auditFilter(ctx context.Context, in domain.ListAudit) (store.AuditFilter, store.User, error) {
	u, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return store.AuditFilter{}, u, err
	}
	return store.AuditFilter{TenantID: tid, WithPlatform: u.Role == store.RolePlatformAdmin && tid == u.TenantID,
		Action: strings.TrimSpace(in.Action), Query: in.Query, Since: in.Since, Until: in.Until, Before: in.Before}, u, nil
}

// ListAudit searches a tenant's audit log. Platform admins looking at
// their own tenant also see entries that belong to no tenant.
func (s *Admin) ListAudit(ctx context.Context, in domain.ListAudit) (domain.AuditLog, error) {
	f, _, err := s.auditFilter(ctx, in)
	if err != nil {
		return domain.AuditLog{}, err
	}
	f.Limit = auditPage + 1
	es, err := s.Store.ListAudit(ctx, f)
	if err != nil {
		return domain.AuditLog{}, storeErr(err)
	}
	out := domain.AuditLog{Entries: []domain.AuditEntry{}, More: len(es) > auditPage}
	for i, e := range es {
		if i == auditPage {
			break
		}
		out.Entries = append(out.Entries, domain.AuditEntry{ID: e.ID, At: e.At, Actor: e.Actor, IP: e.IP, Action: e.Action,
			Target: e.Target, Outcome: e.Outcome, Detail: e.Detail})
	}
	return out, nil
}

// ExportAudit writes the matching entries as CSV, at most 100,000, and
// records the export itself.
func (s *Admin) ExportAudit(ctx context.Context, in domain.ListAudit, w io.Writer) error {
	f, u, err := s.auditFilter(ctx, in)
	if err != nil {
		return err
	}
	s.Audit.Record(ctx, store.AuditEntry{TenantID: f.TenantID, ActorID: u.ID, Actor: u.Address(), IP: s.ip(ctx), Action: "admin.ExportAudit",
		Detail: audit.Detail(map[string]any{"action": f.Action, "q": f.Query, "since": f.Since, "until": f.Until})})
	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "time", "actor", "ip", "action", "target", "outcome", "detail"})
	for total := 0; total < 100_000; {
		f.Limit = 1000
		es, err := s.Store.ListAudit(ctx, f)
		if err != nil {
			return storeErr(err)
		}
		for _, e := range es {
			cw.Write([]string{strconv.FormatInt(e.ID, 10), time.Unix(e.At, 0).UTC().Format(time.RFC3339), csvSafe(e.Actor), e.IP,
				e.Action, csvSafe(e.Target), csvSafe(e.Outcome), csvSafe(e.Detail)})
		}
		total += len(es)
		if len(es) < f.Limit {
			break
		}
		f.Before = es[len(es)-1].ID
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe keeps a spreadsheet from reading a cell as a formula.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
