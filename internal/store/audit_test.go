// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"strings"
	"testing"
)

func TestAuditAppendOnly(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	now := s.unix()
	add := func(e AuditEntry) {
		t.Helper()
		if err := s.Audit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	add(AuditEntry{At: now - 400*86400, TenantID: 1, Actor: "old@a.example", Action: "sign_in"})
	add(AuditEntry{TenantID: 1, Actor: "ana@a.example", IP: "203.0.113.9", Action: "sign_in", Detail: `{"via":"imap"}`})
	add(AuditEntry{TenantID: 1, Actor: "ana@a.example", Action: "admin.CreateUser", Target: "POST /api/v1/admin/users", Detail: `{"request":{"email":"100%_real@a.example"}}`})
	add(AuditEntry{TenantID: 2, Actor: "eve@b.example", Action: "sign_in_failed", Outcome: "wrong password"})
	add(AuditEntry{Actor: "cli", Action: "cli.tenant"})

	list := func(f AuditFilter) []string {
		t.Helper()
		es, err := s.ListAudit(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range es {
			out = append(out, e.Action)
		}
		return out
	}
	if got := strings.Join(list(AuditFilter{TenantID: 1, Since: now - 60}), ","); got != "admin.CreateUser,sign_in" {
		t.Fatalf("tenant 1: %s", got)
	}
	if got := strings.Join(list(AuditFilter{TenantID: 2, WithPlatform: true}), ","); got != "cli.tenant,sign_in_failed" {
		t.Fatalf("tenant 2 with platform: %s", got)
	}
	if got := list(AuditFilter{TenantID: -1, Action: "admin."}); len(got) != 1 {
		t.Fatalf("action prefix: %v", got)
	}
	// LIKE wildcards in the search are taken literally.
	if got := list(AuditFilter{TenantID: -1, Query: "100%_real"}); len(got) != 1 {
		t.Fatalf("literal search: %v", got)
	}
	if got := list(AuditFilter{TenantID: -1, Query: "1%_r"}); len(got) != 0 {
		t.Fatalf("wildcards: %v", got)
	}
	if got := list(AuditFilter{TenantID: -1, Query: "imap 203.0.113"}); len(got) != 1 {
		t.Fatalf("two words: %v", got)
	}

	for _, q := range []string{`UPDATE audit_log SET actor='x'`, `DELETE FROM audit_log`, `TRUNCATE audit_log`} {
		if _, err := s.w.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// The purge removes only old rows; the database refuses recent ones.
	if _, err := s.PurgeAudit(ctx, now+3600); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("purge of recent rows: %v", err)
	}
	if n, err := s.PurgeAudit(ctx, now-365*86400); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if n, broken, err := s.AuditChain(ctx); err != nil || n != 4 || broken != 0 {
		t.Fatalf("chain after purge: %d %d %v", n, broken, err)
	}

	// Someone with the database owner's rights edits a row: the chain shows it.
	es, _ := s.ListAudit(ctx, AuditFilter{TenantID: 1})
	for _, q := range []string{`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_change`,
		`UPDATE audit_log SET actor='someone@else.example' WHERE id=` + itoa(es[0].ID),
		`ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_change`} {
		if _, err := s.w.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, broken, _ := s.AuditChain(ctx); broken != es[0].ID {
		t.Fatalf("tampering not found: broken=%d, edited %d", broken, es[0].ID)
	}
}

func itoa(n int64) string {
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		if n /= 10; n == 0 {
			return string(b)
		}
	}
}
