// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"testing"

	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/store/pgtest"
)

func TestSignInDedupe(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, pgtest.URL(t), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	u, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", "x", store.RoleUser, 0)
	r := &Recorder{Store: st}
	for range 3 {
		r.SignIn(ctx, "imap", "ana@northwind.example", u, "198.51.100.1", true, "")
		r.SignIn(ctx, "web", "ana@northwind.example", u, "198.51.100.1", true, "")
		r.SignIn(ctx, "pop3", "nobody@northwind.example", store.User{}, "198.51.100.2", false, FailReason(store.User{}, false))
	}
	r.SignIn(ctx, "imap", "ana@northwind.example", u, "198.51.100.9", true, "") // new IP
	es, _ := st.ListAudit(ctx, store.AuditFilter{TenantID: tn.ID})
	count := map[string]int{}
	for _, e := range es {
		count[e.Action+"/"+e.Outcome]++
	}
	// Mail app sign-ins once a day per IP, webmail every time, failures
	// once a minute; the unknown address is filed under its domain's tenant.
	if count["sign_in/ok"] != 5 || count["sign_in_failed/unknown account"] != 1 || len(es) != 6 {
		t.Fatalf("%v", count)
	}
	var nilRec *Recorder
	nilRec.SignIn(ctx, "web", "x", u, "", true, "") // must not panic
	nilRec.Record(ctx, store.AuditEntry{Action: "x"})
}
