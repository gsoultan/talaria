// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

func TestIngest(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	defer st.Close()
	bl, _ := blob.Open(dir + "/blobs")
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw", DisplayName: "Northwind"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", "x", store.RoleUser, 0)
	h := &Handler{Token: "secret-token", Store: st, Log: slog.Default(),
		Deliver: &mail.Deliverer{Store: st, Blobs: bl, Hostname: "mx.test", TmpDir: dir, MaxSize: 1 << 20}}

	post := func(token, to, body string) int {
		req := httptest.NewRequest("POST", "/ingest/v1/message", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Envelope-From", "bob@sender.example")
		req.Header.Set("X-Envelope-To", to)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	msg := "From: bob@sender.example\r\nSubject: via worker\r\n\r\nhello\r\n"
	if c := post("wrong", "ana@northwind.example", msg); c != http.StatusUnauthorized {
		t.Fatal(c)
	}
	if c := post("secret-token", "nobody@northwind.example", msg); c != 550 {
		t.Fatal(c)
	}
	if c := post("secret-token", "ana@northwind.example, nobody@northwind.example", msg); c != 200 {
		t.Fatal(c)
	}
	if c := post("secret-token", "ana@northwind.example", strings.Repeat("x", 2<<20)); c != http.StatusRequestEntityTooLarge {
		t.Fatal(c)
	}
}
