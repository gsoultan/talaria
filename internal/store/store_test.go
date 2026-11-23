// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import (
	"context"
	"errors"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seed(t *testing.T, s *Store, tenant, domain, addr string) (Tenant, User) {
	t.Helper()
	ctx := context.Background()
	tn, err := s.CreateTenant(ctx, Tenant{Name: tenant, DisplayName: tenant})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDomain(ctx, tn.ID, domain); err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateUser(ctx, tn.ID, addr, "Test", "x", RoleUser, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tn, u
}

func msg(tn Tenant, u User, hash string, subject string) NewMessage {
	return NewMessage{TenantID: tn.ID, UserID: u.ID, BlobHash: []byte(hash), Size: 100, StoredSize: 50, InternalDate: 1000,
		Subject: subject, FromAddr: "a@b.example", SearchText: "hello quarterly report " + subject}
}

func TestTenantIsolationAndRouting(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	tnA, ana := seed(t, s, "northwind", "northwind.example", "ana@northwind.example")
	tnB, _ := seed(t, s, "harbor", "harbor.example", "bo@harbor.example")

	// A tenant cannot create users on another tenant's domain.
	if _, err := s.CreateUser(ctx, tnB.ID, "evil@northwind.example", "", "x", RoleUser, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant user: %v", err)
	}
	if _, err := s.CreateDomain(ctx, tnB.ID, "NorthWind.Example"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate domain: %v", err)
	}
	if _, err := s.CreateAlias(ctx, tnA.ID, "sales@northwind.example", ana.ID); err != nil {
		t.Fatal(err)
	}
	for _, rcpt := range []string{"ANA@northwind.example", "sales@northwind.example", "ana+news@northwind.example"} {
		u, err := s.ResolveRecipient(ctx, rcpt)
		if err != nil || u.ID != ana.ID {
			t.Fatalf("%s: %v %v", rcpt, u.ID, err)
		}
	}
	if _, err := s.ResolveRecipient(ctx, "nobody@northwind.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	tnA.SeatLimit = 1
	if err := s.UpdateTenant(ctx, tnA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, tnA.ID, "two@northwind.example", "", "x", RoleUser, 0); !errors.Is(err, ErrSeatLimit) {
		t.Fatalf("seat limit: %v", err)
	}
}

func TestMessageLifecycle(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	tn, u := seed(t, s, "northwind", "northwind.example", "ana@northwind.example")
	_, other := seed(t, s, "harbor", "harbor.example", "bo@harbor.example")

	m1, err := s.InsertMessage(ctx, msg(tn, u, "h1", "Q3 numbers"))
	if err != nil {
		t.Fatal(err)
	}
	nm := msg(tn, u, "h1", "Re: Q3 numbers")
	nm.InReplyTo = "<root@x>"
	first := msg(tn, u, "h2", "root")
	first.MessageID = "<root@x>"
	root, _ := s.InsertMessage(ctx, first)
	reply, err := s.InsertMessage(ctx, nm)
	if err != nil {
		t.Fatal(err)
	}
	if reply.ThreadID != root.ThreadID || reply.UID != 3 || m1.UID != 1 {
		t.Fatalf("thread/uid: %+v %+v", reply, root)
	}
	mbs, _ := s.ListMailboxes(ctx, u.ID)
	if mbs[0].Name != "INBOX" || mbs[0].Total != 3 || mbs[0].Unread != 3 {
		t.Fatalf("inbox counts: %+v", mbs[0])
	}
	// Other users can't see or touch these messages.
	if _, err := s.Message(ctx, other.ID, m1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-user read: %v", err)
	}
	if mb, _ := s.SetFlags(ctx, other.ID, []int64{m1.ID}, FlagSeen, 0); len(mb) != 0 {
		t.Fatal("cross-user flag")
	}
	if _, err := s.SetFlags(ctx, u.ID, []int64{m1.ID}, FlagSeen|FlagFlagged, 0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Message(ctx, u.ID, m1.ID)
	if got.Flags != FlagSeen|FlagFlagged || string(got.BlobHash) != "h1" {
		t.Fatalf("flags: %+v", got)
	}
	res, err := s.Search(ctx, u.ID, "quarter", SearchOptions{})
	if err != nil || len(res) != 3 {
		t.Fatalf("search: %d %v", len(res), err)
	}
	if res, _ := s.Search(ctx, other.ID, "quarter", SearchOptions{}); len(res) != 0 {
		t.Fatal("cross-user search")
	}
	if _, err := s.Search(ctx, u.ID, `") OR (* NEAR`, SearchOptions{}); err != nil {
		t.Fatalf("injection-safe query: %v", err)
	}

	trash, _ := s.MailboxByUse(ctx, u.ID, UseTrash)
	if _, err := s.MoveMessages(ctx, u.ID, []int64{m1.ID}, trash.ID); err != nil {
		t.Fatal(err)
	}
	inbox := mbs[0]
	_, gone, _, err := s.Changes(ctx, u.ID, inbox.ID, 0)
	if err != nil || len(gone) != 1 || gone[0] != m1.UID {
		t.Fatalf("changes: %v %v", gone, err)
	}
	if _, err := s.ExpungeMessages(ctx, u.ID, []int64{m1.ID, reply.ID}); err != nil {
		t.Fatal(err)
	}
	dead, _ := s.DeadBlobs(ctx, 10)
	if len(dead) != 1 || string(dead[0].Hash) != "h1" {
		t.Fatalf("dead blobs: %+v", dead)
	}
	got2, _ := s.User(ctx, u.ID)
	if got2.UsedBytes != 100 {
		t.Fatalf("used bytes %d", got2.UsedBytes)
	}

	// Quota.
	u.QuotaBytes = 150
	if err := s.UpdateUser(ctx, got2.withQuota(150)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertMessage(ctx, msg(tn, u, "h3", "big")); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("quota: %v", err)
	}
	if err := s.DeleteMailbox(ctx, u.ID, trash.ID); err == nil {
		t.Fatal("deleted a special folder")
	}
	proj, err := s.CreateMailbox(ctx, u.ID, "Projects")
	if err != nil {
		t.Fatal(err)
	}
	s.MoveMessages(ctx, u.ID, []int64{root.ID}, proj.ID)
	if err := s.DeleteMailbox(ctx, u.ID, proj.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.User(ctx, u.ID); got.UsedBytes != 0 {
		t.Fatalf("used after delete %d", got.UsedBytes)
	}
}

func (u User) withQuota(q int64) User { u.QuotaBytes = q; return u }
