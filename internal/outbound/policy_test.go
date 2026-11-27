// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/dlp"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/store/pgtest"
)

func TestSubmitPolicies(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, _ := store.Open(ctx, pgtest.URL(t), store.Options{})
	defer st.Close()
	bl, _ := blob.Open(dir + "/blobs")
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "dlp"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	ana, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", "x", store.RoleUser, 0)
	boss, _ := st.CreateUser(ctx, tn.ID, "boss@northwind.example", "Boss", "x", store.RoleTenantAdmin, 0)
	sec, _ := st.CreateUser(ctx, tn.ID, "security@northwind.example", "Security", "x", store.RoleUser, 0)

	d := &mail.Deliverer{Store: st, Blobs: bl, Hub: hub.New(), Hostname: "mx.test", TmpDir: dir}
	var hits []string
	sub := &Submitter{Store: st, Blobs: bl, Deliver: d, Keys: &Keys{Store: st}, Hostname: "mx.test", TmpDir: dir,
		PolicyHit: func(_ context.Context, _ Submission, subject string, _ []string, ms []dlp.Match, action string) {
			hits = append(hits, subject+":"+ms[0].Policy.Name+":"+action)
		}}
	save := func(p store.DLPPolicy) store.DLPPolicy {
		p.TenantID, p.Enabled = tn.ID, true
		if p.MinCount == 0 {
			p.MinCount = 1
		}
		saved, err := st.SaveDLPPolicy(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return saved
	}
	send := func(subject, body string, rcpts []string, s Submission) (Result, error) {
		s.User, s.MailFrom, s.Rcpts = ana, "ana@northwind.example", rcpts
		msg := "From: ana@northwind.example\r\nTo: " + strings.Join(rcpts, ", ") + "\r\nSubject: " + subject + "\r\n\r\n" + body + "\r\n"
		return sub.Submit(ctx, s, strings.NewReader(msg))
	}
	out := []string{"priya@lumen.example"}
	in := []string{"boss@northwind.example"}

	block := save(store.DLPPolicy{Name: "Cards", Detector: dlp.CreditCard, Action: dlp.Block, ExternalOnly: true})
	var perr *PolicyError
	if _, err := send("card", "4111 1111 1111 1111", out, Submission{}); !errors.As(err, &perr) || perr.Action != dlp.Block {
		t.Fatalf("block: %v", err)
	}
	if !strings.Contains(perr.Error(), "Cards (1 found)") {
		t.Fatalf("message: %s", perr.Error())
	}
	// External only: internal mail goes.
	if res, err := send("card", "4111 1111 1111 1111", in, Submission{}); err != nil || res.Local != 1 {
		t.Fatalf("internal: %+v %v", res, err)
	}
	// Disabled policies do not run.
	block.Enabled = false
	if _, err := st.SaveDLPPolicy(ctx, block); err != nil {
		t.Fatal(err)
	}

	save(store.DLPPolicy{Name: "Falcon", Detector: dlp.Keywords, Pattern: "project falcon", Action: dlp.Warn, Notify: "security@northwind.example"})
	if _, err := send("plan", "about Project Falcon", out, Submission{CanConfirm: true}); !errors.As(err, &perr) || perr.Action != dlp.Warn {
		t.Fatalf("warn: %v", err)
	}
	if res, err := send("plan", "about Project Falcon", out, Submission{CanConfirm: true, Confirmed: true}); err != nil || res.Queued != 1 {
		t.Fatalf("confirmed: %+v %v", res, err)
	}
	// A mail app cannot confirm, so it is sent.
	if res, err := send("plan2", "about project falcon", out, Submission{}); err != nil || res.Queued != 1 {
		t.Fatalf("app: %+v %v", res, err)
	}

	save(store.DLPPolicy{Name: "Accounts", Detector: dlp.IBAN, Action: dlp.Encrypt})
	save(store.DLPPolicy{Name: "Salary", Detector: dlp.Keywords, Pattern: "salary", Action: dlp.Notify})
	if res, err := send("pay", "salary to GB82WEST12345698765432", out, Submission{}); err != nil || res.Queued != 1 {
		t.Fatalf("encrypt: %+v %v", res, err)
	}
	items, _ := st.ListQueue(ctx, tn.ID, -1, 10)
	tls := map[bool]int{}
	for _, it := range items {
		tls[it.RequireTLS]++
	}
	if tls[true] != 1 || tls[false] != 2 {
		t.Fatalf("require_tls flags: %v", tls)
	}

	want := "card:Cards:block plan:Falcon:warn plan:Falcon:warned plan2:Falcon:warned pay:Accounts:encrypt"
	if strings.Join(hits, " ") != want {
		t.Fatalf("hits: %v", hits)
	}

	inbox := func(u store.User) []store.Message {
		mb, _ := st.MailboxByUse(ctx, u.ID, store.UseInbox)
		m, _ := st.ListMessages(ctx, u.ID, mb.ID, store.ListOptions{})
		return m
	}
	// Security got the two warned sends; the boss got the card mail and
	// the salary notice (admins, since that policy names no contact).
	var subs []string
	for _, m := range inbox(sec) {
		subs = append(subs, m.Subject)
	}
	if len(subs) != 2 || subs[0] != "Policy matched: Falcon" {
		t.Fatalf("security: %v", subs)
	}
	subs = nil
	for _, m := range inbox(boss) {
		subs = append(subs, m.Subject)
	}
	if strings.Join(subs, "|") != "Policy matched: Salary|card" && strings.Join(subs, "|") != "card|Policy matched: Salary" {
		t.Fatalf("boss: %v", subs)
	}
	full, _ := st.Message(ctx, boss.ID, inbox(boss)[0].ID)
	if strings.Contains(full.Preview, "salary to GB82") {
		t.Fatalf("notice leaked the message: %q", full.Preview)
	}
}

func TestDirectRequireTLS(t *testing.T) {
	plain := smtp.NewServer(&fakeRelay{})
	plain.Domain = "plain.test"
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go plain.Serve(ln)
	defer plain.Close()

	tlsSrv := smtp.NewServer(&fakeRelay{})
	tlsSrv.Domain = "tls.test"
	tlsSrv.TLSConfig = selfSigned(t)
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	go tlsSrv.Serve(ln2)
	defer tlsSrv.Close()

	direct := func(ln net.Listener) *Direct {
		return &Direct{Hello: "mx.test", Timeout: 5 * time.Second, Port: ln.Addr().(*net.TCPAddr).Port,
			LookupMX: func(context.Context, string) ([]*net.MX, error) {
				return []*net.MX{{Host: "127.0.0.1.", Pref: 10}}, nil
			}}
	}
	body := "Subject: x\r\n\r\nhi\r\n"
	ctx := context.Background()
	if _, err := direct(ln).Send(ctx, "a@x.example", "b@y.example", strings.NewReader(body)); err != nil {
		t.Fatalf("plain without policy: %v", err)
	}
	if _, err := direct(ln).Send(WithRequireTLS(ctx), "a@x.example", "b@y.example", strings.NewReader(body)); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("plain with policy: %v", err)
	}
	if _, err := direct(ln2).Send(WithRequireTLS(ctx), "a@x.example", "b@y.example", strings.NewReader(body)); err == nil {
		t.Fatal("unverified certificate accepted")
	}
}

func TestRelayRequireTLS(t *testing.T) {
	fr := &fakeRelay{}
	rs := smtp.NewServer(fr)
	rs.Domain = "relay.test"
	rs.TLSConfig = selfSigned(t)
	rs.EnableREQUIRETLS = true
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go rs.Serve(ln)
	defer rs.Close()
	r := &Relay{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Username: "apikey", Password: "secret", Hello: "mx.test",
		Timeout: 5 * time.Second, TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	ctx := context.Background()
	for _, c := range []context.Context{ctx, WithRequireTLS(ctx)} {
		if _, err := r.Send(c, "a@x.example", "b@y.example", strings.NewReader("Subject: x\r\n\r\nhi\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	if fr.reqTLS[0] || !fr.reqTLS[1] || len(fr.got) != 2 {
		t.Fatalf("REQUIRETLS: %v, %d sent", fr.reqTLS, len(fr.got))
	}
}
