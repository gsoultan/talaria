// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package filter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/store/pgtest"
)

type fakeDNS struct {
	hosts map[string][]string
	ptr   map[string][]string
}

func (d fakeDNS) LookupHost(_ context.Context, h string) ([]string, error) {
	if a, ok := d.hosts[h]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}

func (d fakeDNS) LookupAddr(_ context.Context, a string) ([]string, error) {
	if n, ok := d.ptr[a]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: a, IsNotFound: true}
}

func setup(t *testing.T, cfg Config) (*Filter, *store.Store, store.User) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, pgtest.URL(t), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "acme"})
	d, _ := st.CreateDomain(ctx, tn.ID, "acme.example")
	u, err := st.CreateUser(ctx, tn.ID, "ana@acme.example", "Ana", "x", store.RoleUser, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = d
	dns := fakeDNS{
		hosts: map[string][]string{
			"9.113.0.203.zen.example": {"127.0.0.2"},       // 203.0.113.9 listed
			"8.113.0.203.zen.example": {"127.255.255.254"}, // an error code, not a listing
			"mx.good.example":         {"198.51.100.7"},
		},
		ptr: map[string][]string{"198.51.100.7": {"mx.good.example."}},
	}
	cfg.Hostname = "mail.acme.example"
	return New(cfg, st, dns, slog.New(slog.NewTextHandler(io.Discard, nil))), st, u
}

func conn(t *testing.T, f *Filter, ip, helo string) *Conn {
	t.Helper()
	c, err := f.Connect(context.Background(), net.ParseIP(ip), helo)
	if err != nil {
		t.Fatalf("connect %s %s: %v", ip, helo, err)
	}
	return c
}

func isTemp(err error) bool {
	var r *Reject
	return errors.As(err, &r) && r.Temporary
}

func isPerm(err error) bool {
	var r *Reject
	return errors.As(err, &r) && !r.Temporary
}

func TestHelo(t *testing.T) {
	f, _, _ := setup(t, Config{})
	ctx := context.Background()
	if _, err := f.Connect(ctx, net.ParseIP("203.0.113.5"), "mail.acme.example"); !isPerm(err) {
		t.Fatalf("own hostname: %v", err)
	}
	if _, err := f.Connect(ctx, net.ParseIP("203.0.113.5"), "[203.0.113.6]"); !isPerm(err) {
		t.Fatalf("literal mismatch: %v", err)
	}
	if c := conn(t, f, "203.0.113.5", "[203.0.113.5]"); c.BadHelo {
		t.Fatal("matching literal marked bad")
	}
	if c := conn(t, f, "203.0.113.5", "localhost"); !c.BadHelo {
		t.Fatal("dotless HELO not marked")
	}
	// Local relays may say anything.
	conn(t, f, "127.0.0.1", "mail.acme.example")
}

func TestBlocklistsAndRules(t *testing.T) {
	f, st, u := setup(t, Config{DNSBL: []string{"zen.example"}})
	ctx := context.Background()
	c := conn(t, f, "203.0.113.9", "mx.spam.example")
	if err := f.Recipient(ctx, c, "x@spam.example", u); !isPerm(err) {
		t.Fatalf("listed IP accepted: %v", err)
	}
	if c := conn(t, f, "203.0.113.8", "mx.other.example"); f.Recipient(ctx, c, "x@other.example", u) != nil {
		t.Fatal("127.255.255.x treated as a listing")
	}
	// The tenant trusts that sender: allow skips the blocklist.
	if _, err := st.CreateSenderRule(ctx, store.SenderRule{TenantID: u.TenantID, Kind: store.RuleDomain, Value: "partner.example", Action: store.RuleAllow}); err != nil {
		t.Fatal(err)
	}
	c = conn(t, f, "203.0.113.9", "mx.partner.example")
	if err := f.Recipient(ctx, c, "billing@eu.partner.example", u); err != nil {
		t.Fatalf("allowed subdomain refused: %v", err)
	}
	// A block on one address inside the allowed domain still blocks.
	st.CreateSenderRule(ctx, store.SenderRule{TenantID: u.TenantID, Kind: store.RuleAddress, Value: "Spammer@partner.example", Action: store.RuleBlock})
	if err := f.Recipient(ctx, conn(t, f, "198.51.100.7", "mx.good.example"), "spammer@partner.example", u); !isPerm(err) {
		t.Fatalf("blocked address accepted: %v", err)
	}
	// IP ranges.
	st.CreateSenderRule(ctx, store.SenderRule{TenantID: u.TenantID, Kind: store.RuleIP, Value: "192.0.2.0/24", Action: store.RuleBlock})
	if err := f.Recipient(ctx, conn(t, f, "192.0.2.77", "mx.x.example"), "a@x.example", u); !isPerm(err) {
		t.Fatalf("blocked range accepted: %v", err)
	}
	if _, err := st.CreateSenderRule(ctx, store.SenderRule{TenantID: u.TenantID, Kind: store.RuleIP, Value: "not-an-ip", Action: store.RuleBlock}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("bad rule: %v", err)
	}
}

func TestReverseDNS(t *testing.T) {
	f, _, u := setup(t, Config{RequireRDNS: true})
	ctx := context.Background()
	if err := f.Recipient(ctx, conn(t, f, "198.51.100.7", "mx.good.example"), "a@good.example", u); err != nil {
		t.Fatalf("confirmed rDNS refused: %v", err)
	}
	if err := f.Recipient(ctx, conn(t, f, "203.0.113.20", "mx.x.example"), "a@x.example", u); !isPerm(err) {
		t.Fatalf("no rDNS accepted: %v", err)
	}
}

func TestGreylist(t *testing.T) {
	f, _, u := setup(t, Config{Greylist: true, GreylistDelay: time.Second})
	ctx := context.Background()
	try := func(ip string) error { return f.Recipient(ctx, conn(t, f, ip, "mx.x.example"), "news@x.example", u) }
	if err := try("203.0.113.30"); !isTemp(err) {
		t.Fatalf("first attempt: %v", err)
	}
	if err := try("203.0.113.30"); !isTemp(err) {
		t.Fatalf("retry too early: %v", err)
	}
	time.Sleep(2100 * time.Millisecond)
	// Another host of the same /24 retries: passes.
	if err := try("203.0.113.31"); err != nil {
		t.Fatalf("retry after delay: %v", err)
	}
	if err := try("203.0.113.30"); err != nil {
		t.Fatalf("known triplet: %v", err)
	}
	// Local addresses are never greylisted.
	if err := try("10.0.0.5"); err != nil {
		t.Fatalf("local: %v", err)
	}
}

func TestRatePerIP(t *testing.T) {
	f, _, _ := setup(t, Config{MaxPerIPHour: 2})
	c := conn(t, f, "203.0.113.40", "mx.x.example")
	for i := range 2 {
		if err := f.Mail(c); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if err := f.Mail(c); !isTemp(err) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestReverseName(t *testing.T) {
	if got := ReverseName(netip.MustParseAddr("1.2.3.4")); got != "4.3.2.1" {
		t.Fatal(got)
	}
	got := ReverseName(netip.MustParseAddr("2001:db8::1"))
	if got != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2" {
		t.Fatal(got)
	}
}
