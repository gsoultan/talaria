// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package spam

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/store/pgtest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestRules(t *testing.T) {
	s := New(Config{}, nil, quiet)
	ctx := context.Background()
	ip := net.ParseIP("203.0.113.9")

	good := s.Score(ctx, Message{RemoteIP: ip, Auth: store.AuthSPFPass | store.AuthDKIMPass | store.AuthDMARCPass,
		Subject: "Minutes from Tuesday", FromName: "Ana", FromAddr: "ana@acme.example", MessageID: "<1@acme.example>", SentDate: 1,
		Text: "Hi all, the minutes are attached. See https://acme.example/wiki for the plan."})
	if good.Score > 0 {
		t.Fatalf("good mail scored %s", good.Header())
	}

	bad := s.Score(ctx, Message{RemoteIP: ip, BadHelo: true, NoRDNS: true,
		Subject: "URGENT ACCOUNT NOTICE", FromName: "service@paypal.com", FromAddr: "x@evil.example",
		Text: "Unusual sign-in activity. Verify your account at http://198.51.100.7/login or https://bit.ly/abc, or it will be closed."})
	if bad.Score < s.JunkScore() {
		t.Fatalf("phish scored %s", bad.Header())
	}
	for _, want := range []string{"NO_AUTH", "BAD_HELO", "NO_RDNS", "MISSING_MID", "MISSING_DATE", "SUBJ_ALL_CAPS", "FROM_NAME_HAS_ADDR", "SPAM_PHRASES", "URL_SHORTENER", "URL_IP_HOST"} {
		if !strings.Contains(bad.Header(), want) {
			t.Errorf("missing %s in %s", want, bad.Header())
		}
	}

	// Mail handed in over HTTP has no IP and is not blamed for it.
	if r := s.Score(ctx, Message{Subject: "Hello", MessageID: "<x>", SentDate: 1}); r.Score != 0 {
		t.Fatalf("ingest: %s", r.Header())
	}
	if !New(Config{RejectScore: 15}, nil, quiet).Rejects(15) || New(Config{}, nil, quiet).Rejects(100) {
		t.Fatal("Rejects")
	}
}

func TestTokens(t *testing.T) {
	a := Tokens("Cheap PILLS", "x@Spam.example", "cheap cheap pills now http://spam.example/buy")
	seen := map[int64]bool{}
	for _, tk := range a {
		if seen[tk] {
			t.Fatal("duplicate token")
		}
		seen[tk] = true
	}
	// Subject words, the sender domain, body words (the link's too) and
	// link hosts.
	if len(a) != 2+1+7+1 {
		t.Fatalf("%d tokens", len(a))
	}
	b := Tokens("cheap pills", "y@spam.example", "")
	if b[0] != a[0] || b[2] != a[2] {
		t.Fatal("tokens must not depend on case")
	}
}

func TestProbability(t *testing.T) {
	spammy := map[int64][2]int{1: {40, 0}, 2: {35, 1}, 3: {30, 2}}
	if p := probability(spammy, 40, 40); p < 0.95 {
		t.Fatalf("spammy %f", p)
	}
	hammy := map[int64][2]int{1: {0, 40}, 2: {1, 38}, 3: {0, 25}}
	if p := probability(hammy, 40, 40); p > 0.05 {
		t.Fatalf("hammy %f", p)
	}
	if p := probability(map[int64][2]int{1: {10, 10}}, 40, 40); p < 0.3 || p > 0.7 {
		t.Fatalf("neutral %f", p)
	}
	if p := probability(nil, 40, 40); p != 0.5 {
		t.Fatalf("empty %f", p)
	}
}

func TestRspamd(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/checkv2" || string(body) != "Subject: x\r\n\r\nhi" {
			http.Error(w, "bad", 400)
			return
		}
		fmt.Fprint(w, `{"score": 7.5, "action": "add header"}`)
	}))
	defer srv.Close()
	s := New(Config{Rspamd: &Rspamd{URL: srv.URL + "/", Password: "pw"}}, nil, quiet)
	r := s.Score(context.Background(), Message{RemoteIP: net.ParseIP("192.0.2.1"), Helo: "mx.example", MailFrom: "a@b.example",
		Rcpts: []string{"c@d.example"}, Subject: "x", MessageID: "<x>", SentDate: 1, Auth: store.AuthDMARCPass,
		Raw: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("Subject: x\r\n\r\nhi")), nil }})
	if r.Score != 7.5-1.5 || got.Get("IP") != "192.0.2.1" || got.Get("Rcpt") != "c@d.example" || got.Get("Password") != "pw" {
		t.Fatalf("%s %v", r.Header(), got)
	}
}

func TestBayesLearns(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, pgtest.URL(t), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "acme", DisplayName: "Acme"})
	st.CreateDomain(ctx, tn.ID, "acme.example")
	u, _ := st.CreateUser(ctx, tn.ID, "ana@acme.example", "Ana", "x", store.RoleUser, 0)
	junk, _ := st.MailboxByUse(ctx, u.ID, store.UseJunk)
	inbox, _ := st.MailboxByUse(ctx, u.ID, store.UseInbox)

	bodies := map[string]string{}
	add := func(i int, text string) int64 {
		hash := fmt.Sprintf("h%03d", i)
		bodies[hash] = text
		m, err := st.InsertMessage(ctx, store.NewMessage{TenantID: tn.ID, UserID: u.ID, BlobHash: []byte(hash), Size: 10, StoredSize: 10,
			InternalDate: 1, Subject: "s", FromAddr: "x@y.example"})
		if err != nil {
			t.Fatal(err)
		}
		return m.ID
	}
	var spamIDs, hamIDs []int64
	for i := range 25 {
		spamIDs = append(spamIDs, add(i, fmt.Sprintf("casino jackpot bonus spins winner %d", i)))
		hamIDs = append(hamIDs, add(100+i, fmt.Sprintf("meeting agenda budget review quarterly %d", i)))
	}
	st.MoveMessages(ctx, u.ID, spamIDs, junk.ID)
	// Ham: move to Junk and back, as a user correcting the filter would.
	st.MoveMessages(ctx, u.ID, hamIDs, junk.ID)
	st.MoveMessages(ctx, u.ID, hamIDs, inbox.ID)

	l := &Learner{Store: st, Log: quiet, Text: func(_ context.Context, _ int64, h []byte) (string, string, string, error) {
		return "s", "x@y.example", bodies[string(h)], nil
	}}
	s := New(Config{}, st, quiet)
	if b, _ := s.Bayes(ctx, u.ID, Tokens("s", "x@y.example", "casino jackpot")); b != 0 {
		t.Fatal("untrained filter must abstain")
	}
	l.Once(ctx)
	if b, sym := s.Bayes(ctx, u.ID, Tokens("s", "x@y.example", "free casino jackpot spins tonight")); b < 3 {
		t.Fatalf("spam: %v %s", b, sym)
	}
	if b, sym := s.Bayes(ctx, u.ID, Tokens("s", "x@y.example", "agenda for the budget review meeting")); b > -2 {
		t.Fatalf("ham: %v %s", b, sym)
	}
	// Another user's filter is untouched.
	u2, _ := st.CreateUser(ctx, tn.ID, "lena@acme.example", "Lena", "x", store.RoleUser, 0)
	if b, _ := s.Bayes(ctx, u2.ID, Tokens("s", "x@y.example", "casino jackpot")); b != 0 {
		t.Fatal("per-user filter leaked")
	}
}
