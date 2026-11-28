// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package pop3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/store/pgtest"
)

func TestPOP3(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(context.Background(), pgtest.URL(t), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bl, _ := blob.Open(dir + "/blobs")
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	hash, _ := auth.HashPassword("secret-pass")
	u, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", hash, store.RoleUser, 0)
	h := hub.New()
	d := &mail.Deliverer{Store: st, Blobs: bl, Hub: h, Hostname: "mx.test", TmpDir: dir, MaxSize: 1 << 20}
	inbox, _ := st.MailboxByUse(ctx, u.ID, store.UseInbox)
	for _, body := range []string{
		"From: bob@example.com\r\nSubject: one\r\n\r\nline 1\r\n.dot line\r\nline 3\r\n",
		"From: bob@example.com\r\nSubject: two\r\n\r\nhello\r\n",
	} {
		if _, err := d.Append(ctx, u, inbox.ID, 0, time.Now(), strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}

	srvTLS := testTLS(t)
	srv := New(Config{Hostname: "mx.test", TLS: srvTLS}, st, bl, h, slog.New(slog.DiscardHandler))
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	ln := tls.NewListener(raw, srvTLS)
	go srv.Serve(ln)
	defer srv.Close()

	// Without TLS, passwords are refused.
	{
		plainLn, _ := net.Listen("tcp", "127.0.0.1:0")
		go srv.Serve(plainLn)
		nc, err := net.Dial("tcp", plainLn.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c := textproto.NewConn(nc)
		c.ReadLine()
		c.PrintfLine("USER ana@acme.example")
		if r, _ := c.ReadLine(); !strings.HasPrefix(r, "-ERR") {
			t.Fatalf("plaintext USER accepted: %q", r)
		}
		c.Close()
	}

	open := func() *textproto.Conn {
		nc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		c := textproto.NewConn(nc)
		t.Cleanup(func() { c.Close() })
		c.ReadLine()
		return c
	}
	cmd := func(c *textproto.Conn, line string) string {
		t.Helper()
		c.PrintfLine("%s", line)
		r, err := c.ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	multi := func(c *textproto.Conn) []string {
		t.Helper()
		lines, err := c.ReadDotLines()
		if err != nil {
			t.Fatal(err)
		}
		return lines
	}

	c := open()
	if r := cmd(c, "USER ana@northwind.example"); !strings.HasPrefix(r, "+OK") {
		t.Fatal(r)
	}
	if r := cmd(c, "PASS wrong"); !strings.HasPrefix(r, "-ERR [AUTH]") {
		t.Fatal(r)
	}
	plain := base64.StdEncoding.EncodeToString([]byte("\x00ana@northwind.example\x00secret-pass"))
	if r := cmd(c, "AUTH PLAIN "+plain); r != "+OK 2 messages" {
		t.Fatal(r)
	}
	// A second session cannot open the same maildrop.
	c2 := open()
	if r := cmd(c2, "AUTH PLAIN "+plain); !strings.Contains(r, "IN-USE") {
		t.Fatal(r)
	}
	if r := cmd(c, "STAT"); !strings.HasPrefix(r, "+OK 2 ") {
		t.Fatal(r)
	}
	cmd(c, "UIDL")
	if ids := multi(c); len(ids) != 2 || !strings.HasPrefix(ids[0], "1 ") {
		t.Fatal(ids)
	}
	cmd(c, "RETR 1")
	body := strings.Join(multi(c), "\n")
	if !strings.Contains(body, "Subject: one") || !strings.Contains(body, "\n.dot line\n") {
		t.Fatalf("retr: %q", body)
	}
	cmd(c, "TOP 1 1")
	if top := multi(c); top[len(top)-1] != "line 1" {
		t.Fatalf("top: %q", top)
	}
	if r := cmd(c, "DELE 1"); !strings.HasPrefix(r, "+OK") {
		t.Fatal(r)
	}
	if r := cmd(c, "RETR 1"); !strings.HasPrefix(r, "-ERR") {
		t.Fatal(r)
	}
	if r := cmd(c, "QUIT"); !strings.HasPrefix(r, "+OK") {
		t.Fatal(r)
	}
	msgs, _ := st.MailboxMessages(ctx, u.ID, inbox.ID)
	if len(msgs) != 1 || msgs[0].Subject != "two" {
		t.Fatalf("after quit: %+v", msgs)
	}

	// The lock is released after QUIT.
	time.Sleep(50 * time.Millisecond)
	c3 := open()
	if r := cmd(c3, "AUTH PLAIN "+plain); r != "+OK 1 messages" {
		t.Fatal(r)
	}
}

// testTLS returns a server config with a throwaway self-signed certificate.
func testTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mx.test"},
		DNSNames: []string{"mx.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}
