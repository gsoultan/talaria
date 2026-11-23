// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/store"
)

const multipart = "From: =?utf-8?q?Priya_N=C3=A1ir?= <Priya@Lumen.example>\r\n" +
	"To: Ana <ana@northwind.example>, bo@harbor.example\r\n" +
	"Subject: Q3 report\r\n" +
	"Message-ID: <abc@lumen.example>\r\n" +
	"In-Reply-To: <root@northwind.example>\r\n" +
	"Date: Mon, 23 Nov 2026 09:00:00 +0000\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
	"--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" +
	"<html><head><style>p{}</style></head><body><p>Hi Ana,</p><p>Numbers &amp; charts attached.</p></body></html>\r\n" +
	"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=q3.pdf\r\n\r\nJVBERi0=\r\n" +
	"--b--\r\n"

func TestSummarize(t *testing.T) {
	s := Summarize(strings.NewReader(multipart))
	if s.Subject != "Q3 report" || s.FromName != "Priya Náir" || s.FromAddr != "priya@lumen.example" {
		t.Fatalf("%+v", s)
	}
	if s.MessageID != "abc@lumen.example" || s.InReplyTo != "root@northwind.example" || !s.HasAttachments || s.SentDate == 0 {
		t.Fatalf("%+v", s)
	}
	if s.Preview != "Hi Ana, Numbers & charts attached." {
		t.Fatalf("preview %q", s.Preview)
	}
	if !strings.Contains(s.To, "Ana <ana@northwind.example>") {
		t.Fatalf("to %q", s.To)
	}
	if got := preview("Thanks!\n> old quote\n-- \nsig"); got != "Thanks!" {
		t.Fatalf("preview %q", got)
	}
}

type fakeDNS map[string][]string

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[strings.TrimSuffix(name, ".")]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (fakeDNS) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{IsNotFound: true}
}
func (fakeDNS) LookupAddr(context.Context, string) ([]string, error) {
	return nil, &net.DNSError{IsNotFound: true}
}

func setup(t *testing.T, dns fakeDNS) (*Deliverer, store.User) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bl, _ := blob.Open(dir + "/blobs")
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw", DisplayName: "Northwind"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	u, err := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", "x", store.RoleUser, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &Deliverer{Store: st, Blobs: bl, Hub: hub.New(), Checker: &Checker{Hostname: "mx.test", DNS: dns},
		Hostname: "mx.test", TmpDir: dir, MaxSize: 1 << 20}, u
}

func TestDeliverDMARC(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dns := fakeDNS{
		"_dmarc.lumen.example":        {"v=DMARC1; p=reject"},
		"lumen.example":               {"v=spf1 ip4:192.0.2.1 -all"},
		"s1._domainkey.lumen.example": {"v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub)},
	}
	d, u := setup(t, dns)
	ctx := context.Background()
	events, cancel := d.Hub.Subscribe(u.ID)
	defer cancel()

	// Unsigned mail from a stranger's IP: DMARC p=reject refuses it.
	env := Envelope{RemoteIP: net.ParseIP("203.0.113.9"), Helo: "evil.example", MailFrom: "x@lumen.example"}
	_, err := d.Deliver(ctx, Inbound{Env: env, Rcpts: []store.User{u}, Proto: "ESMTP"}, strings.NewReader(multipart))
	var rej *RejectError
	if !errors.As(err, &rej) {
		t.Fatalf("want reject, got %v", err)
	}

	// DKIM-signed copy passes and lands in the inbox.
	var signed bytes.Buffer
	if err := dkim.Sign(&signed, strings.NewReader(multipart), &dkim.SignOptions{Domain: "lumen.example", Selector: "s1", Signer: priv}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Deliver(ctx, Inbound{Env: env, Rcpts: []store.User{u, u}, Proto: "ESMTP"}, &signed); err != nil {
		t.Fatal(err)
	}
	<-events
	inbox, _ := d.Store.MailboxByUse(ctx, u.ID, store.UseInbox)
	msgs, _ := d.Store.ListMessages(ctx, u.ID, inbox.ID, store.ListOptions{})
	if len(msgs) != 1 || msgs[0].Auth&store.AuthDMARCPass == 0 || msgs[0].Subject != "Q3 report" {
		t.Fatalf("%+v", msgs)
	}
	full, _ := d.Store.Message(ctx, u.ID, msgs[0].ID)
	r, err := d.Blobs.Open(u.TenantID, full.BlobHash)
	if err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	raw.ReadFrom(r)
	r.Close()
	if !strings.HasPrefix(raw.String(), "Return-Path: <x@lumen.example>\r\nAuthentication-Results: mx.test;") ||
		!strings.Contains(raw.String(), "dkim=pass") || !strings.Contains(raw.String(), "dmarc=pass") {
		t.Fatalf("headers:\n%.400s", raw.String())
	}

	// Without a DMARC record, an SPF fail goes to Junk.
	delete(dns, "_dmarc.lumen.example")
	if _, err := d.Deliver(ctx, Inbound{Env: env, Rcpts: []store.User{u}, Proto: "ESMTP"}, strings.NewReader(multipart)); err != nil {
		t.Fatal(err)
	}
	junk, _ := d.Store.MailboxByUse(ctx, u.ID, store.UseJunk)
	if m, _ := d.Store.ListMessages(ctx, u.ID, junk.ID, store.ListOptions{}); len(m) != 1 {
		t.Fatal("expected junk")
	}

	d.MaxSize = 10
	if _, err := d.Deliver(ctx, Inbound{Env: env, Rcpts: []store.User{u}}, strings.NewReader(multipart)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size: %v", err)
	}
}

func TestDetail(t *testing.T) {
	d, err := ReadDetail(strings.NewReader(multipart))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.HTML, "Numbers &amp; charts") || len(d.Parts) != 1 || d.Parts[0].Filename != "q3.pdf" || d.Parts[0].Path != "2" {
		t.Fatalf("%+v", d)
	}
	h, body, err := OpenPart(strings.NewReader(multipart), "2")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	b.ReadFrom(body)
	if ct, _, _ := h.ContentType(); ct != "application/pdf" || b.String() != "JVBERi0=" {
		t.Fatalf("%s %q", ct, b.String())
	}
}

func TestCompose(t *testing.T) {
	to, _ := ParseAddresses([]string{"Priya <priya@lumen.example>, bo@harbor.example"})
	from, _ := ParseAddresses([]string{"Ana Lopes <ana@northwind.example>"})
	c := Compose{From: from[0], To: to, Bcc: to[:1], Subject: "Plan für Q4", HTML: "<p>Hello <b>there</b></p>", MessageID: "x@mx.test",
		InReplyTo: "<root@x>", Attachments: []NewAttachment{{Filename: "a.txt", ContentType: "text/plain", Data: []byte("data")}}}
	var b bytes.Buffer
	if err := c.Write(&b); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "Bcc") {
		t.Fatal("bcc leaked")
	}
	s := Summarize(bytes.NewReader(b.Bytes()))
	if s.Subject != "Plan für Q4" || s.Preview != "Hello there" || !s.HasAttachments || s.InReplyTo != "root@x" || !strings.Contains(s.To, "bo@harbor.example") {
		t.Fatalf("%+v\n%s", s, b.String())
	}
}
