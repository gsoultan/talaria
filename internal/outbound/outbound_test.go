// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

func selfSigned(t *testing.T) *tls.Config {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"}, DNSNames: []string{"relay.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// fakeRelay records what it receives and refuses "bad@" recipients.
type fakeRelay struct {
	mu     sync.Mutex
	got    []string
	authed string
}

type relaySession struct{ r *fakeRelay }

func (f *fakeRelay) NewSession(*smtp.Conn) (smtp.Session, error) { return &relaySession{f}, nil }
func (s *relaySession) AuthMechanisms() []string                 { return []string{sasl.Plain} }
func (s *relaySession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, user, pass string) error {
		if user != "apikey" || pass != "secret" {
			return errors.New("bad auth")
		}
		s.r.mu.Lock()
		s.r.authed = user
		s.r.mu.Unlock()
		return nil
	}), nil
}
func (s *relaySession) Mail(string, *smtp.MailOptions) error { return nil }
func (s *relaySession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if strings.HasPrefix(to, "bad@") {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "User unknown"}
	}
	return nil
}
func (s *relaySession) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	s.r.mu.Lock()
	s.r.got = append(s.r.got, string(b))
	s.r.mu.Unlock()
	return nil
}
func (s *relaySession) Reset()        {}
func (s *relaySession) Logout() error { return nil }

func TestSubmitSignRelayBounce(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	defer st.Close()
	bl, _ := blob.Open(dir + "/blobs")
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	ana, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", "x", store.RoleUser, 0)
	lena, _ := st.CreateUser(ctx, tn.ID, "lena@northwind.example", "Lena", "x", store.RoleUser, 0)

	fr := &fakeRelay{}
	rs := smtp.NewServer(fr)
	rs.Domain = "relay.test"
	rs.TLSConfig = selfSigned(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go rs.Serve(ln)
	defer rs.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	d := &mail.Deliverer{Store: st, Blobs: bl, Hub: hub.New(), Hostname: "mx.test", TmpDir: dir}
	keys := &Keys{Store: st}
	q := &Queue{Store: st, Blobs: bl, Deliver: d, Hostname: "mx.test", Log: slog.Default(),
		Transport: &Relay{Host: "127.0.0.1", Port: port, Username: "apikey", Password: "secret", Hello: "mx.test", Timeout: 5 * time.Second,
			TLSConfig: &tls.Config{InsecureSkipVerify: true}}}
	sub := &Submitter{Store: st, Blobs: bl, Deliver: d, Keys: keys, Queue: q, Hostname: "mx.test", TmpDir: dir}

	msg := "From: Ana <ana@northwind.example>\r\nTo: priya@lumen.example, lena@northwind.example\r\nSubject: Hi\r\n\r\nHello\r\n"
	if _, err := sub.Submit(ctx, Submission{User: ana, MailFrom: "lena@northwind.example", Rcpts: []string{"x@y.example"}}, strings.NewReader(msg)); !errors.Is(err, ErrSenderNotAllowed) {
		t.Fatalf("spoofed envelope: %v", err)
	}
	res, err := sub.Submit(ctx, Submission{User: ana, MailFrom: "ana@northwind.example", SaveSent: true,
		Rcpts: []string{"priya@lumen.example", "lena@northwind.example", "bad@lumen.example", "secret@lumen.example"}}, strings.NewReader(msg))
	if err != nil || res.Local != 1 || res.Queued != 3 {
		t.Fatalf("%+v %v", res, err)
	}

	qctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { q.Run(qctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		items, _ := st.ListQueue(ctx, 0, -1, 10)
		finished := 0
		for _, it := range items {
			if it.Status >= store.QueueSent {
				finished++
			}
		}
		if finished == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue stuck: %+v", items)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	fr.mu.Lock()
	got := append([]string(nil), fr.got...)
	fr.mu.Unlock()
	if len(got) != 2 || fr.authed != "apikey" {
		t.Fatalf("relay got %d messages, auth %q", len(got), fr.authed)
	}
	if strings.Contains(got[0], "Bcc") || !strings.HasPrefix(got[0], "DKIM-Signature:") || !strings.Contains(got[0], "Message-Id:") {
		t.Fatalf("relayed:\n%s", got[0])
	}
	sel, txt, err := keys.DNSRecord(ctx, "northwind.example")
	if err != nil {
		t.Fatal(err)
	}
	verifs, err := dkim.VerifyWithOptions(strings.NewReader(got[0]), &dkim.VerifyOptions{LookupTXT: func(name string) ([]string, error) {
		if name == sel+"._domainkey.northwind.example" {
			return []string{txt}, nil
		}
		return nil, errors.New("nx")
	}})
	if err != nil || len(verifs) != 1 || verifs[0].Err != nil {
		t.Fatalf("dkim: %v %+v", err, verifs)
	}

	// Lena got it locally; Ana has a Sent copy (with Bcc) and one bounce.
	inbox := func(u store.User, use string) []store.Message {
		mb, _ := st.MailboxByUse(ctx, u.ID, use)
		m, _ := st.ListMessages(ctx, u.ID, mb.ID, store.ListOptions{})
		return m
	}
	if m := inbox(lena, store.UseInbox); len(m) != 1 || m[0].Subject != "Hi" {
		t.Fatalf("lena: %+v", m)
	}
	if m := inbox(ana, store.UseSent); len(m) != 1 || m[0].Flags&store.FlagSeen == 0 {
		t.Fatalf("sent: %+v", m)
	}
	b := inbox(ana, store.UseInbox)
	if len(b) != 1 || !strings.Contains(b[0].Subject, "bad@lumen.example") {
		t.Fatalf("bounce: %+v", b)
	}
	full, _ := st.Message(ctx, ana.ID, b[0].ID)
	r, _ := bl.Open(ana.TenantID, full.BlobHash)
	var raw bytes.Buffer
	raw.ReadFrom(r)
	r.Close()
	if !strings.Contains(raw.String(), "User unknown") {
		t.Fatalf("bounce body:\n%s", raw.String())
	}
}
