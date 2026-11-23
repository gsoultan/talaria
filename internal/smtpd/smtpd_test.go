// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package smtpd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"

	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

func TestInbound(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bl, _ := blob.Open(dir + "/blobs")
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw", DisplayName: "Northwind"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	u, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", "x", store.RoleUser, 0)

	d := &mail.Deliverer{Store: st, Blobs: bl, Hostname: "mx.test", TmpDir: dir, MaxSize: 1 << 20}
	srv := NewInbound(Config{Hostname: "mx.test", MaxMessageSize: 1 << 20}, st, d, slog.Default())
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	defer srv.Close()

	c, err := smtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("sender.example"); err != nil {
		t.Fatal(err)
	}
	if err := c.Mail("bob@sender.example", nil); err != nil {
		t.Fatal(err)
	}
	var se *smtp.SMTPError
	if err := c.Rcpt("nobody@northwind.example", nil); !errors.As(err, &se) || se.Code != 550 {
		t.Fatalf("unknown rcpt: %v", err)
	}
	if err := c.Rcpt("Ana+x@northwind.example", nil); err != nil {
		t.Fatal(err)
	}
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("From: Bob <bob@sender.example>\r\nSubject: hello\r\n\r\nHi Ana\r\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	c.Quit()

	inbox, _ := st.MailboxByUse(ctx, u.ID, store.UseInbox)
	msgs, _ := st.ListMessages(ctx, u.ID, inbox.ID, store.ListOptions{})
	if len(msgs) != 1 || msgs[0].Subject != "hello" || !strings.HasPrefix(msgs[0].Preview, "Hi Ana") {
		t.Fatalf("%+v", msgs)
	}
}
