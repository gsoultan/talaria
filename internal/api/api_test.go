// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

func TestLoginWatchDeliver(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	defer st.Close()
	bl, _ := blob.Open(dir + "/blobs")
	h := hub.New()
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	hash, _ := auth.HashPassword("correct horse")
	u, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", hash, store.RoleUser, 0)

	a := NewAuth(st)
	opts := connect.WithInterceptors(a)
	mux := http.NewServeMux()
	mux.Handle(talariav1connect.NewAuthServiceHandler(NewAuthServer(a), opts))
	mux.Handle(talariav1connect.NewMailServiceHandler(&MailServer{Store: st, Blobs: bl, Hub: h}, opts))
	mux.Handle(talariav1connect.NewAdminServiceHandler(&AdminServer{Store: st}, opts))
	srv := httptest.NewTLSServer(mux) // Secure cookies need https
	defer srv.Close()

	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	authc := talariav1connect.NewAuthServiceClient(client, srv.URL)
	mailc := talariav1connect.NewMailServiceClient(client, srv.URL)
	adminc := talariav1connect.NewAdminServiceClient(client, srv.URL)

	if _, err := mailc.ListMailboxes(ctx, connect.NewRequest(&talariav1.ListMailboxesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous: %v", err)
	}
	if _, err := authc.Login(ctx, connect.NewRequest(&talariav1.LoginRequest{Email: "ana@northwind.example", Password: "nope"})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad password: %v", err)
	}
	if _, err := authc.Login(ctx, connect.NewRequest(&talariav1.LoginRequest{Email: "ana@northwind.example", Password: "correct horse"})); err != nil {
		t.Fatal(err)
	}
	if _, err := adminc.ListUsers(ctx, connect.NewRequest(&talariav1.ListUsersRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("user reached admin: %v", err)
	}

	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := mailc.Watch(wctx, connect.NewRequest(&talariav1.WatchRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() { // initial empty event
		t.Fatal(stream.Err())
	}
	d := &mail.Deliverer{Store: st, Blobs: bl, Hub: h, Hostname: "mx.test", TmpDir: dir}
	if _, err := d.Deliver(ctx, mail.Inbound{Rcpts: []store.User{u}, Trusted: true},
		strings.NewReader("From: Bob <bob@x.example>\r\nSubject: live\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() || len(stream.Msg().MailboxIds) != 1 {
		t.Fatalf("watch: %v", stream.Err())
	}
	inbox := stream.Msg().MailboxIds[0]
	list, err := mailc.ListMessages(ctx, connect.NewRequest(&talariav1.ListMessagesRequest{MailboxId: inbox}))
	if err != nil || len(list.Msg.Messages) != 1 || list.Msg.Messages[0].Subject != "live" {
		t.Fatalf("list: %v %v", list, err)
	}
	id := list.Msg.Messages[0].Id
	if _, err := mailc.DeleteMessages(ctx, connect.NewRequest(&talariav1.DeleteMessagesRequest{Ids: []int64{id}})); err != nil {
		t.Fatal(err)
	}
	if _, err := mailc.DeleteMessages(ctx, connect.NewRequest(&talariav1.DeleteMessagesRequest{Ids: []int64{id}})); err != nil {
		t.Fatal(err)
	}
	if _, err := mailc.GetMessage(ctx, connect.NewRequest(&talariav1.GetMessageRequest{Id: id})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("purged: %v", err)
	}

	if _, err := authc.Logout(ctx, connect.NewRequest(&talariav1.LogoutRequest{})); err != nil {
		t.Fatal(err)
	}
	su, _ := url.Parse(srv.URL)
	if len(client.Jar.Cookies(su)) != 0 {
		t.Fatal("cookie not cleared")
	}
}
