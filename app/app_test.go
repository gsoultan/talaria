// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/store/pgtest"
	"github.com/gsoultan/talaria/internal/uploads"
)

type env struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	st     *store.Store
	bl     *blob.Store
	hub    *hub.Hub
	user   store.User
	dir    string
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), pgtest.URL(t), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bl, _ := blob.Open(dir + "/blobs")
	h := hub.New()
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw", DisplayName: "Northwind"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	hash, _ := auth.HashPassword("correct horse")
	u, _ := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", hash, store.RoleUser, 0)
	ups, _ := uploads.New(dir+"/uploads", 1<<20)
	d := &mail.Deliverer{Store: st, Blobs: bl, Hub: h, Hostname: "mx.test", TmpDir: dir}
	r := Build(Deps{Store: st, Blobs: bl, Hub: h, Deliver: d, Uploads: ups, Hostname: "mx.test", MaxSize: 1 << 20})
	srv := httptest.NewTLSServer(r) // Secure cookies need https
	t.Cleanup(srv.Close)
	c := srv.Client()
	c.Jar, _ = cookiejar.New(nil)
	return &env{t: t, srv: srv, client: c, st: st, bl: bl, hub: h, user: u, dir: dir}
}

// call sends a JSON request and decodes the JSON answer into out (when not
// nil). It returns the status and, for errors, the error code.
func (e *env) call(method, path string, body, out any) (int, string) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	res, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 400 {
		var eb struct {
			Error struct{ Code string } `json:"error"`
		}
		json.Unmarshal(raw, &eb)
		return res.StatusCode, eb.Error.Code
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: %v\n%s", method, path, err, raw)
		}
	}
	return res.StatusCode, ""
}

func (e *env) login() {
	e.t.Helper()
	var s domain.Session
	if st, code := e.call("POST", "/api/v1/session", domain.Login{Email: "ana@northwind.example", Password: "correct horse"}, &s); st != 201 {
		e.t.Fatalf("login: %d %s", st, code)
	}
	if s.User.Email != "ana@northwind.example" || s.User.TenantName != "Northwind" || s.User.Role != domain.RoleUser {
		e.t.Fatalf("session: %+v", s)
	}
}

func TestLoginWatchDeliverDelete(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	if st, code := e.call("GET", "/api/v1/mailboxes", nil, nil); st != 401 || code != "unauthorized" {
		t.Fatalf("anonymous: %d %s", st, code)
	}
	if st, _ := e.call("GET", "/api/v1/info", nil, nil); st != 200 {
		t.Fatalf("public info: %d", st)
	}
	if st, code := e.call("POST", "/api/v1/session", domain.Login{Email: "ana@northwind.example", Password: "nope"}, nil); st != 401 {
		t.Fatalf("bad password: %d %s", st, code)
	}
	if st, code := e.call("POST", "/api/v1/session", domain.Login{Email: "ana@northwind.example"}, nil); st != 400 || code != "invalid" {
		t.Fatalf("missing password: %d %s", st, code)
	}
	e.login()
	if st, code := e.call("GET", "/api/v1/admin/users", nil, nil); st != 403 {
		t.Fatalf("user reached admin: %d %s", st, code)
	}

	// Watch: server-sent events, first an empty change.
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(wctx, "GET", e.srv.URL+"/api/v1/watch", nil)
	req.Header.Set("Accept", "text/event-stream")
	res, err := e.client.Do(req)
	if err != nil || res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("watch: %v %v", res, err)
	}
	defer res.Body.Close()
	events := bufio.NewScanner(res.Body)
	next := func() domain.Change {
		for events.Scan() {
			if data, ok := strings.CutPrefix(events.Text(), "data: "); ok {
				var c domain.Change
				json.Unmarshal([]byte(data), &c)
				return c
			}
		}
		t.Fatalf("stream ended: %v", events.Err())
		return domain.Change{}
	}
	if c := next(); c.MailboxIDs == nil || len(c.MailboxIDs) != 0 {
		t.Fatalf("first event: %+v", c)
	}
	d := &mail.Deliverer{Store: e.st, Blobs: e.bl, Hub: e.hub, Hostname: "mx.test", TmpDir: e.dir}
	if _, err := d.Deliver(ctx, mail.Inbound{Rcpts: []store.User{e.user}, Trusted: true},
		strings.NewReader("From: Bob <bob@x.example>\r\nSubject: live\r\n\r\nhi\r\n")); err != nil {
		t.Fatal(err)
	}
	c := next()
	if len(c.MailboxIDs) != 1 {
		t.Fatalf("change: %+v", c)
	}
	var page domain.MessagePage
	e.call("GET", fmt.Sprintf("/api/v1/mailboxes/%d/messages?limit=10", c.MailboxIDs[0]), nil, &page)
	if len(page.Messages) != 1 || page.Messages[0].Subject != "live" || page.Messages[0].Seen {
		t.Fatalf("page: %+v", page)
	}
	id := page.Messages[0].ID
	var m domain.Message
	if e.call("GET", fmt.Sprintf("/api/v1/messages/%d", id), nil, &m); m.Message.TextBody != "hi\r\n" && m.Message.TextBody != "hi\n" {
		t.Fatalf("body %q", m.Message.TextBody)
	}
	if m.Message.Attachments == nil || m.Message.Keywords == nil {
		t.Fatal("lists must be [] not null")
	}
	if st, code := e.call("POST", "/api/v1/messages/flags", domain.UpdateFlags{IDs: []int64{id}, Add: []domain.Flag{"bogus"}}, nil); st != 400 {
		t.Fatalf("bad flag: %d %s", st, code)
	}
	if st, _ := e.call("POST", "/api/v1/messages/flags", domain.UpdateFlags{IDs: []int64{id}, Add: []domain.Flag{domain.FlagSeen}}, nil); st != 201 {
		t.Fatalf("flags: %d", st)
	}
	// Delete twice: to Trash, then for good.
	for range 2 {
		if st, code := e.call("POST", "/api/v1/messages/delete", domain.DeleteMessages{IDs: []int64{id}}, nil); st != 201 {
			t.Fatalf("delete: %d %s", st, code)
		}
	}
	if st, _ := e.call("GET", fmt.Sprintf("/api/v1/messages/%d", id), nil, nil); st != 404 {
		t.Fatalf("purged: %d", st)
	}

	if st, _ := e.call("DELETE", "/api/v1/session", nil, nil); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	su, _ := url.Parse(e.srv.URL)
	if len(e.client.Jar.Cookies(su)) != 0 {
		t.Fatal("cookie not cleared")
	}
	if st, _ := e.call("GET", "/api/v1/me", nil, nil); st != 401 {
		t.Fatalf("after logout: %d", st)
	}
}

func TestUploadDraftDownload(t *testing.T) {
	e := setup(t)
	e.login()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/uploads", strings.NewReader("quarterly numbers"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Filename", url.PathEscape("Q3 report.txt"))
	res, err := e.client.Do(req)
	if err != nil || res.StatusCode != 201 {
		t.Fatalf("upload: %v %v", res, err)
	}
	var up domain.Upload
	json.NewDecoder(res.Body).Decode(&up)
	res.Body.Close()
	if up.Filename != "Q3 report.txt" || up.Size != 17 {
		t.Fatalf("upload: %+v", up)
	}

	var saved domain.DraftSaved
	if st, code := e.call("POST", "/api/v1/drafts", domain.SaveDraft{Message: domain.Compose{To: []string{"bob@x.example"}, Subject: "Q3",
		TextBody: "attached", Attachments: []domain.NewAttachment{{UploadID: up.ID}}}}, &saved); st != 201 {
		t.Fatalf("draft: %d %s", st, code)
	}
	var m domain.Message
	e.call("GET", fmt.Sprintf("/api/v1/messages/%d", saved.DraftID), nil, &m)
	if len(m.Message.Attachments) != 1 || m.Message.Attachments[0].Filename != "Q3 report.txt" {
		t.Fatalf("draft attachments: %+v", m.Message.Attachments)
	}
	res, err = e.client.Get(fmt.Sprintf("%s/api/v1/messages/%d/parts/%s", e.srv.URL, saved.DraftID, m.Message.Attachments[0].Part))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("download: %v %v", res, err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "quarterly numbers" || res.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("download: %q %v", body, res.Header)
	}

	// Another user's upload id is not found, and stale ids are refused.
	if st, code := e.call("POST", "/api/v1/drafts", domain.SaveDraft{Message: domain.Compose{
		Attachments: []domain.NewAttachment{{UploadID: "nope"}}}}, nil); st != 400 {
		t.Fatalf("unknown upload: %d %s", st, code)
	}
}

func TestCrossSiteRequestsRefused(t *testing.T) {
	e := setup(t)
	e.login()
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/mailboxes", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Origin", "https://evil.example")
	res, err := e.client.Do(req)
	if err != nil || res.StatusCode != 403 {
		t.Fatalf("cross-site: %v %v", res, err)
	}
	res.Body.Close()
}

func TestOpenAPI(t *testing.T) {
	b, err := OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	json.Unmarshal(b, &doc)
	if doc.Paths["/api/v1/mailboxes/{mailboxId}/messages"]["get"].OperationID != "mail.ListMessages" {
		t.Fatalf("paths: %v", doc.Paths)
	}
	n := 0
	for _, ops := range doc.Paths {
		n += len(ops)
	}
	if n != 42 { // the generated routes; uploads and downloads are raw HTTP
		t.Fatalf("%d operations, want 42", n)
	}
}
