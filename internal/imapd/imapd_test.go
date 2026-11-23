// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package imapd

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

type env struct {
	st   *store.Store
	addr string
	u    store.User
}

func setup(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bl, _ := blob.Open(dir + "/blobs")
	ctx := context.Background()
	tn, _ := st.CreateTenant(ctx, store.Tenant{Name: "nw"})
	st.CreateDomain(ctx, tn.ID, "northwind.example")
	hash, _ := auth.HashPassword("secret-pass")
	u, err := st.CreateUser(ctx, tn.ID, "ana@northwind.example", "Ana", hash, store.RoleUser, 0)
	if err != nil {
		t.Fatal(err)
	}
	h := hub.New()
	d := &mail.Deliverer{Store: st, Blobs: bl, Hub: h, Hostname: "mx.test", TmpDir: dir, MaxSize: 1 << 20}
	srv := New(Config{UpstreamTLS: true, MaxSize: 1 << 20}, st, bl, h, d, slog.New(slog.DiscardHandler))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return env{st: st, addr: ln.Addr().String(), u: u}
}

func dial(t *testing.T, e env, opts *imapclient.Options) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(e.addr, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login("ana@northwind.example", "secret-pass").Wait(); err != nil {
		t.Fatal(err)
	}
	return c
}

func appendMsg(t *testing.T, c *imapclient.Client, mbox, body string, flags ...imap.Flag) {
	t.Helper()
	cmd := c.Append(mbox, int64(len(body)), &imap.AppendOptions{Flags: flags, Time: time.Unix(1700000000, 0)})
	cmd.Write([]byte(body))
	cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

const msg1 = "From: Bob <bob@example.com>\r\nTo: ana@northwind.example\r\nSubject: Quarterly report\r\nMessage-Id: <1@example.com>\r\nX-Tag: blue\r\n\r\nNumbers attached for the board meeting.\r\n.leading dot\r\n"
const msg2 = "From: Carol <carol@example.com>\r\nTo: ana@northwind.example\r\nSubject: Lunch\r\n\r\nPizza on Friday?\r\n"

func TestLoginFails(t *testing.T) {
	e := setup(t)
	c, err := imapclient.DialInsecure(e.addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("ana@northwind.example", "wrong").Wait(); err == nil {
		t.Fatal("bad password accepted")
	}
	if err := c.Login("nobody@northwind.example", "secret-pass").Wait(); err == nil {
		t.Fatal("unknown user accepted")
	}
}

func TestMailboxes(t *testing.T) {
	e := setup(t)
	c := dial(t, e, nil)
	list, err := c.List("", "*", &imap.ListOptions{ReturnSpecialUse: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range list {
		names = append(names, l.Mailbox)
	}
	if !strings.Contains(strings.Join(names, ","), "INBOX") || !strings.Contains(strings.Join(names, ","), "Sent") {
		t.Fatalf("list: %v", names)
	}
	if err := c.Create("Projects/2026", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Rename("Projects/2026", "Projects/Archive26", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status("Projects/Archive26", &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil || *st.NumMessages != 0 {
		t.Fatalf("status: %v %+v", err, st)
	}
	if err := c.Delete("Projects/Archive26").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Select("Nope", nil).Wait(); err == nil {
		t.Fatal("selected a missing mailbox")
	}
}

func TestFetchStoreSearchMove(t *testing.T) {
	e := setup(t)
	c := dial(t, e, nil)
	appendMsg(t, c, "INBOX", msg1)
	appendMsg(t, c, "INBOX", msg2, imap.FlagSeen)

	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil || sel.NumMessages != 2 {
		t.Fatalf("select: %v %+v", err, sel)
	}

	// Envelope, flags and a header-only section, without setting \Seen.
	hdr := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true, Flags: true, Envelope: true, RFC822Size: true, BodySection: []*imap.FetchItemBodySection{hdr}}).Collect()
	if err != nil || len(msgs) != 2 {
		t.Fatalf("fetch: %v %d", err, len(msgs))
	}
	if msgs[0].Envelope.Subject != "Quarterly report" || msgs[0].RFC822Size != int64(len(msg1)) {
		t.Fatalf("envelope: %+v size %d", msgs[0].Envelope, msgs[0].RFC822Size)
	}
	if len(msgs[0].Flags) != 0 || len(msgs[1].Flags) != 1 {
		t.Fatalf("flags: %v %v", msgs[0].Flags, msgs[1].Flags)
	}
	if !strings.Contains(string(msgs[0].FindBodySection(hdr)), "X-Tag: blue") {
		t.Fatal("header section")
	}

	// Full body marks the message seen.
	full := &imap.FetchItemBodySection{}
	msgs, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}, BodyStructure: &imap.FetchItemBodyStructure{}}).Collect()
	if err != nil || string(msgs[0].FindBodySection(full)) != msg1 {
		t.Fatalf("body: %v %q", err, msgs[0].FindBodySection(full))
	}
	msgs, _ = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if len(msgs[0].Flags) != 1 || msgs[0].Flags[0] != imap.FlagSeen {
		t.Fatalf("seen not set: %v", msgs[0].Flags)
	}

	// Store flags and a keyword.
	if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagFlagged, "$Work"}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}

	search := func(cr *imap.SearchCriteria) []uint32 {
		t.Helper()
		d, err := c.Search(cr, nil).Wait()
		if err != nil {
			t.Fatal(err)
		}
		return d.AllSeqNums()
	}
	if got := search(&imap.SearchCriteria{Flag: []imap.Flag{imap.FlagFlagged}}); len(got) != 1 || got[0] != 1 {
		t.Fatalf("flagged: %v", got)
	}
	if got := search(&imap.SearchCriteria{Flag: []imap.Flag{"$Work"}}); len(got) != 1 {
		t.Fatalf("keyword: %v", got)
	}
	if got := search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "lunch"}}}); len(got) != 1 || got[0] != 2 {
		t.Fatalf("subject: %v", got)
	}
	if got := search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "X-Tag", Value: "blue"}}}); len(got) != 1 || got[0] != 1 {
		t.Fatalf("x-tag: %v", got)
	}
	if got := search(&imap.SearchCriteria{Body: []string{"pizza"}}); len(got) != 1 || got[0] != 2 {
		t.Fatalf("body: %v", got)
	}
	if got := search(&imap.SearchCriteria{Not: []imap.SearchCriteria{{Flag: []imap.Flag{imap.FlagFlagged}}}}); len(got) != 1 || got[0] != 2 {
		t.Fatalf("not: %v", got)
	}

	// Copy, then move, with UIDPLUS data.
	cd, err := c.Copy(imap.SeqSetNum(2), "Archive").Wait()
	if err != nil || cd.DestUIDs.String() != "1" {
		t.Fatalf("copy: %v %+v", err, cd)
	}
	if _, err := c.Move(imap.SeqSetNum(1), "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	st, _ := c.Status("Archive", &imap.StatusOptions{NumMessages: true}).Wait()
	if *st.NumMessages != 2 {
		t.Fatalf("archive has %d", *st.NumMessages)
	}

	// Expunge the remaining INBOX message.
	if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Expunge().Collect(); err != nil {
		t.Fatal(err)
	}
	st, _ = c.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
	if *st.NumMessages != 0 {
		t.Fatalf("inbox has %d", *st.NumMessages)
	}
}

// A second session sees new mail while idling.
func TestIdle(t *testing.T) {
	e := setup(t)
	got := make(chan uint32, 4)
	c := dial(t, e, &imapclient.Options{UnilateralDataHandler: &imapclient.UnilateralDataHandler{
		Mailbox: func(d *imapclient.UnilateralDataMailbox) {
			if d.NumMessages != nil {
				got <- *d.NumMessages
			}
		},
	}})
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	idle, err := c.Idle()
	if err != nil {
		t.Fatal(err)
	}
	other := dial(t, e, nil)
	appendMsg(t, other, "INBOX", msg2)
	select {
	case n := <-got:
		if n != 1 {
			t.Fatalf("exists %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EXISTS during IDLE")
	}
	idle.Close()
	idle.Wait()
}
