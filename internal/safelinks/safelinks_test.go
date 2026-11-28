// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package safelinks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestFeedsAndCheck(t *testing.T) {
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", 503)
			return
		}
		switch r.URL.Path {
		case "/urls":
			fmt.Fprint(w, "# URLhaus\nhttp://hacked.example/wp-content/x.exe\nhttps://Phish.Example:443/login/\n")
		case "/hosts":
			fmt.Fprint(w, "# hosts\n0.0.0.0 malware.example\nbad.example\n")
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	c := &Checker{Dir: dir, Feeds: []Feed{{Name: "Test URLs", URL: srv.URL + "/urls"}, {Name: "Test hosts", URL: srv.URL + "/hosts", Hosts: true}}}
	ctx := context.Background()
	c.Refresh(ctx)
	if u, h := c.Size(); u != 2 || h != 2 {
		t.Fatalf("loaded %d urls, %d hosts", u, h)
	}
	for in, want := range map[string]Level{
		"https://example.org/":                     Safe,
		"http://hacked.example/wp-content/x.exe":   Malicious,
		"http://HACKED.example/wp-content/x.exe#a": Malicious,
		"http://hacked.example/":                   Safe, // only the listed page
		"https://phish.example/login":              Malicious,
		"https://cdn.malware.example/a":            Malicious, // host feeds cover subdomains
		"https://bad.example":                      Malicious,
		"https://notbad.example":                   Safe,
		"http://192.0.2.1/x":                       Suspicious,
		"https://xn--pypal-4ve.com/":               Suspicious,
		"https://paypal.com@evil.example/":         Suspicious,
		"https://example.org:8443/":                Suspicious,
		"javascript:alert(1)":                      Malicious,
		"/relative":                                Malicious,
	} {
		if v := c.Check(in); v.Level != want {
			t.Errorf("%s: %v (%s), want %v", in, v.Level, v.Reason, want)
		}
	}

	// A restart loads the cached copy even when the feeds are down.
	down.Store(true)
	c2 := &Checker{Dir: dir, Feeds: c.Feeds}
	c2.load(ctx, true)
	c2.Refresh(ctx)
	if c2.Check("https://bad.example").Level != Malicious {
		t.Fatal("cache not used")
	}
}
