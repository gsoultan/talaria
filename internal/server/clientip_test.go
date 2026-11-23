// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPMiddleware(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, remote, header, value, want string
	}{
		{"untrusted peer ignores header", "203.0.113.9:1234", "X-Forwarded-For", "1.2.3.4", "203.0.113.9"},
		{"trusted peer, single hop", "127.0.0.1:1234", "X-Forwarded-For", "198.51.100.7", "198.51.100.7"},
		{"spoofed leftmost entry ignored", "127.0.0.1:1234", "X-Forwarded-For", "6.6.6.6, 198.51.100.7, 10.1.2.3", "198.51.100.7"},
		{"cloudflare header", "127.0.0.1:1234", "CF-Connecting-IP", "2001:db8::1", "2001:db8::1"},
		{"no header", "127.0.0.1:1234", "X-Real-IP", "", "127.0.0.1"},
	}
	for _, c := range cases {
		var got netip.Addr
		h := ClientIPMiddleware(trusted, c.header, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = ClientIP(r.Context())
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.remote
		if c.value != "" {
			req.Header.Set(c.header, c.value)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got.String() != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
