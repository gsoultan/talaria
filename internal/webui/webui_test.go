// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestHandler(t *testing.T) {
	h := New(fstest.MapFS{
		"index.html":       {Data: []byte("<html>")},
		"assets/app.js":    {Data: []byte("plain")},
		"assets/app.js.br": {Data: []byte("brotli")},
		"assets/app.js.gz": {Data: []byte("gzip")},
	})
	cases := []struct {
		path, accept, wantBody, wantEnc, wantCache string
		wantCode                                   int
	}{
		{"/assets/app.js", "gzip, br", "brotli", "br", "public, max-age=31536000, immutable", 200},
		{"/assets/app.js", "gzip", "gzip", "gzip", "public, max-age=31536000, immutable", 200},
		{"/assets/app.js", "", "plain", "", "public, max-age=31536000, immutable", 200},
		{"/inbox/123", "", "<html>", "", "no-cache", 200},
		{"/missing.png", "", "", "", "", 404},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		if c.accept != "" {
			req.Header.Set("Accept-Encoding", c.accept)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.wantCode {
			t.Errorf("%s: code %d, want %d", c.path, rec.Code, c.wantCode)
			continue
		}
		if c.wantCode != 200 {
			continue
		}
		if got := rec.Body.String(); got != c.wantBody {
			t.Errorf("%s (%s): body %q, want %q", c.path, c.accept, got, c.wantBody)
		}
		if got := rec.Header().Get("Content-Encoding"); got != c.wantEnc {
			t.Errorf("%s (%s): encoding %q, want %q", c.path, c.accept, got, c.wantEnc)
		}
		if got := rec.Header().Get("Cache-Control"); got != c.wantCache {
			t.Errorf("%s: cache %q, want %q", c.path, got, c.wantCache)
		}
	}
}
