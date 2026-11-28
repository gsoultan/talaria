// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package webui serves the embedded webmail build.
//
// The Vite build output is copied into dist/ by `make web`. Files are served
// precompressed (brotli, then gzip) when the build produced .br/.gz siblings,
// hashed assets get immutable caching, and unknown paths fall back to
// index.html so client-side routes work.
package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// Handler returns an http.Handler serving the webmail.
// PageCSP is the webmail page's Content-Security-Policy. Only the app's own
// scripts run. Message bodies render in a sandboxed srcdoc frame, which
// inherits this policy and adds its own stricter one, so images may come from
// anywhere here and each message decides whether remote ones load. Inline
// styles are allowed for the UI library and for HTML mail.
const PageCSP = "default-src 'self'; script-src 'self'; worker-src 'self'; connect-src 'self'; " +
	"img-src 'self' data: blob: https: http:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; " +
	"frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'"

func Handler() http.Handler {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err)
	}
	return New(sub)
}

// New serves files from fsys. It is exported for tests.
func New(fsys fs.FS) http.Handler {
	return &handler{fsys: fsys}
}

type handler struct{ fsys fs.FS }

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if !h.exists(name) {
		if !h.exists("index.html") {
			http.Error(w, "webmail not built: run `make web`", http.StatusServiceUnavailable)
			return
		}
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
		name = "index.html" // SPA route
	}

	hdr := w.Header()
	switch {
	case strings.HasPrefix(name, "assets/"):
		hdr.Set("Cache-Control", "public, max-age=31536000, immutable")
	case name == "sw.js" || name == "index.html" || strings.HasSuffix(name, ".webmanifest"):
		hdr.Set("Cache-Control", "no-cache")
		if name == "index.html" {
			hdr.Set("Content-Security-Policy", PageCSP)
		}
	default:
		hdr.Set("Cache-Control", "public, max-age=3600")
	}
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		hdr.Set("Content-Type", ct)
	}
	hdr.Add("Vary", "Accept-Encoding")
	hdr.Set("X-Content-Type-Options", "nosniff")

	accept := r.Header.Get("Accept-Encoding")
	for _, enc := range []struct{ token, ext string }{{"br", ".br"}, {"gzip", ".gz"}} {
		if strings.Contains(accept, enc.token) && h.exists(name+enc.ext) {
			hdr.Set("Content-Encoding", enc.token)
			name += enc.ext
			break
		}
	}
	http.ServeFileFS(w, r, h.fsys, name)
}

func (h *handler) exists(name string) bool {
	st, err := fs.Stat(h.fsys, name)
	return err == nil && !st.IsDir()
}
