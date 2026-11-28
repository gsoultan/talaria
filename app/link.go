// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package app

import (
	"html/template"
	"log/slog"
	"net/http"

	"github.com/gsoultan/kakarot/transport/httpx"

	"github.com/gsoultan/talaria/internal/safelinks"
	"github.com/gsoultan/talaria/usecase"
)

// links is the safe-links redirect. The webmail points every link in a
// message at GET /api/v1/link?u=<url>; it is checked when clicked, so a
// link that turned bad after the mail arrived is still caught. Only
// signed-in users are redirected, so it is no use as an open redirect.
type links struct {
	check *safelinks.Checker // nil: links open without a check
	log   *slog.Logger
	// Clicked records a click, for the audit log.
	clicked func(r *http.Request, userID int64, url string, v safelinks.Verdict)
}

func (l *links) register(r *httpx.Router) {
	r.HandleFunc("GET /api/v1/link", l.open)
}

var linkPage = template.Must(template.New("link").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>{{.Title}} · Talaria</title>
<style>
body{margin:0;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:#f3f4f6;color:#1a1d21;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;max-width:560px;margin:16px;padding:28px 32px;border-radius:14px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h1{font-size:22px;margin:0 0 8px}.bad h1{color:#c92a2a}.warn h1{color:#b35900}
code{display:block;background:#f1f3f5;padding:10px 12px;border-radius:8px;word-break:break-all;font-size:14px;margin:14px 0}
a.btn{display:inline-block;padding:8px 14px;border-radius:8px;border:1px solid #ced4da;color:#1a1d21;text-decoration:none;font-size:14px}
p.small{color:#666;font-size:14px}
@media (prefers-color-scheme:dark){body{background:#1a1b1e;color:#e9ecef}main{background:#25262b}code{background:#2c2e33}a.btn{color:#e9ecef;border-color:#495057}}
</style></head>
<body><main class="{{.Class}}"><h1>{{.Title}}</h1><p>{{.Reason}}</p>{{if .URL}}<code>{{.URL}}</code>{{end}}
{{if .Continue}}<p><a class="btn" href="{{.Continue}}" rel="noopener noreferrer">Open it anyway</a></p>{{end}}
<p class="small">{{.Note}}</p></main></body></html>`))

type linkView struct {
	Title, Class, Reason, URL, Note string
	Continue                        template.URL
}

func (l *links) page(w http.ResponseWriter, status int, v linkView) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	linkPage.Execute(w, v)
}

func (l *links) open(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("u")
	u := usecase.CallerFrom(r.Context()).User
	if u.ID == 0 {
		l.page(w, http.StatusUnauthorized, linkView{Title: "Sign in to open this link", Class: "warn",
			Reason: "Links in mail open through Talaria's link check, which needs you to be signed in to your webmail.", URL: target})
		return
	}
	v := safelinks.Verdict{}
	if l.check != nil {
		v = l.check.Check(target)
	} else if c := (&safelinks.Checker{}).Check(target); c.Level == safelinks.Malicious {
		v = c // not a web link at all
	}
	if l.clicked != nil {
		l.clicked(r, u.ID, target, v)
	}
	switch v.Level {
	case safelinks.Malicious:
		l.log.Warn("blocked link", "user", u.ID, "url", target, "reason", v.Reason)
		l.page(w, http.StatusOK, linkView{Title: "This link was blocked", Class: "bad", Reason: v.Reason, URL: target,
			Note: "It may try to steal your password or install malware. If you think it is safe, ask your administrator."})
	case safelinks.Suspicious:
		l.page(w, http.StatusOK, linkView{Title: "Check this link before you open it", Class: "warn", Reason: v.Reason, URL: target,
			Continue: template.URL(target), Note: "Open it only if you trust the sender and expected this link."})
	default:
		h := w.Header()
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		http.Redirect(w, r, target, http.StatusSeeOther)
	}
}
