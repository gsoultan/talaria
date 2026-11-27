// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gsoultan/kakarot"
	"github.com/gsoultan/kakarot/transport/httpx"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/audit"
	"github.com/gsoultan/talaria/internal/safelinks"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/usecase"
)

// adminRequest is what the audit middleware needs from an admin HTTP
// request, which endpoint middleware does not see.
type adminRequest struct {
	method, path string
	query        map[string]string
	body         map[string]any
}

type adminRequestKey struct{}

// captureAdmin keeps a copy of admin API requests for the audit log.
func captureAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
			next.ServeHTTP(w, r)
			return
		}
		ar := &adminRequest{method: r.Method, path: r.URL.Path, query: map[string]string{}}
		for k, v := range r.URL.Query() {
			if len(v) > 0 && len(ar.query) < 20 {
				ar.query[k] = v[0]
			}
		}
		if r.Body != nil && r.Method != http.MethodGet {
			head, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
			json.Unmarshal(head, &ar.body)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminRequestKey{}, ar)))
	})
}

// secretKey reports whether a field holds something that must not be
// logged.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"password", "secret", "token", "privatekey", "private_key"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			if secretKey(k) {
				out[k] = "(hidden)"
			} else {
				out[k] = redact(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redact(x)
		}
		return out
	case string:
		if len(t) > 500 {
			return t[:500] + "…"
		}
	}
	return v
}

// audited reports whether an admin operation goes in the log: every
// change, and reading a held message.
func audited(method string) bool {
	switch {
	case method == "GetHeldMail":
		return true
	case strings.HasPrefix(method, "List"), strings.HasPrefix(method, "Get"), method == "TestDLP":
		return false
	}
	return true
}

// auditAdmin records admin operations, including refused ones.
func auditAdmin(rec *audit.Recorder) kakarot.Middleware {
	return func(ctx context.Context, op kakarot.Op, next kakarot.Next) error {
		err := next(ctx)
		if rec == nil || !audited(op.Method) {
			return err
		}
		u := usecase.CallerFrom(ctx).User
		e := store.AuditEntry{TenantID: u.TenantID, ActorID: u.ID, Actor: u.Address(), IP: ipOf(ctx), Action: "admin." + op.Method}
		if u.ID == 0 {
			e.Actor = "(signed out)"
		}
		detail := map[string]any{}
		if ar, ok := ctx.Value(adminRequestKey{}).(*adminRequest); ok {
			e.Target = ar.method + " " + ar.path
			tid := ar.query["tenantId"]
			if tid == "" {
				tid = ar.query["tenant"]
			}
			if n, ok := ar.body["tenantId"].(float64); ok && n > 0 {
				tid = strconv.FormatInt(int64(n), 10)
			}
			// A platform admin's action belongs to the tenant it acts on.
			// Anyone else's stays in their own tenant, so an attempt on
			// another tenant shows where their admins look.
			if n, _ := strconv.ParseInt(tid, 10, 64); n > 0 && u.Role == store.RolePlatformAdmin {
				e.TenantID = n
			}
			if len(ar.body) > 0 {
				detail["request"] = redact(ar.body)
			}
			if len(ar.query) > 0 {
				detail["query"] = ar.query
			}
		}
		if err != nil {
			e.Outcome = kakarot.CodeOf(err).String()
			detail["error"] = kakarot.AsError(err).Message
		}
		e.Detail = audit.Detail(detail)
		rec.Record(ctx, e)
		return err
	}
}

// linkClicked records clicks on links the checker blocked or warned about.
func linkClicked(rec *audit.Recorder) func(r *http.Request, userID int64, url string, v safelinks.Verdict) {
	if rec == nil {
		return nil
	}
	return func(r *http.Request, _ int64, url string, v safelinks.Verdict) {
		if v.Level == safelinks.Safe {
			return
		}
		u := usecase.CallerFrom(r.Context()).User
		outcome := "warned"
		if v.Level == safelinks.Malicious {
			outcome = "blocked"
		}
		if len(url) > 1000 {
			url = url[:1000]
		}
		rec.Record(r.Context(), store.AuditEntry{TenantID: u.TenantID, ActorID: u.ID, Actor: u.Address(), IP: ipOf(r.Context()),
			Action: audit.PolicyLink, Target: url, Outcome: outcome, Detail: audit.Detail(map[string]any{"reason": v.Reason})})
	}
}

// auditExport serves the audit log as CSV.
type auditExport struct{ admin *usecase.Admin }

func (a *auditExport) register(r *httpx.Router) {
	r.HandleFunc("GET /api/v1/admin/audit.csv", a.csv)
}

func (a *auditExport) csv(w http.ResponseWriter, r *http.Request) {
	if _, ok := signedIn(w, r); !ok {
		return
	}
	q := r.URL.Query()
	num := func(k string) int64 { n, _ := strconv.ParseInt(q.Get(k), 10, 64); return n }
	in := domain.ListAudit{TenantScope: domain.TenantScope{TenantID: num("tenantId")}, Action: q.Get("action"), Query: q.Get("q"),
		Since: num("since"), Until: num("until")}
	var buf bytes.Buffer
	if err := a.admin.ExportAudit(r.Context(), in, &buf); err != nil {
		httpx.WriteError(r.Context(), w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="audit-`+time.Now().UTC().Format("2006-01-02")+`.csv"`)
	h.Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}
