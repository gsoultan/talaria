// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package app wires the webmail API: usecases, the generated kakarot
// endpoints and HTTP routes, the session cookie and file transfers. It is
// the only place that knows every layer.
package app

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/gsoultan/kakarot"
	"github.com/gsoultan/kakarot/auth"
	"github.com/gsoultan/kakarot/middleware"
	"github.com/gsoultan/kakarot/transport/httpx"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/endpoint"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/clientip"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/safelinks"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/uploads"
	"github.com/gsoultan/talaria/transport"
	"github.com/gsoultan/talaria/usecase"
)

// APIInfo names the API in its OpenAPI document.
var APIInfo = httpx.Info{Title: "Talaria webmail API", Version: "1"}

func init() {
	httpx.RegisterStatus(domain.CodeLimit, http.StatusUnprocessableEntity)
}

// Deps is what the API needs from the server.
type Deps struct {
	Store     *store.Store
	Blobs     *blob.Store
	Hub       *hub.Hub
	Submit    *outbound.Submitter
	Deliver   *mail.Deliverer
	Keys      *outbound.Keys
	Uploads   *uploads.Store
	Hostname  string
	MaxSize   int64
	Endpoints []domain.MailEndpoint
	Route     string // where outbound mail goes, for the queue view
	RelayHost string
	Wake      func() // nudges the outbound queue
	// SafeLinks checks links when they are clicked; nil opens them as is.
	SafeLinks *safelinks.Checker
	// Who may release held mail, and how long it is kept.
	UserReleaseMalware bool
	QuarantineDays     int
	Logger             *slog.Logger
}

func ipOf(ctx context.Context) string { return clientip.From(ctx).String() }

// Build returns the API router. Mount it at /api/; the client-IP middleware
// must run before it.
func Build(d Deps) *httpx.Router {
	log := d.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	qp := usecase.QuarantinePolicy{UserReleaseMalware: d.UserReleaseMalware, KeepDays: d.QuarantineDays}
	authUC := usecase.NewAuth(d.Store, cookies{}, ipOf)
	mailUC := &usecase.Mail{Store: d.Store, Blobs: d.Blobs, Hub: d.Hub, Submit: d.Submit, Deliver: d.Deliver, Uploads: d.Uploads,
		IP: ipOf, Hostname: d.Hostname, MaxSize: d.MaxSize, Endpoints: d.Endpoints, Quarantine: qp}
	adminUC := &usecase.Admin{Store: d.Store, Blobs: d.Blobs, Deliver: d.Deliver, Quarantine: qp, Keys: d.Keys, Hostname: d.Hostname, Route: d.Route, RelayHost: d.RelayHost, Wake: d.Wake}

	// Shared endpoint middleware. Mail has no timeout because Watch is a
	// long-lived stream; its calls are bounded by the HTTP server instead.
	signedIn := auth.Require[usecase.Caller](nil)
	public := middleware.Default(log, 30*time.Second)
	mailMW := kakarot.Chain(middleware.Recover(log), middleware.Logging(log), signedIn)

	r := httpx.NewRouter()
	r.Use(sameOrigin, sessions(authUC))
	transport.RegisterSystemHTTP(r, endpoint.MakeSystemEndpoints(usecase.System{}), public)
	transport.RegisterSessionHTTP(r, endpoint.MakeSessionEndpoints(authUC), public)
	transport.RegisterAccountHTTP(r, endpoint.MakeAccountEndpoints(authUC), public, signedIn)
	transport.RegisterMailHTTP(r, endpoint.MakeMailEndpoints(mailUC), mailMW)
	transport.RegisterAdminHTTP(r, endpoint.MakeAdminEndpoints(adminUC), public, signedIn)
	(&files{store: d.Store, blobs: d.Blobs, uploads: d.Uploads}).register(r)
	(&links{check: d.SafeLinks, log: log}).register(r)
	r.ServeOpenAPI("GET /api/v1/openapi.json", APIInfo)
	return r
}

// OpenAPI returns the API's OpenAPI 3.1 document, for generating the web
// client's types.
func OpenAPI() ([]byte, error) {
	return json.MarshalIndent(Build(Deps{}).OpenAPI(APIInfo), "", "  ")
}

// sameOrigin refuses state-changing requests that a browser sent from
// another site. The session cookie is SameSite=Strict already; this also
// covers browsers and proxies that get that wrong.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					httpx.WriteError(r.Context(), w, kakarot.E(kakarot.CodeForbidden, "cross-site request refused", nil))
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
