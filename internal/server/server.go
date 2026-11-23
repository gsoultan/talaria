// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package server wires Talaria's listeners together and runs them.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/emersion/go-smtp"
	"golang.org/x/net/netutil"

	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/api"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/clientip"
	"github.com/gsoultan/talaria/internal/config"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/ingest"
	"github.com/gsoultan/talaria/internal/listener"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/smtpd"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/tlsutil"
	"github.com/gsoultan/talaria/internal/webui"
)

// Server owns the store and all listeners.
type Server struct {
	cfg     config.Config
	log     *slog.Logger
	Store   *store.Store
	Blobs   *blob.Store
	Hub     *hub.Hub
	Deliver *mail.Deliverer
	tls     *tls.Config
	http    *http.Server
	smtp    *smtp.Server
}

// OpenStores opens the database and blob store under the data directory.
func OpenStores(dataDir string) (*store.Store, *blob.Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "tmp"), 0o700); err != nil {
		return nil, nil, err
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return nil, nil, err
	}
	bl, err := blob.Open(filepath.Join(dataDir, "blobs"))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, bl, nil
}

// New builds a server from config.
func New(cfg config.Config, log *slog.Logger) (*Server, error) {
	trusted, err := config.ParsePrefixes(cfg.HTTP.TrustedProxies)
	if err != nil {
		return nil, err
	}
	st, bl, err := OpenStores(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, Store: st, Blobs: bl, Hub: hub.New()}
	switch cfg.TLS.Mode {
	case "files":
		r, err := tlsutil.Load(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			st.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		s.tls = r.Config()
	case "acme":
		st.Close()
		return nil, errors.New(`tls.mode "acme" is not available yet; use "files" with certbot, or "off" behind a gateway`)
	}
	s.Deliver = &mail.Deliverer{
		Store: st, Blobs: bl, Hub: s.Hub, Hostname: cfg.Hostname, Log: log,
		Checker: &mail.Checker{Hostname: cfg.Hostname},
		TmpDir:  filepath.Join(cfg.DataDir, "tmp"), MaxSize: int64(cfg.SMTP.MaxMessageSize),
	}

	authn := api.NewAuth(st)
	opts := connect.WithInterceptors(authn)
	mailSrv := &api.MailServer{Store: st, Blobs: bl, Hub: s.Hub}

	mux := http.NewServeMux()
	mux.Handle(talariav1connect.NewSystemServiceHandler(api.NewSystemServer()))
	mux.Handle(talariav1connect.NewAuthServiceHandler(api.NewAuthServer(authn), opts))
	mux.Handle(talariav1connect.NewMailServiceHandler(mailSrv, opts))
	mux.Handle(talariav1connect.NewAdminServiceHandler(&api.AdminServer{Store: st}, opts))
	(&api.Downloads{Auth: authn, Mail: mailSrv}).Register(mux)
	if cfg.Ingest.Enabled {
		tok, err := os.ReadFile(cfg.Ingest.TokenFile)
		if err != nil {
			st.Close()
			return nil, fmt.Errorf("ingest token: %w", err)
		}
		token := strings.TrimSpace(string(tok))
		if len(token) < 32 {
			st.Close()
			return nil, errors.New("ingest token must be at least 32 characters")
		}
		mux.Handle(ingest.Path, &ingest.Handler{Token: token, Store: st, Deliver: s.Deliver, Log: log})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte("ok\n"))
	})
	mux.Handle("/", webui.Handler())

	// HTTP/1.1 plus cleartext HTTP/2, so gRPC clients and proxies that speak
	// h2c (cloudflared with http2Origin, Envoy, Traefik) work without TLS here.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	s.http = &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           clientip.Middleware(trusted, cfg.HTTP.ClientIPHeader, mux),
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if cfg.SMTP.Listen != "" {
		s.smtp = smtpd.NewInbound(smtpd.Config{
			Hostname: cfg.Hostname, MaxMessageSize: int64(cfg.SMTP.MaxMessageSize), TLS: s.tls, UpstreamTLS: cfg.SMTP.UpstreamTLS,
		}, st, s.Deliver, log)
	}
	return s, nil
}

// Close releases the stores. Run calls it on exit.
func (s *Server) Close() error { return s.Store.Close() }

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	defer s.Close()
	errc := make(chan error, 4)
	var wg sync.WaitGroup

	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.log.Info("http listening", "addr", ln.Addr().String())
	go func() { errc <- s.http.Serve(ln) }()

	if s.smtp != nil {
		trusted, _ := config.ParsePrefixes(s.cfg.SMTP.TrustedProxies)
		sl, err := net.Listen("tcp", s.cfg.SMTP.Listen)
		if err != nil {
			return fmt.Errorf("smtp: %w", err)
		}
		if s.cfg.SMTP.MaxConnections > 0 {
			sl = netutil.LimitListener(sl, s.cfg.SMTP.MaxConnections)
		}
		s.log.Info("smtp listening", "addr", sl.Addr().String(), "starttls", s.tls != nil)
		go func() { errc <- s.smtp.Serve(listener.Wrap(sl, trusted)) }()
	}

	jctx, stopJanitor := context.WithCancel(ctx)
	wg.Add(1)
	go func() { defer wg.Done(); s.janitor(jctx) }()

	select {
	case err := <-errc:
		stopJanitor()
		wg.Wait()
		return err
	case <-ctx.Done():
	}
	stopJanitor()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if s.smtp != nil {
		s.smtp.Shutdown(shutdownCtx)
	}
	err = s.http.Shutdown(shutdownCtx)
	wg.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// janitor does periodic housekeeping: expired sessions, unreferenced blobs
// and old expunge records.
func (s *Server) janitor(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		s.sweep(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) sweep(ctx context.Context) {
	if n, err := s.Store.PurgeExpiredSessions(ctx); err != nil {
		s.log.Warn("purge sessions", "err", err)
	} else if n > 0 {
		s.log.Debug("purged sessions", "n", n)
	}
	for {
		dead, err := s.Store.DeadBlobs(ctx, 500)
		if err != nil || len(dead) == 0 {
			break
		}
		for _, b := range dead {
			// The row is deleted only if still unreferenced, under a lock that
			// deliveries hold while they reference blobs.
			s.Blobs.Collect(b.TenantID, b.Hash, func() (bool, error) { return s.Store.DeleteBlob(ctx, b.ID) })
		}
		if len(dead) < 500 || ctx.Err() != nil {
			break
		}
	}
	if err := s.Store.PruneExpunged(ctx, 100_000); err != nil {
		s.log.Warn("prune expunged", "err", err)
	}
}
