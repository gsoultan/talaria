// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package server wires Talaria's listeners together and runs them.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-smtp"
	"golang.org/x/net/netutil"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/api"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/clientip"
	"github.com/gsoultan/talaria/internal/config"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/imapd"
	"github.com/gsoultan/talaria/internal/ingest"
	"github.com/gsoultan/talaria/internal/listener"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/pop3"
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
	Keys    *outbound.Keys
	Queue   *outbound.Queue
	Submit  *outbound.Submitter
	tls     *tls.Config
	http    *http.Server
	smtp    *smtp.Server
	sub     *smtp.Server
	imap    *imapserver.Server
	pop     *pop3.Server
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

	transport, route, err := newTransport(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	s.Keys = &outbound.Keys{Store: st}
	s.Queue = &outbound.Queue{Store: st, Blobs: bl, Transport: transport, Deliver: s.Deliver, Hostname: cfg.Hostname, Log: log}
	s.Submit = &outbound.Submitter{Store: st, Blobs: bl, Deliver: s.Deliver, Keys: s.Keys, Queue: s.Queue, Hostname: cfg.Hostname,
		TmpDir: s.Deliver.TmpDir, MaxSize: int64(cfg.SMTP.MaxMessageSize), Log: log}

	authn := api.NewAuth(st)
	maxRead := int(cfg.SMTP.MaxMessageSize)*2 + 1<<20
	opts := connect.WithHandlerOptions(connect.WithInterceptors(authn), connect.WithReadMaxBytes(maxRead))
	mailSrv := &api.MailServer{Store: st, Blobs: bl, Hub: s.Hub, Submit: s.Submit, Deliver: s.Deliver, Hostname: cfg.Hostname,
		MaxSize: int64(cfg.SMTP.MaxMessageSize), Endpoints: mailEndpoints(cfg)}
	adminSrv := &api.AdminServer{Store: st, Keys: s.Keys, Hostname: cfg.Hostname, Route: route, Wake: s.Queue.Wake}
	if cfg.Outbound.Mode == "relay" {
		adminSrv.RelayHost = cfg.Outbound.Relay.Host
	}

	mux := http.NewServeMux()
	mux.Handle(talariav1connect.NewSystemServiceHandler(api.NewSystemServer()))
	mux.Handle(talariav1connect.NewAuthServiceHandler(api.NewAuthServer(authn), opts))
	mux.Handle(talariav1connect.NewMailServiceHandler(mailSrv, opts))
	mux.Handle(talariav1connect.NewAdminServiceHandler(adminSrv, opts))
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
	if cfg.SMTP.Submission != "" || cfg.SMTP.SubmissionTLS != "" {
		s.sub = smtpd.NewSubmission(smtpd.Config{
			Hostname: cfg.Hostname, MaxMessageSize: int64(cfg.SMTP.MaxMessageSize), TLS: s.tls, UpstreamTLS: cfg.SMTP.UpstreamTLS,
		}, st, s.Submit, log)
	}
	if cfg.IMAP.Listen != "" || cfg.IMAP.ListenTLS != "" {
		s.imap = imapd.New(imapd.Config{TLS: s.tls, UpstreamTLS: cfg.IMAP.UpstreamTLS, MaxSize: int64(cfg.SMTP.MaxMessageSize)},
			st, s.Blobs, s.Hub, s.Deliver, log)
	}
	if cfg.POP3.Listen != "" || cfg.POP3.ListenTLS != "" {
		s.pop = pop3.New(pop3.Config{Hostname: cfg.Hostname, TLS: s.tls, UpstreamTLS: cfg.POP3.UpstreamTLS}, st, s.Blobs, s.Hub, log)
	}
	return s, nil
}

func newTransport(cfg config.Config) (outbound.Transport, string, error) {
	timeout := cfg.Outbound.Relay.Timeout.D()
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if cfg.Outbound.Mode == "direct" {
		return &outbound.Direct{Hello: cfg.Hostname, Timeout: timeout}, "direct to MX on port 25", nil
	}
	r := cfg.Outbound.Relay
	if r.Host == "" {
		return noRelay{}, "not configured: set outbound.relay.host", nil
	}
	var password string
	if r.PasswordFile != "" {
		b, err := os.ReadFile(r.PasswordFile)
		if err != nil {
			return nil, "", fmt.Errorf("relay password: %w", err)
		}
		password = strings.TrimSpace(string(b))
	}
	return &outbound.Relay{Host: r.Host, Port: r.Port, Username: r.Username, Password: password, Hello: cfg.Hostname, Timeout: timeout},
		fmt.Sprintf("relay %s:%d", r.Host, r.Port), nil
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

	if s.sub != nil {
		trusted, _ := config.ParsePrefixes(s.cfg.SMTP.TrustedProxies)
		if err := s.serveSubmission(s.cfg.SMTP.Submission, false, trusted, errc); err != nil {
			return err
		}
		if err := s.serveSubmission(s.cfg.SMTP.SubmissionTLS, true, trusted, errc); err != nil {
			return err
		}
	}

	if s.imap != nil {
		trusted, _ := config.ParsePrefixes(s.cfg.IMAP.TrustedProxies)
		for _, l := range []struct {
			addr     string
			implicit bool
		}{{s.cfg.IMAP.Listen, false}, {s.cfg.IMAP.ListenTLS, true}} {
			ln, err := s.mailListener("imap", l.addr, l.implicit, s.cfg.IMAP.ProxyProtocol, trusted)
			if err != nil {
				return err
			}
			if ln != nil {
				go func() { errc <- s.imap.Serve(ln) }()
			}
		}
	}
	if s.pop != nil {
		trusted, _ := config.ParsePrefixes(s.cfg.POP3.TrustedProxies)
		for _, l := range []struct {
			addr     string
			implicit bool
		}{{s.cfg.POP3.Listen, false}, {s.cfg.POP3.ListenTLS, true}} {
			ln, err := s.mailListener("pop3", l.addr, l.implicit, s.cfg.POP3.ProxyProtocol, trusted)
			if err != nil {
				return err
			}
			if ln != nil {
				go func() { errc <- s.pop.Serve(ln) }()
			}
		}
	}

	jctx, stopJanitor := context.WithCancel(ctx)
	wg.Add(2)
	go func() { defer wg.Done(); s.janitor(jctx) }()
	go func() { defer wg.Done(); s.Queue.Run(jctx) }()

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
	if s.sub != nil {
		s.sub.Shutdown(shutdownCtx)
	}
	if s.imap != nil {
		s.imap.Close()
	}
	if s.pop != nil {
		s.pop.Close()
	}
	err = s.http.Shutdown(shutdownCtx)
	wg.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// serveSubmission starts one submission listener. implicit marks port 465:
// TLS from the first byte, unless a gateway already terminated it.
func (s *Server) serveSubmission(addr string, implicit bool, trusted []netip.Prefix, errc chan<- error) error {
	if addr == "" {
		return nil
	}
	if s.tls == nil && !s.cfg.SMTP.UpstreamTLS {
		s.log.Warn("submission disabled: it needs tls.mode files, or upstream_tls behind a TLS-terminating gateway", "addr", addr)
		return nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("submission: %w", err)
	}
	if s.cfg.SMTP.MaxConnections > 0 {
		l = netutil.LimitListener(l, s.cfg.SMTP.MaxConnections)
	}
	l = listener.Wrap(l, trusted)
	if implicit && !s.cfg.SMTP.UpstreamTLS {
		l = tls.NewListener(l, s.tls)
	}
	s.log.Info("submission listening", "addr", addr, "implicit_tls", implicit)
	go func() { errc <- s.sub.Serve(l) }()
	return nil
}

// mailEndpoints lists the mail-app listeners that will start, for the
// webmail's setup screen. Mail apps need TLS, so listeners without it are
// left out, as mailListener and serveSubmission skip them too.
func mailEndpoints(cfg config.Config) []*talariav1.MailEndpoint {
	secure := func(pp config.ProxyProtocol) bool { return cfg.TLS.Mode != "off" || pp.UpstreamTLS }
	var out []*talariav1.MailEndpoint
	add := func(proto, addr, sec string, ok bool) {
		if addr == "" || !ok {
			return
		}
		_, p, err := net.SplitHostPort(addr)
		port, perr := strconv.Atoi(p)
		if err != nil || perr != nil {
			return
		}
		out = append(out, &talariav1.MailEndpoint{Protocol: proto, Port: int32(port), Security: sec})
	}
	add("IMAP", cfg.IMAP.ListenTLS, "TLS", secure(cfg.IMAP.ProxyProtocol))
	add("IMAP", cfg.IMAP.Listen, "STARTTLS", secure(cfg.IMAP.ProxyProtocol))
	add("POP3", cfg.POP3.ListenTLS, "TLS", secure(cfg.POP3.ProxyProtocol))
	add("POP3", cfg.POP3.Listen, "STARTTLS", secure(cfg.POP3.ProxyProtocol))
	add("SMTP", cfg.SMTP.SubmissionTLS, "TLS", secure(cfg.SMTP.ProxyProtocol))
	add("SMTP", cfg.SMTP.Submission, "STARTTLS", secure(cfg.SMTP.ProxyProtocol))
	return out
}

// mailListener opens an IMAP or POP3 listener. Mail apps send passwords, so
// a listener only starts with certificates, or behind a gateway that
// terminates TLS (upstream_tls). implicit marks 993/995.
func (s *Server) mailListener(name, addr string, implicit bool, pp config.ProxyProtocol, trusted []netip.Prefix) (net.Listener, error) {
	if addr == "" {
		return nil, nil
	}
	if s.tls == nil && !pp.UpstreamTLS {
		s.log.Warn(name+" disabled: it needs tls.mode files, or upstream_tls behind a TLS-terminating gateway", "addr", addr)
		return nil, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if s.cfg.SMTP.MaxConnections > 0 {
		l = netutil.LimitListener(l, s.cfg.SMTP.MaxConnections)
	}
	l = listener.Wrap(l, trusted)
	if implicit && !pp.UpstreamTLS {
		l = tls.NewListener(l, s.tls)
	}
	s.log.Info(name+" listening", "addr", addr, "implicit_tls", implicit)
	return l, nil
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
	if err := s.Store.PruneQueue(ctx, 30*86400); err != nil {
		s.log.Warn("prune queue", "err", err)
	}
	if err := s.Store.PruneExpunged(ctx, 100_000); err != nil {
		s.log.Warn("prune expunged", "err", err)
	}
}

// noRelay keeps mail queued until a relay is configured.
type noRelay struct{}

func (noRelay) Send(context.Context, string, string, io.Reader) (string, error) {
	return "", errors.New("no outbound relay configured (outbound.relay.host)")
}
