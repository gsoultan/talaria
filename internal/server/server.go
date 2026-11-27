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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-smtp"
	"golang.org/x/net/netutil"

	"github.com/gsoultan/talaria/app"
	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/clientip"
	"github.com/gsoultan/talaria/internal/config"
	"github.com/gsoultan/talaria/internal/filter"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/imapd"
	"github.com/gsoultan/talaria/internal/ingest"
	"github.com/gsoultan/talaria/internal/listener"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/malware"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/pop3"
	"github.com/gsoultan/talaria/internal/smtpd"
	"github.com/gsoultan/talaria/internal/spam"
	"github.com/gsoultan/talaria/internal/store"
	"github.com/gsoultan/talaria/internal/tlsutil"
	"github.com/gsoultan/talaria/internal/uploads"
	"github.com/gsoultan/talaria/internal/webui"
)

// Server owns the store and all listeners.
type Server struct {
	cfg     config.Config
	log     *slog.Logger
	Store   *store.Store
	Blobs   *blob.Store
	Hub     *hub.Hub
	Filter  *filter.Filter // inbound connection checks
	learner *spam.Learner
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
	// Instances for implicit-TLS ports behind a TLS-terminating gateway.
	// Every connection they get is secure (see listener.Implicit), so they
	// allow password logins without seeing a TLS handshake themselves.
	subUp  *smtp.Server
	imapUp *imapserver.Server
	https  *http.Server
	acme   *tlsutil.ACME
}

// OpenStores connects to the database and opens the blob store under the
// data directory.
func OpenStores(cfg config.Config) (*store.Store, *blob.Store, error) {
	dataDir := cfg.DataDir
	if err := os.MkdirAll(filepath.Join(dataDir, "tmp"), 0o700); err != nil {
		return nil, nil, err
	}
	st, err := store.Open(context.Background(), cfg.Database.URL, store.Options{MaxConns: cfg.Database.MaxConns})
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
	st, bl, err := OpenStores(cfg)
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
		hosts := cfg.TLS.Hosts
		if len(hosts) == 0 {
			hosts = []string{cfg.Hostname}
		}
		s.acme = tlsutil.NewACME(filepath.Join(cfg.DataDir, "acme"), cfg.TLS.Email, cfg.Hostname, hosts)
		s.tls = s.acme.Config()
	}
	s.Deliver = &mail.Deliverer{
		Store: st, Blobs: bl, Hub: s.Hub, Hostname: cfg.Hostname, Log: log,
		Checker: &mail.Checker{Hostname: cfg.Hostname},
		TmpDir:  filepath.Join(cfg.DataDir, "tmp"), MaxSize: int64(cfg.SMTP.MaxMessageSize),
	}
	if cfg.Spam.Enabled {
		sc := spam.Config{JunkScore: cfg.Spam.JunkScore, RejectScore: cfg.Spam.RejectScore}
		if cfg.Spam.RspamdURL != "" {
			sc.Rspamd = &spam.Rspamd{URL: cfg.Spam.RspamdURL}
			if f := cfg.Spam.RspamdPasswordFile; f != "" {
				b, err := os.ReadFile(f)
				if err != nil {
					st.Close()
					return nil, fmt.Errorf("spam.rspamd_password_file: %w", err)
				}
				sc.Rspamd.Password = strings.TrimSpace(string(b))
			}
		}
		s.Deliver.Spam = spam.New(sc, st, log)
	}
	if m := cfg.Malware; m.Enabled {
		mc := malware.Config{BlockedExtensions: m.BlockedExtensions, BlockMacros: m.BlockMacros,
			BlockEncryptedArchives: m.BlockEncryptedArchives, Rules: malware.Builtin()}
		if len(m.BlockedExtensions) == 0 {
			mc.BlockedExtensions = nil
		}
		if m.RulesDir != "" {
			rules, errs := malware.LoadDir(m.RulesDir)
			for _, err := range errs {
				log.Warn("yara rules skipped", "err", err)
			}
			mc.Rules = append(mc.Rules, rules...)
		}
		if m.ClamAV != "" {
			mc.ClamAV = &malware.ClamAV{Address: m.ClamAV}
		}
		s.Deliver.Malware = malware.New(mc, log)
	}
	// Training runs even with scoring off, so the filters are ready when
	// it is turned on.
	s.learner = &spam.Learner{Store: st, Log: log, Text: func(ctx context.Context, tenantID int64, hash []byte) (string, string, string, error) {
		rc, err := bl.Open(tenantID, hash)
		if err != nil {
			return "", "", "", err
		}
		defer rc.Close()
		sum := mail.Summarize(rc)
		return sum.Subject, sum.FromAddr, sum.Text, nil
	}}

	transport, route, err := newTransport(cfg)
	if err != nil {
		st.Close()
		return nil, err
	}
	s.Keys = &outbound.Keys{Store: st}
	s.Queue = &outbound.Queue{Store: st, Blobs: bl, Transport: transport, Deliver: s.Deliver, Hostname: cfg.Hostname, Log: log}
	s.Submit = &outbound.Submitter{Store: st, Blobs: bl, Deliver: s.Deliver, Keys: s.Keys, Queue: s.Queue, Hostname: cfg.Hostname,
		TmpDir: s.Deliver.TmpDir, MaxSize: int64(cfg.SMTP.MaxMessageSize), Log: log}

	ups, err := uploads.New(filepath.Join(cfg.DataDir, "tmp", "uploads"), int64(cfg.SMTP.MaxMessageSize))
	if err != nil {
		st.Close()
		return nil, err
	}
	deps := app.Deps{Store: st, Blobs: bl, Hub: s.Hub, Submit: s.Submit, Deliver: s.Deliver, Keys: s.Keys, Uploads: ups,
		Hostname: cfg.Hostname, MaxSize: int64(cfg.SMTP.MaxMessageSize), Endpoints: mailEndpoints(cfg),
		Route: route, Wake: s.Queue.Wake, Logger: log}
	if cfg.Outbound.Mode == "relay" {
		deps.RelayHost = cfg.Outbound.Relay.Host
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", app.Build(deps))
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
	handler := securityHeaders(clientip.Middleware(trusted, cfg.HTTP.ClientIPHeader, mux))
	plainHandler := handler
	if s.acme != nil {
		plainHandler = s.acme.HTTPHandler(handler)
	}
	s.http = &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           plainHandler,
		Protocols:         &protocols,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if cfg.HTTP.ListenTLS != "" && s.tls != nil {
		tc := s.tls.Clone()
		if len(tc.NextProtos) == 0 {
			tc.NextProtos = []string{"h2", "http/1.1"}
		}
		s.https = &http.Server{
			Addr:              cfg.HTTP.ListenTLS,
			Handler:           handler,
			TLSConfig:         tc,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
	}
	smtpCfg := smtpd.Config{Hostname: cfg.Hostname, MaxMessageSize: int64(cfg.SMTP.MaxMessageSize), TLS: s.tls}
	if cfg.SMTP.Listen != "" {
		in := smtpCfg
		s.Filter = filter.New(filter.Config{
			Hostname: cfg.Hostname, DNSBL: cfg.Filter.DNSBL,
			Greylist: cfg.Filter.Greylist, GreylistDelay: cfg.Filter.GreylistDelay.D(),
			RequireRDNS: cfg.Filter.RequireRDNS, MaxPerIPHour: cfg.Filter.MaxPerIPHour,
		}, st, nil, log)
		in.Filter = s.Filter
		s.smtp = smtpd.NewInbound(in, st, s.Deliver, log)
	}
	if cfg.SMTP.Submission != "" || cfg.SMTP.SubmissionTLS != "" {
		s.sub = smtpd.NewSubmission(smtpCfg, st, s.Submit, log)
		if cfg.SMTP.UpstreamTLS && cfg.SMTP.SubmissionTLS != "" {
			up := smtpCfg
			up.UpstreamTLS = true
			s.subUp = smtpd.NewSubmission(up, st, s.Submit, log)
		}
	}
	if cfg.IMAP.Listen != "" || cfg.IMAP.ListenTLS != "" {
		imapCfg := imapd.Config{TLS: s.tls, MaxSize: int64(cfg.SMTP.MaxMessageSize)}
		s.imap = imapd.New(imapCfg, st, s.Blobs, s.Hub, s.Deliver, log)
		if cfg.IMAP.UpstreamTLS && cfg.IMAP.ListenTLS != "" {
			imapCfg.UpstreamTLS = true
			s.imapUp = imapd.New(imapCfg, st, s.Blobs, s.Hub, s.Deliver, log)
		}
	}
	if cfg.POP3.Listen != "" || cfg.POP3.ListenTLS != "" {
		s.pop = pop3.New(pop3.Config{Hostname: cfg.Hostname, TLS: s.tls}, st, s.Blobs, s.Hub, log)
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
	errc := make(chan error, 16)
	var wg sync.WaitGroup

	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.log.Info("http listening", "addr", ln.Addr().String())
	go func() { errc <- s.http.Serve(ln) }()
	if s.https != nil {
		hl, err := net.Listen("tcp", s.https.Addr)
		if err != nil {
			return fmt.Errorf("https: %w", err)
		}
		s.log.Info("https listening", "addr", hl.Addr().String(), "tls", s.cfg.TLS.Mode)
		go func() { errc <- s.https.Serve(tls.NewListener(hl, s.https.TLSConfig)) }()
	}

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
		go func() { errc <- s.smtp.Serve(listener.PerIP(listener.Wrap(sl, trusted), perIPLimit)) }()
	}

	type port struct {
		name     string
		addr     string
		implicit bool
		pp       config.ProxyProtocol
		serve    func(net.Listener) error
	}
	var ports []port
	if s.sub != nil {
		sub465 := s.sub.Serve
		if s.subUp != nil {
			sub465 = s.subUp.Serve
		}
		ports = append(ports, port{"submission", s.cfg.SMTP.Submission, false, s.cfg.SMTP.ProxyProtocol, s.sub.Serve},
			port{"submission", s.cfg.SMTP.SubmissionTLS, true, s.cfg.SMTP.ProxyProtocol, sub465})
	}
	if s.imap != nil {
		imap993 := s.imap.Serve
		if s.imapUp != nil {
			imap993 = s.imapUp.Serve
		}
		ports = append(ports, port{"imap", s.cfg.IMAP.Listen, false, s.cfg.IMAP.ProxyProtocol, s.imap.Serve},
			port{"imap", s.cfg.IMAP.ListenTLS, true, s.cfg.IMAP.ProxyProtocol, imap993})
	}
	if s.pop != nil {
		ports = append(ports, port{"pop3", s.cfg.POP3.Listen, false, s.cfg.POP3.ProxyProtocol, s.pop.Serve},
			port{"pop3", s.cfg.POP3.ListenTLS, true, s.cfg.POP3.ProxyProtocol, s.pop.Serve})
	}
	for _, p := range ports {
		ln, err := s.mailListener(p.name, p.addr, p.implicit, p.pp)
		if err != nil {
			return err
		}
		if ln != nil {
			go func() { errc <- p.serve(ln) }()
		}
	}

	jctx, stopJanitor := context.WithCancel(ctx)
	wg.Add(3)
	go func() { defer wg.Done(); s.janitor(jctx) }()
	go func() { defer wg.Done(); s.learner.Run(jctx, 30*time.Second) }()
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
	for _, sub := range []*smtp.Server{s.sub, s.subUp} {
		if sub != nil {
			sub.Shutdown(shutdownCtx)
		}
	}
	for _, im := range []*imapserver.Server{s.imap, s.imapUp} {
		if im != nil {
			im.Close()
		}
	}
	if s.pop != nil {
		s.pop.Close()
	}
	if s.https != nil {
		s.https.Shutdown(shutdownCtx)
	}
	err = s.http.Shutdown(shutdownCtx)
	wg.Wait()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// mailEndpoints lists the mail-app listeners that will start, for the
// webmail's setup screen. Mail apps need TLS, so listeners without it are
// left out, as mailListener and serveSubmission skip them too.
func mailEndpoints(cfg config.Config) []domain.MailEndpoint {
	certs := cfg.TLS.Mode != "off"
	secure := func(pp config.ProxyProtocol) bool { return certs || pp.UpstreamTLS }
	var out []domain.MailEndpoint
	add := func(proto, addr, sec string, ok bool) {
		if addr == "" || !ok {
			return
		}
		_, p, err := net.SplitHostPort(addr)
		port, perr := strconv.Atoi(p)
		if err != nil || perr != nil {
			return
		}
		out = append(out, domain.MailEndpoint{Protocol: proto, Port: port, Security: sec})
	}
	add("IMAP", cfg.IMAP.ListenTLS, "TLS", secure(cfg.IMAP.ProxyProtocol))
	add("IMAP", cfg.IMAP.Listen, "STARTTLS", certs)
	add("POP3", cfg.POP3.ListenTLS, "TLS", secure(cfg.POP3.ProxyProtocol))
	add("POP3", cfg.POP3.Listen, "STARTTLS", certs)
	add("SMTP", cfg.SMTP.SubmissionTLS, "TLS", secure(cfg.SMTP.ProxyProtocol))
	add("SMTP", cfg.SMTP.Submission, "STARTTLS", certs)
	return out
}

// perIPLimit caps open connections from one client address on each mail
// port; mail apps open a few each, so this leaves room for an office NAT.
const perIPLimit = 32

// mailListener opens a submission, IMAP or POP3 listener. Mail apps send
// passwords, so a STARTTLS port only starts with certificates, and an
// implicit-TLS port (465/993/995) with certificates or behind a gateway that
// terminates TLS (upstream_tls).
func (s *Server) mailListener(name, addr string, implicit bool, pp config.ProxyProtocol) (net.Listener, error) {
	if addr == "" {
		return nil, nil
	}
	if s.tls == nil && (!implicit || !pp.UpstreamTLS) {
		s.log.Warn(name+" port disabled: it needs certificates (tls.mode), or upstream_tls on an implicit-TLS port behind a gateway", "addr", addr)
		return nil, nil
	}
	trusted, err := config.ParsePrefixes(pp.TrustedProxies)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if s.cfg.SMTP.MaxConnections > 0 {
		l = netutil.LimitListener(l, s.cfg.SMTP.MaxConnections)
	}
	l = listener.PerIP(listener.Wrap(l, trusted), perIPLimit)
	if implicit {
		l = listener.Implicit(l, s.tls, pp.UpstreamTLS)
	}
	s.log.Info(name+" listening", "addr", addr, "implicit_tls", implicit, "upstream_tls", implicit && pp.UpstreamTLS)
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
	if s.Filter != nil {
		if err := s.Filter.Prune(ctx); err != nil {
			s.log.Warn("prune greylist", "err", err)
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
