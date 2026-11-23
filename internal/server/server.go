// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package server wires Talaria's listeners together and runs them.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/api"
	"github.com/gsoultan/talaria/internal/config"
	"github.com/gsoultan/talaria/internal/webui"
)

// Server owns all listeners. Later phases add SMTP, IMAP and the queue here.
type Server struct {
	cfg  config.Config
	log  *slog.Logger
	http *http.Server
}

func New(cfg config.Config, log *slog.Logger) (*Server, error) {
	trusted, err := config.ParsePrefixes(cfg.HTTP.TrustedProxies)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(talariav1connect.NewSystemServiceHandler(api.NewSystemServer()))
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

	return &Server{
		cfg: cfg,
		log: log,
		http: &http.Server{
			Addr:              cfg.HTTP.Listen,
			Handler:           ClientIPMiddleware(trusted, cfg.HTTP.ClientIPHeader, mux),
			Protocols:         &protocols,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
		},
	}, nil
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	s.log.Info("http listening", "addr", ln.Addr().String())
	errc := make(chan error, 1)
	go func() { errc <- s.http.Serve(ln) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.http.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
