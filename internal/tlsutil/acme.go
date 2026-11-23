// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package tlsutil

import (
	"crypto/tls"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// ACME gets and renews Let's Encrypt certificates for hosts, keeping them in
// cacheDir. Domains are proven over HTTPS (TLS-ALPN-01) or plain HTTP on
// port 80 (HTTP-01, through HTTPHandler).
type ACME struct {
	m        *autocert.Manager
	fallback string
}

// NewACME returns a manager limited to hosts. fallback names the
// certificate used when a client sends no server name, which mail apps
// connecting by IP address and some older clients do.
func NewACME(cacheDir, email, fallback string, hosts []string) *ACME {
	return &ACME{
		m: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(hosts...),
			Email:      email,
		},
		fallback: strings.ToLower(fallback),
	}
}

// GetCertificate implements tls.Config.GetCertificate.
func (a *ACME) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		h := *hello
		h.ServerName = a.fallback
		hello = &h
	}
	return a.m.GetCertificate(hello)
}

// Config returns a server TLS config that also answers TLS-ALPN-01
// challenges.
func (a *ACME) Config() *tls.Config {
	return &tls.Config{
		GetCertificate: a.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
	}
}

// HTTPHandler answers HTTP-01 challenges and passes everything else to h.
func (a *ACME) HTTPHandler(h http.Handler) http.Handler { return a.m.HTTPHandler(h) }
