// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package tlsutil loads certificates for SMTP and IMAP and reloads them when
// the files change (certbot, acme.sh or a gateway renewing them).
package tlsutil

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// Reloader serves a certificate pair and re-reads it at most once a minute
// when its modification time changes.
type Reloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	mtime   time.Time
	checked time.Time
}

// Load reads the pair once and returns a reloader.
func Load(certFile, keyFile string) (*Reloader, error) {
	r := &Reloader{certFile: certFile, keyFile: keyFile}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reloader) reload() error {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.mtime = &c, st.ModTime()
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) > time.Minute {
		r.checked = time.Now()
		if st, err := os.Stat(r.certFile); err == nil && !st.ModTime().Equal(r.mtime) {
			r.reload() // keep serving the old pair if the new one is broken
		}
	}
	return r.cert, nil
}

// Config returns a server TLS config with modern defaults.
func (r *Reloader) Config() *tls.Config {
	return &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12}
}
