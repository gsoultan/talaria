// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"net/smtp"
	"net/textproto"
)

// Transport hands one message to the next hop.
type Transport interface {
	Send(ctx context.Context, from, to string, body io.Reader) (reply string, err error)
}

type requireTLSKey struct{}

// WithRequireTLS marks a send as needing a verified encrypted connection.
func WithRequireTLS(ctx context.Context) context.Context {
	return context.WithValue(ctx, requireTLSKey{}, true)
}

func requireTLS(ctx context.Context) bool { v, _ := ctx.Value(requireTLSKey{}).(bool); return v }

// PermanentError is a failure that retrying will not fix (5xx, null MX).
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// classify turns SMTP 5xx replies into permanent errors.
func classify(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return &PermanentError{err}
	}
	return err
}

// Relay sends everything through a smarthost on 587 (STARTTLS), 465
// (implicit TLS), 2525 or 25.
type Relay struct {
	Host     string
	Port     int
	Username string
	Password string
	Hello    string
	Timeout  time.Duration
	// TLSConfig overrides certificate checks (tests only).
	TLSConfig *tls.Config
}

func (r *Relay) tlsConfig() *tls.Config {
	if r.TLSConfig != nil {
		return r.TLSConfig
	}
	return &tls.Config{ServerName: r.Host, MinVersion: tls.VersionTLS12}
}

// Send delivers one message to the relay.
func (r *Relay) Send(ctx context.Context, from, to string, body io.Reader) (string, error) {
	addr := net.JoinHostPort(r.Host, strconv.Itoa(r.Port))
	d := net.Dialer{Timeout: r.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	if r.Port == 465 {
		conn = tls.Client(conn, r.tlsConfig())
	}
	setDeadline(conn, r.Timeout)
	c, err := smtp.NewClient(conn, r.Host)
	if err != nil {
		conn.Close()
		return "", err
	}
	defer c.Close()
	setDeadline(conn, r.Timeout)
	if err := c.Hello(r.Hello); err != nil {
		return "", err
	}
	if r.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return "", errors.New("relay does not offer STARTTLS; refusing to send credentials in clear text")
		}
		if err := c.StartTLS(r.tlsConfig()); err != nil {
			return "", err
		}
	}
	if r.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", r.Username, r.Password, r.Host)); err != nil {
			// Bad relay credentials need an admin, but are not the recipient's fault:
			// keep retrying so mail goes out once they are fixed.
			return "", fmt.Errorf("relay auth: %w", err)
		}
	}
	// The hop to the relay is encrypted. When policy requires it, ask the
	// relay to keep the message encrypted all the way (REQUIRETLS, RFC
	// 8689), if it offers that.
	keepTLS := false
	if requireTLS(ctx) {
		keepTLS, _ = c.Extension("REQUIRETLS")
	}
	return transact(c, conn, r.Timeout, from, to, body, keepTLS)
}

func setDeadline(conn net.Conn, t time.Duration) {
	if t > 0 {
		conn.SetDeadline(time.Now().Add(t * 4))
	}
}

func transact(c *smtp.Client, conn net.Conn, timeout time.Duration, from, to string, body io.Reader, keepTLS bool) (string, error) {
	if keepTLS {
		// net/smtp has no MAIL parameters, so send the command directly.
		if strings.ContainsAny(from, "\r\n") {
			return "", &PermanentError{errors.New("bad sender address")}
		}
		params := " REQUIRETLS"
		if ok, _ := c.Extension("8BITMIME"); ok {
			params += " BODY=8BITMIME"
		}
		id, err := c.Text.Cmd("MAIL FROM:<%s>%s", from, params)
		if err != nil {
			return "", err
		}
		c.Text.StartResponse(id)
		_, _, err = c.Text.ReadResponse(250)
		c.Text.EndResponse(id)
		if err != nil {
			return "", classify(err)
		}
	} else if err := c.Mail(from); err != nil {
		return "", classify(err)
	}
	if err := c.Rcpt(to); err != nil {
		return "", classify(err)
	}
	w, err := c.Data()
	if err != nil {
		return "", classify(err)
	}
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(10 * time.Minute))
	}
	if _, err := io.Copy(w, body); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", classify(err)
	}
	c.Quit()
	return "250 accepted", nil
}

// Direct delivers to the recipient domain's MX hosts on port 25, using
// STARTTLS when offered.
type Direct struct {
	Hello   string
	Timeout time.Duration
	Port    int // 25; tests override
	// LookupMX defaults to the system resolver.
	LookupMX func(ctx context.Context, domain string) ([]*net.MX, error)
	// RootCAs verifies certificates when TLS is required; nil uses the
	// system roots.
	RootCAs *x509.CertPool
}

// Send delivers one message to the best reachable MX.
func (d *Direct) Send(ctx context.Context, from, to string, body io.Reader) (string, error) {
	i := strings.LastIndexByte(to, '@')
	if i < 0 {
		return "", &PermanentError{fmt.Errorf("bad recipient %q", to)}
	}
	domain := to[i+1:]
	lookup := d.LookupMX
	if lookup == nil {
		lookup = net.DefaultResolver.LookupMX
	}
	mxs, err := lookup(ctx, domain)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		mxs, err = []*net.MX{{Host: domain, Pref: 0}}, nil // implicit MX (RFC 5321 5.1)
	}
	if err != nil {
		return "", err
	}
	if len(mxs) == 1 && (mxs[0].Host == "." || mxs[0].Host == "") {
		return "", &PermanentError{fmt.Errorf("%s does not accept mail (null MX)", domain)}
	}
	sort.Slice(mxs, func(a, b int) bool { return mxs[a].Pref < mxs[b].Pref })
	port := d.Port
	if port == 0 {
		port = 25
	}
	seeker, _ := body.(io.Seeker)
	var last error
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		reply, err := d.try(ctx, host, port, from, to, body)
		if err == nil {
			return reply, nil
		}
		last = err
		var perm *PermanentError
		if errors.As(err, &perm) {
			return "", err
		}
		if seeker == nil {
			break // body consumed; retry later
		}
		seeker.Seek(0, io.SeekStart)
	}
	return "", last
}

func (d *Direct) try(ctx context.Context, host string, port int, from, to string, body io.Reader) (string, error) {
	dl := net.Dialer{Timeout: d.Timeout}
	conn, err := dl.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	setDeadline(conn, d.Timeout)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return "", err
	}
	defer c.Close()
	if err := c.Hello(d.Hello); err != nil {
		return "", err
	}
	if requireTLS(ctx) {
		// A policy says this message must travel encrypted: refuse servers
		// without STARTTLS or with a certificate that does not verify.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return "", fmt.Errorf("%s does not offer STARTTLS, and policy requires an encrypted connection", host)
		}
		cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: d.RootCAs}
		if err := c.StartTLS(cfg); err != nil {
			return "", fmt.Errorf("encrypted connection to %s required by policy: %w", host, err)
		}
	} else if ok, _ := c.Extension("STARTTLS"); ok {
		// Opportunistic TLS: most MX certificates do not match their host
		// name, and refusing them would only fall back to clear text.
		if err := c.StartTLS(&tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}); err != nil {
			return "", err
		}
	}
	return transact(c, conn, d.Timeout, from, to, body, false)
}
