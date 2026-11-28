// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package smtpd runs the inbound SMTP server (port 25): it accepts mail for
// local domains, checks sender authentication and delivers to mailboxes.
package smtpd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/gsoultan/talaria/internal/audit"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/filter"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// Config for the inbound server.
type Config struct {
	Hostname       string
	MaxMessageSize int64
	MaxRecipients  int
	TLS            *tls.Config // nil disables STARTTLS
	// UpstreamTLS marks connections as TLS because a gateway terminated it.
	UpstreamTLS bool
	// Filter runs the connection checks; nil skips them.
	Filter *filter.Filter
	// Audit records submission sign-ins; nil records nothing.
	Audit *audit.Recorder
}

// Inbound is the port 25 backend.
type Inbound struct {
	cfg     Config
	store   *store.Store
	deliver *mail.Deliverer
	log     *slog.Logger
	// unknown counts rejected recipients per IP to slow address harvesting.
	unknown *auth.Limiter
}

// NewInbound returns an SMTP server for inbound mail.
func NewInbound(cfg Config, st *store.Store, d *mail.Deliverer, log *slog.Logger) *smtp.Server {
	if cfg.MaxRecipients == 0 {
		cfg.MaxRecipients = 100
	}
	b := &Inbound{cfg: cfg, store: st, deliver: d, log: log, unknown: auth.NewLimiter(20, 10*time.Minute)}
	s := smtp.NewServer(b)
	s.Domain = cfg.Hostname
	s.MaxMessageBytes = cfg.MaxMessageSize
	s.MaxRecipients = cfg.MaxRecipients
	s.MaxLineLength = 4000
	s.ReadTimeout = 5 * time.Minute
	s.WriteTimeout = time.Minute
	s.TLSConfig = cfg.TLS
	s.EnableSMTPUTF8 = true
	s.ErrorLog = logAdapter{log}
	return s
}

type logAdapter struct{ l *slog.Logger }

func (a logAdapter) Printf(format string, v ...any) {
	a.l.Debug("smtp", "msg", strings.TrimSpace(fmt.Sprintf(format, v...)))
}
func (a logAdapter) Println(v ...any) { a.l.Debug("smtp", "msg", strings.TrimSpace(fmt.Sprint(v...))) }

// NewSession is called after the greeting, at HELO/EHLO.
func (b *Inbound) NewSession(c *smtp.Conn) (smtp.Session, error) {
	ip := remoteIP(c.Conn().RemoteAddr())
	if ip != nil && !b.unknown.Allowed(ip.String()) {
		return nil, &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many unknown recipients, try later"}
	}
	var fc *filter.Conn
	if f := b.cfg.Filter; f != nil {
		var err error
		if fc, err = f.Connect(context.Background(), ip, c.Hostname()); err != nil {
			b.log.Info("refused", "ip", ip, "helo", c.Hostname(), "reason", err)
			return nil, rejectError(err)
		}
	}
	_, isTLS := c.TLSConnectionState()
	return &session{b: b, c: c, ip: ip, fc: fc, tls: isTLS || b.cfg.UpstreamTLS}, nil
}

// rejectError turns a filter refusal into an SMTP reply.
func rejectError(err error) error {
	var r *filter.Reject
	if !errors.As(err, &r) {
		return errTemporary
	}
	code := 550
	if r.Temporary {
		code = 450
	}
	return &smtp.SMTPError{Code: code, EnhancedCode: smtp.EnhancedCode{r.Code[0], r.Code[1], r.Code[2]}, Message: r.Reason}
}

type session struct {
	b     *Inbound
	c     *smtp.Conn
	ip    net.IP
	fc    *filter.Conn // nil when filtering is off
	tls   bool
	from  string
	rcpts []store.User
}

func (s *session) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *session) Logout() error { return nil }

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	s.Reset()
	if s.fc != nil {
		if err := s.b.cfg.Filter.Mail(s.fc); err != nil {
			s.b.log.Info("refused", "ip", s.ip, "from", from, "reason", err)
			return rejectError(err)
		}
	}
	s.from = from
	return nil
}

var (
	errNoUser    = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such user here"}
	errDisabled  = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 2, 1}, Message: "Mailbox disabled"}
	errTooMany   = &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{4, 7, 1}, Message: "Too many unknown recipients, try later"}
	errTemporary = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary failure, try again later"}
)

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	key := ""
	if s.ip != nil {
		key = s.ip.String()
		if !s.b.unknown.Allowed(key) {
			return errTooMany
		}
	}
	u, err := s.b.store.ResolveRecipient(context.Background(), to)
	switch {
	case errors.Is(err, store.ErrNotFound):
		if key != "" {
			s.b.unknown.Fail(key)
		}
		return errNoUser
	case err != nil:
		s.b.log.Error("resolve recipient", "err", err)
		return errTemporary
	case u.Suspended:
		return errDisabled
	}
	if s.fc != nil {
		if err := s.b.cfg.Filter.Recipient(context.Background(), s.fc, s.from, u); err != nil {
			s.b.log.Info("refused", "ip", s.ip, "from", s.from, "to", to, "reason", err)
			return rejectError(err)
		}
	}
	s.rcpts = append(s.rcpts, u)
	return nil
}

func (s *session) Data(r io.Reader) error {
	proto := "ESMTP"
	if s.tls {
		proto = "ESMTPS"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	env := mail.Envelope{RemoteIP: s.ip, Helo: s.c.Hostname(), MailFrom: s.from}
	if s.fc != nil && !s.fc.Local {
		env.BadHelo = s.fc.BadHelo
		env.NoRDNS = s.fc.RDNSChecked && s.fc.RDNS == ""
	}
	_, err := s.b.deliver.Deliver(ctx, mail.Inbound{
		Env:   env,
		Rcpts: s.rcpts, Proto: proto,
	}, r)
	io.Copy(io.Discard, r) // the server requires the body to be consumed
	return smtpError(err)
}

func smtpError(err error) error {
	var rej *mail.RejectError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &rej):
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: rej.Reason}
	case errors.Is(err, mail.ErrTooLarge):
		return smtp.ErrDataTooLarge
	case errors.Is(err, store.ErrQuotaExceeded):
		return &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 2, 2}, Message: "Mailbox full"}
	default:
		return errTemporary
	}
}

func remoteIP(a net.Addr) net.IP {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
