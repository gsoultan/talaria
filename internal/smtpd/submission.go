// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package smtpd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

// Submission is the backend for ports 587 and 465: authenticated users
// sending mail.
type Submission struct {
	cfg    Config
	store  *store.Store
	submit *outbound.Submitter
	log    *slog.Logger
	fails  *auth.Limiter
}

// NewSubmission returns an SMTP server for mail apps. AUTH is only offered
// over TLS (or when a gateway terminated TLS, UpstreamTLS).
func NewSubmission(cfg Config, st *store.Store, sub *outbound.Submitter, log *slog.Logger) *smtp.Server {
	b := &Submission{cfg: cfg, store: st, submit: sub, log: log, fails: auth.NewLimiter(10, 15*time.Minute)}
	s := smtp.NewServer(b)
	s.Domain = cfg.Hostname
	s.MaxMessageBytes = cfg.MaxMessageSize
	s.MaxRecipients = 100
	s.MaxLineLength = 4000
	s.ReadTimeout = 5 * time.Minute
	s.WriteTimeout = time.Minute
	s.TLSConfig = cfg.TLS
	s.AllowInsecureAuth = cfg.UpstreamTLS
	s.EnableSMTPUTF8 = true
	s.ErrorLog = logAdapter{log}
	return s
}

func (b *Submission) NewSession(c *smtp.Conn) (smtp.Session, error) {
	ip := remoteIP(c.Conn().RemoteAddr())
	key := ""
	if ip != nil {
		key = ip.String()
	}
	if !b.fails.Allowed(key) {
		return nil, &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many failed logins, try later"}
	}
	_, isTLS := c.TLSConnectionState()
	return &subSession{b: b, ip: ip, key: key, tls: isTLS || b.cfg.UpstreamTLS}, nil
}

type subSession struct {
	b     *Submission
	ip    net.IP
	key   string
	tls   bool
	user  *store.User
	from  string
	rcpts []string
}

var (
	errAuthRequired = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}
	errBadAuth      = &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Authentication failed"}
	errNotYours     = &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "You cannot send as this address"}
)

func (s *subSession) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *subSession) Auth(mech string) (sasl.Server, error) {
	check := func(username, password string) error {
		u, err := s.b.store.UserByAddress(context.Background(), username)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return errTemporary
		}
		if !auth.CheckPassword(u.PasswordHash, password) || u.Suspended {
			s.b.fails.Fail(s.key)
			return errBadAuth
		}
		s.user = &u
		return nil
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && !strings.EqualFold(identity, username) {
				return errBadAuth
			}
			return check(username, password)
		}), nil
	case sasl.Login:
		return &loginServer{check: check}, nil
	}
	return nil, errBadAuth
}

func (s *subSession) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *subSession) Logout() error { return nil }

func (s *subSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.user == nil {
		return errAuthRequired
	}
	if !s.b.store.CanSendAs(context.Background(), *s.user, from) {
		return errNotYours
	}
	s.Reset()
	s.from = from
	return nil
}

func (s *subSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.user == nil {
		return errAuthRequired
	}
	if _, _, err := store.SplitAddress(to); err != nil {
		return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 1, 3}, Message: "Bad recipient address"}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *subSession) Data(r io.Reader) error {
	if s.user == nil {
		return errAuthRequired
	}
	proto := "ESMTPSA"
	if !s.tls {
		proto = "ESMTPA"
	}
	ip := ""
	if s.ip != nil {
		ip = s.ip.String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := s.b.submit.Submit(ctx, outbound.Submission{User: *s.user, MailFrom: s.from, Rcpts: s.rcpts, ClientIP: ip, Proto: proto}, r)
	io.Copy(io.Discard, r)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, outbound.ErrSenderNotAllowed):
		return errNotYours
	case errors.Is(err, store.ErrSendLimit):
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 1}, Message: "Daily sending limit reached, try later"}
	case errors.Is(err, mail.ErrTooLarge):
		return smtp.ErrDataTooLarge
	}
	var rerr *outbound.RecipientError
	if errors.As(err, &rerr) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: rerr.Msg}
	}
	s.b.log.Error("submission", "user", s.user.Address(), "err", err)
	return errTemporary
}

// loginServer implements the obsolete but widely used AUTH LOGIN.
type loginServer struct {
	check func(user, pass string) error
	user  string
	step  int
}

func (l *loginServer) Next(resp []byte) ([]byte, bool, error) {
	switch l.step {
	case 0:
		l.step = 1
		if len(resp) > 0 { // initial response carries the username
			l.user = string(resp)
			l.step = 2
			return []byte("Password:"), false, nil
		}
		return []byte("Username:"), false, nil
	case 1:
		l.user = string(resp)
		l.step = 2
		return []byte("Password:"), false, nil
	case 2:
		l.step = 3
		return nil, true, l.check(l.user, string(resp))
	}
	return nil, true, errBadAuth
}
