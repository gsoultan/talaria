// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package imapd serves users' mailboxes over IMAP (IMAP4rev1 and rev2, with
// IDLE, MOVE, UIDPLUS and SPECIAL-USE), backed by the same store as the
// webmail, so changes show up everywhere at once.
package imapd

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/store"
)

// Config for the IMAP server.
type Config struct {
	TLS *tls.Config
	// UpstreamTLS treats plaintext connections as secure because a gateway
	// terminated TLS in front of them.
	UpstreamTLS bool
	MaxSize     int64
}

// Backend holds what sessions share.
type Backend struct {
	cfg     Config
	store   *store.Store
	blobs   *blob.Store
	hub     *hub.Hub
	deliver *mail.Deliverer
	log     *slog.Logger
	fails   *auth.Limiter
	// fetchSem bounds full-message loads so a client fetching many large
	// messages at once cannot exhaust memory.
	fetchSem chan struct{}
}

// New returns an IMAP server.
func New(cfg Config, st *store.Store, bl *blob.Store, h *hub.Hub, d *mail.Deliverer, log *slog.Logger) *imapserver.Server {
	b := &Backend{cfg: cfg, store: st, blobs: bl, hub: h, deliver: d, log: log,
		fails: auth.NewLimiter(10, 15*time.Minute), fetchSem: make(chan struct{}, 4)}
	caps := imap.CapSet{
		imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}, imap.CapIdle: {}, imap.CapMove: {}, imap.CapUIDPlus: {},
		imap.CapUnselect: {}, imap.CapNamespace: {}, imap.CapSpecialUse: {}, imap.CapLiteralMinus: {}, imap.CapStatusSize: {},
		imap.CapChildren: {}, imap.CapESearch: {}, imap.CapSASLIR: {}, imap.CapEnable: {}, imap.CapListExtended: {}, imap.CapListStatus: {},
	}
	return imapserver.New(&imapserver.Options{
		NewSession: b.newSession,
		Caps:       caps,
		Logger:     slogLogger{log},
		TLSConfig:  cfg.TLS,
		// Without TLS here, logins are only safe if a gateway terminated it.
		InsecureAuth: cfg.UpstreamTLS,
	})
}

type slogLogger struct{ l *slog.Logger }

func (s slogLogger) Printf(format string, v ...any) {
	s.l.Debug("imap", "msg", strings.TrimSpace(sprintf(format, v...)))
}

func (b *Backend) newSession(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	ip := ""
	if a, ok := c.NetConn().RemoteAddr().(*net.TCPAddr); ok {
		ip = a.IP.String()
	}
	return &session{b: b, ip: ip}, nil, nil
}

var (
	errNoMailbox = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
	errTryLater  = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "Too many failed logins, try later"}
	errServer    = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeServerBug, Text: "Internal error"}
	errOverQuota = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeOverQuota, Text: "Mailbox full"}
	errTooBig    = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTooBig, Text: "Message too large"}
)

func (b *Backend) err(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return errNoMailbox
	case errors.Is(err, store.ErrExists):
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAlreadyExists, Text: "Mailbox already exists"}
	case errors.Is(err, store.ErrInvalid):
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: err.Error()}
	case errors.Is(err, store.ErrQuotaExceeded):
		return errOverQuota
	case errors.Is(err, mail.ErrTooLarge):
		return errTooBig
	}
	var ie *imap.Error
	if errors.As(err, &ie) {
		return err
	}
	b.log.Error("imap", "err", err)
	return errServer
}

func ctx() context.Context { return context.Background() }
