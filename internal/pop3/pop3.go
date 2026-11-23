// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package pop3 serves each user's Inbox over POP3 (RFC 1939) with UIDL,
// TOP, STLS and SASL PLAIN, for mail apps that download and delete.
package pop3

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/hub"
	"github.com/gsoultan/talaria/internal/store"
)

// Config for the POP3 server.
type Config struct {
	Hostname string
	TLS      *tls.Config
	// UpstreamTLS treats plaintext connections as secure because a gateway
	// terminated TLS in front of them.
	UpstreamTLS bool
	// IdleTimeout closes silent sessions; RFC 1939 asks for at least 10 minutes.
	IdleTimeout time.Duration
}

// Server is a POP3 server.
type Server struct {
	cfg   Config
	store *store.Store
	blobs *blob.Store
	hub   *hub.Hub
	log   *slog.Logger
	fails *auth.Limiter

	mu     sync.Mutex
	lns    map[net.Listener]bool
	conns  map[net.Conn]bool
	closed bool
	// locks holds users with an open transaction: RFC 1939 gives one
	// session at a time an exclusive lock on the maildrop.
	locks map[int64]bool
}

// New returns a POP3 server.
func New(cfg Config, st *store.Store, bl *blob.Store, h *hub.Hub, log *slog.Logger) *Server {
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	return &Server{cfg: cfg, store: st, blobs: bl, hub: h, log: log, fails: auth.NewLimiter(10, 15*time.Minute),
		lns: map[net.Listener]bool{}, conns: map[net.Conn]bool{}, locks: map[int64]bool{}}
}

// ErrServerClosed is returned by Serve after Close.
var ErrServerClosed = errors.New("pop3: server closed")

// Serve accepts connections on l until Close.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.lns[l] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.lns, l)
		s.mu.Unlock()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handle(c)
	}
}

// Close stops all listeners and connections.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for l := range s.lns {
		l.Close()
	}
	for c := range s.conns {
		c.Close()
	}
	return nil
}

func (s *Server) track(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		if s.closed {
			return false
		}
		s.conns[c] = true
	} else {
		delete(s.conns, c)
	}
	return true
}

func (s *Server) lock(userID int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks[userID] {
		return false
	}
	s.locks[userID] = true
	return true
}

func (s *Server) unlock(userID int64) {
	s.mu.Lock()
	delete(s.locks, userID)
	s.mu.Unlock()
}

type item struct {
	msg     store.Message
	deleted bool
}

type conn struct {
	s      *Server
	nc     net.Conn
	r      *bufio.Reader
	w      *bufio.Writer
	ip     string
	secure bool
	user   string
	u      *store.User
	mb     store.Mailbox
	items  []item
}

func (s *Server) handle(nc net.Conn) {
	if !s.track(nc, true) {
		nc.Close()
		return
	}
	defer s.track(nc, false)
	defer nc.Close()
	c := &conn{s: s, nc: nc}
	c.reset(nc)
	if a, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
		c.ip = a.IP.String()
	}
	if tc, ok := nc.(*tls.Conn); ok {
		tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.Handshake(); err != nil {
			return
		}
		c.secure = true
	} else if s.cfg.UpstreamTLS {
		c.secure = true
	}
	defer func() {
		if c.u != nil {
			s.unlock(c.u.ID)
		}
	}()
	c.ok("Talaria POP3 ready")
	for {
		nc.SetDeadline(time.Now().Add(s.cfg.IdleTimeout))
		line, err := c.r.ReadString('\n')
		if err != nil {
			return
		}
		if len(line) > 512 {
			c.err("line too long")
			continue
		}
		cmd, arg, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		if quit := c.command(strings.ToUpper(cmd), arg); quit {
			return
		}
	}
}

func (c *conn) reset(nc net.Conn) {
	c.nc = nc
	c.r = bufio.NewReaderSize(nc, 1024)
	c.w = bufio.NewWriterSize(nc, 32<<10)
}

func (c *conn) ok(msg string) {
	c.w.WriteString("+OK " + msg + "\r\n")
	c.w.Flush()
}

func (c *conn) err(msg string) {
	c.w.WriteString("-ERR " + msg + "\r\n")
	c.w.Flush()
}

func (c *conn) capa() {
	c.w.WriteString("+OK capabilities follow\r\nTOP\r\nUIDL\r\nUSER\r\nRESP-CODES\r\nAUTH-RESP-CODE\r\nPIPELINING\r\nSASL PLAIN\r\nIMPLEMENTATION Talaria\r\n")
	if !c.secure && c.s.cfg.TLS != nil {
		c.w.WriteString("STLS\r\n")
	}
	c.w.WriteString(".\r\n")
	c.w.Flush()
}

// command runs one command and reports whether the session ends.
func (c *conn) command(cmd, arg string) bool {
	if c.u == nil {
		return c.authorization(cmd, arg)
	}
	switch cmd {
	case "STAT":
		n, size := 0, int64(0)
		for _, it := range c.items {
			if !it.deleted {
				n++
				size += it.msg.Size
			}
		}
		c.ok(fmt.Sprintf("%d %d", n, size))
	case "LIST", "UIDL":
		if arg != "" {
			i, ok := c.index(arg)
			if !ok {
				return false
			}
			c.ok(fmt.Sprintf("%d %s", i+1, c.value(cmd, i)))
			return false
		}
		c.w.WriteString("+OK\r\n")
		for i, it := range c.items {
			if !it.deleted {
				fmt.Fprintf(c.w, "%d %s\r\n", i+1, c.value(cmd, i))
			}
		}
		c.w.WriteString(".\r\n")
		c.w.Flush()
	case "RETR":
		i, ok := c.index(arg)
		if ok {
			c.send(i, -1)
		}
	case "TOP":
		n, lines, _ := strings.Cut(arg, " ")
		k, err := strconv.Atoi(strings.TrimSpace(lines))
		if err != nil || k < 0 {
			c.err("usage: TOP msg lines")
			return false
		}
		if i, ok := c.index(n); ok {
			c.send(i, k)
		}
	case "DELE":
		if i, ok := c.index(arg); ok {
			c.items[i].deleted = true
			c.ok("marked for deletion")
		}
	case "RSET":
		for i := range c.items {
			c.items[i].deleted = false
		}
		c.ok("")
	case "NOOP":
		c.ok("")
	case "CAPA":
		c.capa()
	case "QUIT":
		c.update()
		return true
	default:
		c.err("unknown command")
	}
	return false
}

func (c *conn) value(cmd string, i int) string {
	m := c.items[i].msg
	if cmd == "LIST" {
		return strconv.FormatInt(m.Size, 10)
	}
	return fmt.Sprintf("%d.%d", c.mb.UIDValidity, m.UID)
}

func (c *conn) index(arg string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(arg))
	if err != nil || n < 1 || n > len(c.items) {
		c.err("no such message")
		return 0, false
	}
	if c.items[n-1].deleted {
		c.err("message deleted")
		return 0, false
	}
	return n - 1, true
}

func (c *conn) authorization(cmd, arg string) bool {
	switch cmd {
	case "CAPA":
		c.capa()
	case "STLS":
		if c.secure || c.s.cfg.TLS == nil {
			c.err("TLS not available")
			return false
		}
		c.ok("begin TLS negotiation")
		tc := tls.Server(c.nc, c.s.cfg.TLS)
		tc.SetDeadline(time.Now().Add(30 * time.Second))
		if err := tc.Handshake(); err != nil {
			return true
		}
		c.reset(tc)
		c.secure = true
		c.user = ""
	case "USER":
		if !c.secure {
			c.err("[AUTH] use STLS first")
			return false
		}
		c.user = strings.TrimSpace(arg)
		c.ok("")
	case "PASS":
		if c.user == "" {
			c.err("USER first")
			return false
		}
		c.login(c.user, arg)
	case "AUTH":
		mech, ir, _ := strings.Cut(arg, " ")
		if !strings.EqualFold(mech, "PLAIN") {
			c.err("unsupported mechanism")
			return false
		}
		if !c.secure {
			c.err("[AUTH] use STLS first")
			return false
		}
		if ir == "" {
			c.w.WriteString("+ \r\n")
			c.w.Flush()
			line, err := c.r.ReadString('\n')
			if err != nil {
				return true
			}
			ir = strings.TrimRight(line, "\r\n")
		}
		if ir == "*" {
			c.err("authentication cancelled")
			return false
		}
		raw, err := base64.StdEncoding.DecodeString(ir)
		parts := strings.Split(string(raw), "\x00")
		if err != nil || len(parts) != 3 || (parts[0] != "" && parts[0] != parts[1]) {
			c.err("[AUTH] invalid credentials")
			return false
		}
		c.login(parts[1], parts[2])
	case "QUIT":
		c.ok("bye")
		return true
	default:
		c.err("authenticate first")
	}
	return false
}

func (c *conn) login(username, password string) {
	c.user = ""
	if !c.s.fails.Allowed(c.ip) {
		c.err("[LOGIN-DELAY] too many failed logins, try later")
		return
	}
	ctx := context.Background()
	u, err := c.s.store.UserByAddress(ctx, strings.TrimSpace(username))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		c.err("[SYS/TEMP] try again later")
		return
	}
	if !auth.CheckPassword(u.PasswordHash, password) || u.Suspended {
		c.s.fails.Fail(c.ip)
		c.err("[AUTH] invalid credentials")
		return
	}
	if !c.s.lock(u.ID) {
		c.err("[IN-USE] mailbox is open in another POP3 session")
		return
	}
	mb, err := c.s.store.MailboxByUse(ctx, u.ID, store.UseInbox)
	var msgs []store.Message
	if err == nil {
		msgs, err = c.s.store.MailboxMessages(ctx, u.ID, mb.ID)
	}
	if err != nil {
		c.s.unlock(u.ID)
		c.s.log.Error("pop3", "err", err)
		c.err("[SYS/TEMP] try again later")
		return
	}
	c.u, c.mb = &u, mb
	c.items = make([]item, len(msgs))
	for i, m := range msgs {
		c.items[i] = item{msg: m}
	}
	c.ok(fmt.Sprintf("%d messages", len(msgs)))
}

// send writes a message, dot-stuffed. With lines >= 0 it writes the header
// and that many body lines (TOP).
func (c *conn) send(i, lines int) {
	m := c.items[i].msg
	full, err := c.s.store.Message(context.Background(), c.u.ID, m.ID)
	var r io.ReadCloser
	if err == nil {
		r, err = c.s.blobs.Open(c.u.TenantID, full.BlobHash)
	}
	if err != nil {
		c.s.log.Error("pop3 read", "err", err)
		c.err("[SYS/TEMP] cannot read message")
		return
	}
	defer r.Close()
	c.w.WriteString("+OK\r\n")
	br := bufio.NewReaderSize(r, 32<<10)
	inBody, n := false, 0
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			if inBody && lines >= 0 {
				if n >= lines {
					break
				}
				n++
			}
			text := strings.TrimRight(line, "\r\n")
			if !inBody && text == "" {
				inBody = true
			}
			if strings.HasPrefix(text, ".") {
				c.w.WriteByte('.')
			}
			c.w.WriteString(text)
			c.w.WriteString("\r\n")
		}
		if err != nil {
			break
		}
	}
	c.w.WriteString(".\r\n")
	c.w.Flush()
	if lines < 0 && full.Flags&store.FlagSeen == 0 {
		if mbs, err := c.s.store.SetFlags(context.Background(), c.u.ID, []int64{m.ID}, store.FlagSeen, 0); err == nil {
			c.s.hub.Publish(c.u.ID, mbs...)
		}
	}
}

// update applies deletions at QUIT (the UPDATE state).
func (c *conn) update() {
	var ids []int64
	for _, it := range c.items {
		if it.deleted {
			ids = append(ids, it.msg.ID)
		}
	}
	if len(ids) > 0 {
		mbs, err := c.s.store.ExpungeMessages(context.Background(), c.u.ID, ids)
		if err != nil {
			c.s.log.Error("pop3 delete", "err", err)
			c.err("[SYS/TEMP] some messages were not deleted")
			return
		}
		c.s.hub.Publish(c.u.ID, mbs...)
	}
	c.ok("bye")
}
