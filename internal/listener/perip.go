// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package listener

import (
	"net"
	"sync"
)

// PerIP closes connections beyond max open ones from the same client
// address, so one host cannot take every connection slot. Use it after Wrap,
// so the limit applies to the real client behind a gateway.
func PerIP(ln net.Listener, max int) net.Listener {
	if max <= 0 {
		return ln
	}
	return &perIP{Listener: ln, max: max, open: map[string]int{}}
}

type perIP struct {
	net.Listener
	max  int
	mu   sync.Mutex
	open map[string]int
}

func hostOf(a net.Addr) string {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.IP.String()
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func (l *perIP) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := hostOf(c.RemoteAddr())
		l.mu.Lock()
		if l.open[ip] >= l.max {
			l.mu.Unlock()
			c.Close()
			continue
		}
		l.open[ip]++
		l.mu.Unlock()
		return &countedConn{Conn: c, release: func() {
			l.mu.Lock()
			if l.open[ip]--; l.open[ip] <= 0 {
				delete(l.open, ip)
			}
			l.mu.Unlock()
		}}, nil
	}
}

type countedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *countedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// Unwrap returns the connection PerIP wrapped.
func (c *countedConn) Unwrap() net.Conn { return c.Conn }
