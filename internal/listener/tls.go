// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package listener

import (
	"crypto/tls"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

// Proxied reports whether c came through a trusted proxy (it carried a
// PROXY header that Wrap required).
func Proxied(c net.Conn) bool {
	for {
		if _, ok := c.(*proxyproto.Conn); ok {
			return true
		}
		u, ok := c.(interface{ Unwrap() net.Conn })
		if !ok {
			return false
		}
		c = u.Unwrap()
	}
}

// upstreamConn is a plaintext connection from a trusted gateway that already
// terminated TLS.
type upstreamConn struct{ net.Conn }

// Secure reports whether c is encrypted end to end to Talaria, or reached it
// through a trusted gateway that terminated TLS (see Implicit).
func Secure(c net.Conn) bool {
	switch c.(type) {
	case *tls.Conn, upstreamConn:
		return true
	}
	return false
}

// Implicit serves an implicit-TLS port (465, 993, 995). With upstream set,
// connections from a trusted proxy arrive already decrypted by the gateway
// and are passed on as they are; every other connection gets a TLS
// handshake, or is dropped when there is no certificate. Without upstream,
// every connection gets a TLS handshake.
//
// Every connection it returns is therefore secure, so the servers behind it
// may allow password logins.
func Implicit(ln net.Listener, cfg *tls.Config, upstream bool) net.Listener {
	if !upstream {
		return tls.NewListener(ln, cfg)
	}
	return &implicit{Listener: ln, cfg: cfg}
}

type implicit struct {
	net.Listener
	cfg *tls.Config
}

func (l *implicit) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if Proxied(c) {
			return upstreamConn{c}, nil
		}
		if l.cfg != nil {
			return tls.Server(c, l.cfg), nil
		}
		c.Close()
	}
}
