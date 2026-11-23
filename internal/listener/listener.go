// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package listener builds the TCP listeners for SMTP and IMAP, including
// HAProxy PROXY protocol (v1 and v2) for running behind a TCP gateway such
// as Gateon, HAProxy, nginx stream or Traefik.
package listener

import (
	"net"
	"net/netip"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// HeaderTimeout bounds how long a trusted proxy has to send its PROXY header.
const HeaderTimeout = 5 * time.Second

// Wrap returns ln unchanged when trusted is empty. Otherwise connections from
// a trusted proxy must start with a PROXY header, and their RemoteAddr is the
// real client. Connections from anyone else are passed through untouched, so
// the same port can also take direct traffic, and a header they send is not
// believed (the SMTP or IMAP parser rejects it as a bad command).
//
// SMTP and IMAP are server-first: the server greets before the client says
// anything. Callers must call RemoteAddr before writing the greeting; for a
// trusted proxy that reads the header, which the proxy sends on connect.
// Untrusted connections are never read before the greeting.
func Wrap(ln net.Listener, trusted []netip.Prefix) net.Listener {
	if len(trusted) == 0 {
		return ln
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: HeaderTimeout,
		ConnPolicy: func(o proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if isTrusted(o.Upstream, trusted) {
				return proxyproto.REQUIRE, nil
			}
			return proxyproto.SKIP, nil
		},
	}
}

func isTrusted(addr net.Addr, trusted []netip.Prefix) bool {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return false
	}
	a, ok := netip.AddrFromSlice(tcp.IP)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
