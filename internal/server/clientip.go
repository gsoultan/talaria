// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// ClientIP returns the client address resolved by ClientIPMiddleware.
func ClientIP(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(clientIPKey{}).(netip.Addr)
	return a
}

// ClientIPMiddleware resolves the real client address. Forwarded headers are
// honoured only when the direct peer is in trusted, so a client cannot spoof
// its address by sending the header itself. For X-Forwarded-For the rightmost
// address that is not itself a trusted proxy wins.
func ClientIPMiddleware(trusted []netip.Prefix, header string, next http.Handler) http.Handler {
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := peerAddr(r.RemoteAddr)
		if ip.IsValid() && isTrusted(ip) {
			if v := r.Header.Get(header); v != "" {
				if header == "X-Forwarded-For" {
					parts := strings.Split(v, ",")
					for i := len(parts) - 1; i >= 0; i-- {
						a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
						if err != nil {
							break
						}
						ip = a.Unmap()
						if !isTrusted(ip) {
							break
						}
					}
				} else if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
					ip = a.Unmap()
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip)))
	})
}

func peerAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
