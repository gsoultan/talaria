// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package listener

import (
	"bufio"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// serve accepts one connection, records its RemoteAddr, greets server-first
// and echoes one line back.
func serve(t *testing.T, ln net.Listener) <-chan string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- "accept: " + err.Error()
			return
		}
		defer c.Close()
		got <- c.RemoteAddr().String()
		c.Write([]byte("220 ready\r\n"))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Write([]byte(line))
	}()
	return got
}

func dialAndTalk(t *testing.T, addr string, header []byte) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if header != nil {
		c.Write(header)
	}
	r := bufio.NewReader(c)
	greet, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(greet, "220") {
		t.Fatalf("greeting %q, %v", greet, err)
	}
	c.Write([]byte("EHLO x\r\n"))
	echo, _ := r.ReadString('\n')
	return echo
}

func TestTrustedProxyV1AndV2(t *testing.T) {
	for _, version := range []byte{1, 2} {
		raw, _ := net.Listen("tcp", "127.0.0.1:0")
		ln := Wrap(raw, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
		got := serve(t, ln)

		h := proxyproto.HeaderProxyFromAddrs(version,
			&net.TCPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000},
			&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 25})
		hb, _ := h.Format()
		if echo := dialAndTalk(t, raw.Addr().String(), hb); echo != "EHLO x\r\n" {
			t.Fatalf("v%d: echo %q", version, echo)
		}
		if addr := <-got; addr != "198.51.100.7:40000" {
			t.Fatalf("v%d: RemoteAddr %s", version, addr)
		}
		ln.Close()
	}
}

func TestUntrustedClientIsServerFirst(t *testing.T) {
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	// Trust a range the test client is not in.
	ln := Wrap(raw, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	defer ln.Close()
	got := serve(t, ln)
	// No header, and the client waits for the greeting: must not deadlock.
	if echo := dialAndTalk(t, raw.Addr().String(), nil); echo != "EHLO x\r\n" {
		t.Fatalf("echo %q", echo)
	}
	if addr := <-got; !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("RemoteAddr %s", addr)
	}
}

func TestNoTrustedProxiesReturnsListener(t *testing.T) {
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	defer raw.Close()
	if Wrap(raw, nil) != raw {
		t.Fatal("expected the listener unchanged")
	}
}
