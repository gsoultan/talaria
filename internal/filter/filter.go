// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package filter decides, while an inbound SMTP connection is still open,
// whether to take its mail at all: DNS blocklists, greylisting, reverse DNS
// and HELO checks, per-IP rate limits, and each tenant's allow and block
// lists. Mail refused here never reaches the disk.
package filter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/store"
)

// Config tunes the checks. The zero value checks nothing but HELO forgery
// and tenant rules.
type Config struct {
	// Hostname is the server's own name, which no other server may claim
	// in HELO.
	Hostname string
	// DNSBL lists blocklist zones, e.g. "zen.spamhaus.org".
	DNSBL []string
	// Greylist defers the first message of an unknown (network, sender,
	// recipient) triplet by GreylistDelay.
	Greylist      bool
	GreylistDelay time.Duration // default 5 minutes
	GreylistTTL   time.Duration // forget unused triplets after; default 36 days
	// RequireRDNS refuses servers whose IP has no reverse DNS name that
	// resolves back to it.
	RequireRDNS bool
	// MaxPerIPHour caps messages per hour from one IP; 0 = no limit.
	MaxPerIPHour int
}

// Resolver is the DNS the checks use; tests replace it.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Filter runs the checks. It is safe for concurrent use.
type Filter struct {
	cfg  Config
	st   *store.Store
	dns  Resolver
	log  *slog.Logger
	rate *auth.Limiter

	mu     sync.Mutex
	listed map[netip.Addr]cached // DNSBL answers, shared by connections
}

type cached struct {
	zone string // "" = not listed
	at   time.Time
}

// New returns a filter. dns nil means the system resolver.
func New(cfg Config, st *store.Store, dns Resolver, log *slog.Logger) *Filter {
	if cfg.GreylistDelay <= 0 {
		cfg.GreylistDelay = 5 * time.Minute
	}
	if cfg.GreylistTTL <= 0 {
		cfg.GreylistTTL = 36 * 24 * time.Hour
	}
	if dns == nil {
		dns = net.DefaultResolver
	}
	f := &Filter{cfg: cfg, st: st, dns: dns, log: log, listed: map[netip.Addr]cached{}}
	if cfg.MaxPerIPHour > 0 {
		f.rate = auth.NewLimiter(cfg.MaxPerIPHour, time.Hour)
	}
	return f
}

// Reject is a refusal to give the client. Temporary ones (4xx) ask the
// client to try again later.
type Reject struct {
	Temporary bool
	Code      [3]int // enhanced status code, e.g. 5.7.1
	Reason    string
}

func (r *Reject) Error() string { return r.Reason }

func perm(reason string, code ...int) *Reject {
	c := [3]int{5, 7, 1}
	copy(c[:], code)
	return &Reject{Code: c, Reason: reason}
}

func temp(reason string, code ...int) *Reject {
	c := [3]int{4, 7, 1}
	copy(c[:], code)
	return &Reject{Temporary: true, Code: c, Reason: reason}
}

// Conn is what the filter learned about one connection. The spam scorer
// reads it later.
type Conn struct {
	IP   netip.Addr
	Helo string
	// Local is true for loopback and private addresses: an internal relay
	// or a test, exempt from the network checks.
	Local bool
	// RDNS is the verified reverse DNS name ("" if none), and RDNSChecked
	// whether the lookup ran.
	RDNS        string
	RDNSChecked bool
	// Listed is the blocklist zone that lists the IP, once checked.
	Listed      string
	ListChecked bool
	// BadHelo is set for a HELO that is not a fully qualified name or an
	// address literal.
	BadHelo bool
}

// Connect checks a new connection at HELO/EHLO.
func (f *Filter) Connect(ctx context.Context, ip net.IP, helo string) (*Conn, error) {
	c := &Conn{Helo: strings.ToLower(strings.TrimSpace(helo))}
	if a, ok := netip.AddrFromSlice(ip); ok {
		c.IP = a.Unmap()
	}
	c.Local = !c.IP.IsValid() || c.IP.IsLoopback() || c.IP.IsPrivate() || c.IP.IsLinkLocalUnicast()
	if err := f.checkHelo(c); err != nil {
		return c, err
	}
	return c, nil
}

func (f *Filter) checkHelo(c *Conn) error {
	h := c.Helo
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		lit := strings.TrimPrefix(strings.Trim(h, "[]"), "ipv6:")
		if a, err := netip.ParseAddr(lit); err != nil || (!c.Local && a.Unmap() != c.IP) {
			return perm("HELO address literal does not match your address")
		}
		return nil
	}
	if !c.Local && f.cfg.Hostname != "" && h == strings.ToLower(f.cfg.Hostname) {
		return perm("You are not me: HELO uses this server's own name")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		c.BadHelo = true // a bare IP must be written as [1.2.3.4]
	} else if !strings.Contains(h, ".") {
		c.BadHelo = true
	}
	return nil
}

// Mail counts a message against the client's hourly limit.
func (f *Filter) Mail(c *Conn) error {
	if f.rate == nil || c.Local {
		return nil
	}
	key := c.IP.String()
	if c.IP.Is6() {
		key = netip.PrefixFrom(c.IP, 64).Masked().String() // one host owns a /64
	}
	if !f.rate.Allowed(key) {
		return temp("Too much mail from your address, try again later", 4, 7, 1)
	}
	f.rate.Fail(key)
	return nil
}

// Recipient checks one accepted recipient: the tenant's rules first, then
// the blocklists, reverse DNS and greylisting, which the tenant can skip
// with an allow rule.
func (f *Filter) Recipient(ctx context.Context, c *Conn, from string, rcpt store.User) error {
	verdict, err := f.st.SenderVerdict(ctx, rcpt.TenantID, c.IP, from)
	if err != nil {
		f.log.Error("sender rules", "err", err)
		return temp("Temporary failure, try again later", 4, 3, 0)
	}
	switch verdict {
	case store.RuleBlock:
		return perm("Mail from you is not accepted here")
	case store.RuleAllow:
		return nil
	}
	if c.Local {
		return nil
	}
	if zone := f.blocklisted(ctx, c); zone != "" {
		return perm(fmt.Sprintf("Your address is listed by %s", zone))
	}
	if f.cfg.RequireRDNS && f.rdns(ctx, c) == "" {
		return perm("Your address has no reverse DNS name that points back to it", 5, 7, 25)
	}
	if f.cfg.Greylist {
		ok, err := f.st.Greylist(ctx, greyKey(c.IP, from, rcpt.ID), int64(f.cfg.GreylistDelay/time.Second), int64(f.cfg.GreylistTTL/time.Second))
		if err != nil {
			f.log.Error("greylist", "err", err)
			return nil // fail open: a database hiccup must not stop mail
		}
		if !ok {
			return temp("Greylisted, please try again in a few minutes", 4, 7, 1)
		}
	}
	return nil
}

// greyKey hashes the triplet. The network, not the address, so a sender
// that retries from another host of its pool still passes.
func greyKey(ip netip.Addr, from string, rcptID int64) []byte {
	bits := 24
	if ip.Is6() {
		bits = 64
	}
	p := netip.PrefixFrom(ip, bits).Masked()
	h := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%d", p, strings.ToLower(from), rcptID))
	return h[:]
}

// Prune forgets old greylist entries.
func (f *Filter) Prune(ctx context.Context) error {
	f.mu.Lock()
	for ip, c := range f.listed {
		if time.Since(c.at) > listTTL {
			delete(f.listed, ip)
		}
	}
	f.mu.Unlock()
	if !f.cfg.Greylist {
		return nil
	}
	return f.st.PruneGreylist(ctx, int64(f.cfg.GreylistTTL/time.Second))
}

const listTTL = 15 * time.Minute

// blocklisted returns the first zone listing the client, checking once per
// connection and caching answers for a few minutes.
func (f *Filter) blocklisted(ctx context.Context, c *Conn) string {
	if c.ListChecked || len(f.cfg.DNSBL) == 0 {
		return c.Listed
	}
	c.ListChecked = true
	f.mu.Lock()
	hit, ok := f.listed[c.IP]
	f.mu.Unlock()
	if ok && time.Since(hit.at) < listTTL {
		c.Listed = hit.zone
		return c.Listed
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	type answer struct {
		zone   string
		listed bool
	}
	ch := make(chan answer, len(f.cfg.DNSBL))
	for _, zone := range f.cfg.DNSBL {
		go func() { ch <- answer{zone, f.lookupDNSBL(ctx, c.IP, zone)} }()
	}
	for range f.cfg.DNSBL {
		if a := <-ch; a.listed && c.Listed == "" {
			c.Listed = a.zone
		}
	}
	f.mu.Lock()
	if len(f.listed) < 50000 {
		f.listed[c.IP] = cached{zone: c.Listed, at: time.Now()}
	}
	f.mu.Unlock()
	return c.Listed
}

func (f *Filter) lookupDNSBL(ctx context.Context, ip netip.Addr, zone string) bool {
	addrs, err := f.dns.LookupHost(ctx, ReverseName(ip)+"."+zone)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		r, err := netip.ParseAddr(a)
		if err != nil || !r.Is4() {
			continue
		}
		b := r.As4()
		// 127.0.0.2 to 127.0.0.255 mean listed. 127.255.255.x are error
		// codes (a public resolver, over quota), never a listing.
		if b[0] == 127 && !(b[1] == 255 && b[2] == 255) && !(b[1] == 0 && b[2] == 0 && b[3] < 2) {
			return true
		}
	}
	return false
}

// ReverseName is the DNSBL query label for ip: 4.3.2.1 for 1.2.3.4, and
// nibbles for IPv6.
func ReverseName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var parts []string
	for i := len(b) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", b[i]&0xf), fmt.Sprintf("%x", b[i]>>4))
	}
	return strings.Join(parts, ".")
}

// rdns returns the forward-confirmed reverse DNS name of the client, or "".
func (f *Filter) rdns(ctx context.Context, c *Conn) string {
	if c.RDNSChecked {
		return c.RDNS
	}
	c.RDNSChecked = true
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	names, err := f.dns.LookupAddr(ctx, c.IP.String())
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && !de.IsNotFound {
			c.RDNS = "?" // a DNS failure is not the sender's fault
			return c.RDNS
		}
		return ""
	}
	for i, n := range names {
		if i >= 5 {
			break
		}
		addrs, err := f.dns.LookupHost(ctx, strings.TrimSuffix(n, "."))
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p, err := netip.ParseAddr(a); err == nil && p.Unmap() == c.IP {
				c.RDNS = strings.TrimSuffix(strings.ToLower(n), ".")
				return c.RDNS
			}
		}
	}
	return ""
}
