// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package config loads Talaria's TOML configuration file.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is the full server configuration. Domains, users and mailboxes live
// in the database, not here, so many domains can be managed at runtime.
type Config struct {
	// Hostname is the server's public FQDN, used in SMTP banners and HELO.
	Hostname string `toml:"hostname"`
	// DataDir holds the message blob store, certificates and temporary
	// files. Metadata lives in PostgreSQL (see Database).
	DataDir string `toml:"data_dir"`
	// Database is the PostgreSQL database for metadata and search.
	Database Database `toml:"database"`
	// MemoryLimit is the Go runtime soft memory limit, e.g. "512MiB".
	MemoryLimit ByteSize `toml:"memory_limit"`
	Log         Log      `toml:"log"`
	HTTP        HTTP     `toml:"http"`
	SMTP        SMTP     `toml:"smtp"`
	IMAP        IMAP     `toml:"imap"`
	POP3        POP3     `toml:"pop3"`
	Outbound    Outbound `toml:"outbound"`
	TLS         TLS      `toml:"tls"`
	Ingest      Ingest   `toml:"ingest"`
	Filter      Filter   `toml:"filter"`
}

// Filter configures the checks on inbound SMTP connections. Tenants add
// their own allow and block lists in the admin.
type Filter struct {
	// DNSBL lists DNS blocklist zones. Spamhaus refuses queries that come
	// through public resolvers (8.8.8.8, 1.1.1.1); run a local resolver
	// such as unbound, or use its data query service key in the zone.
	DNSBL []string `toml:"dnsbl"`
	// Greylist defers the first message from an unknown sender for
	// greylist_delay; real mail servers retry and get through.
	Greylist      bool     `toml:"greylist"`
	GreylistDelay Duration `toml:"greylist_delay"`
	// RequireRDNS refuses servers without forward-confirmed reverse DNS.
	RequireRDNS bool `toml:"require_rdns"`
	// MaxPerIPHour caps messages per hour from one IP (IPv6: one /64).
	MaxPerIPHour int `toml:"max_per_ip_hour"`
}

// Database configures the PostgreSQL connection.
type Database struct {
	// URL is a PostgreSQL connection URL, e.g.
	// postgres://talaria:secret@localhost:5432/talaria?sslmode=disable.
	// TALARIA_DATABASE_URL in the environment overrides it, which keeps the
	// password out of the config file.
	URL string `toml:"url"`
	// MaxConns caps open connections. Each one is a PostgreSQL process of
	// several MB, so keep it small on a small machine. Default 10.
	MaxConns int `toml:"max_conns"`
}

// DatabaseURLEnv overrides database.url.
const DatabaseURLEnv = "TALARIA_DATABASE_URL"

// TLS controls where TLS is terminated. Behind Cloudflare Tunnel or a web
// gateway the HTTP side is usually terminated upstream ("off"), while SMTP and
// IMAP listeners that face the internet still need certificates.
type TLS struct {
	// Mode is "acme" (automatic Let's Encrypt), "files" (cert_file/key_file),
	// or "off" (plaintext; TLS is terminated by a proxy or tunnel).
	Mode     string   `toml:"mode"`
	CertFile string   `toml:"cert_file"`
	KeyFile  string   `toml:"key_file"`
	Email    string   `toml:"email"` // ACME account contact
	Hosts    []string `toml:"hosts"` // names to request certificates for
}

// Ingest is an HTTP endpoint that accepts raw RFC 5322 messages. It lets
// mail arrive without a public port 25, for example from a Cloudflare Email
// Worker or an external MX relay, through a tunnel or web gateway.
type Ingest struct {
	Enabled bool `toml:"enabled"`
	// TokenFile holds the shared bearer token callers must present.
	TokenFile string `toml:"token_file"`
}

type Log struct {
	Level  string `toml:"level"`  // debug, info, warn, error
	Format string `toml:"format"` // text or json
}

type HTTP struct {
	Listen string `toml:"listen"`
	// ListenTLS serves HTTPS (usually ":443") with the certificates from
	// [tls]. Leave empty behind Cloudflare Tunnel or a gateway that
	// terminates HTTPS. tls.mode "acme" needs it: certificates are proven over
	// this port (TLS-ALPN-01), or over Listen on port 80 (HTTP-01).
	ListenTLS string `toml:"listen_tls"`
	// TrustedProxies lists CIDRs (e.g. the cloudflared host, a gateway) whose
	// forwarded client-IP headers are believed. Empty means trust nobody.
	TrustedProxies []string `toml:"trusted_proxies"`
	// ClientIPHeader is read from trusted proxies: "X-Forwarded-For",
	// "X-Real-IP" or "CF-Connecting-IP".
	ClientIPHeader string `toml:"client_ip_header"`
}

// ProxyProtocol holds gateway options shared by the SMTP and IMAP listeners.
type ProxyProtocol struct {
	// TrustedProxies lists gateway CIDRs (Gateon, HAProxy, nginx stream).
	// Connections from them must begin with a PROXY protocol v1 or v2 header
	// carrying the real client address, which SPF, rate limits and logs use.
	// Connections from other addresses are served directly as usual.
	TrustedProxies []string `toml:"trusted_proxies"`
	// UpstreamTLS marks the implicit-TLS listener (465 or 993) as fed by a
	// gateway that already terminated TLS and forwards plaintext. Talaria then
	// treats those sessions as encrypted without doing its own handshake.
	// Only takes effect for connections from TrustedProxies.
	UpstreamTLS bool `toml:"upstream_tls"`
}

type SMTP struct {
	// Listen is the inbound MX listener (port 25).
	Listen string `toml:"listen"`
	// Submission is the authenticated STARTTLS listener (port 587).
	Submission string `toml:"submission"`
	// SubmissionTLS is the authenticated implicit-TLS listener (port 465).
	SubmissionTLS  string   `toml:"submission_tls"`
	MaxMessageSize ByteSize `toml:"max_message_size"`
	MaxConnections int      `toml:"max_connections"`
	ProxyProtocol
}

type IMAP struct {
	Listen    string `toml:"listen"`     // STARTTLS, port 143
	ListenTLS string `toml:"listen_tls"` // implicit TLS, port 993
	ProxyProtocol
}

// POP3 serves the Inbox to apps that download and delete. Off by default;
// IMAP is the better choice for most people.
type POP3 struct {
	Listen    string `toml:"listen"`     // STARTTLS (STLS), port 110
	ListenTLS string `toml:"listen_tls"` // implicit TLS, port 995
	ProxyProtocol
}

// Outbound controls how mail leaves the server. Most VPS providers block
// outbound port 25, so relaying through a smarthost is the default.
type Outbound struct {
	// Mode is "relay" (send everything through a smarthost) or "direct"
	// (deliver to recipient MX hosts on port 25).
	Mode  string `toml:"mode"`
	Relay Relay  `toml:"relay"`
}

type Relay struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"` // 587 (STARTTLS) or 465 (implicit TLS)
	Username string `toml:"username"`
	// PasswordFile points to a file holding the relay password, so the
	// secret stays out of the config file.
	PasswordFile string   `toml:"password_file"`
	Timeout      Duration `toml:"timeout"`
}

// Default returns a configuration tuned for a 2 vCPU / 2 GB machine.
func Default() Config {
	return Config{
		Hostname:    "localhost",
		DataDir:     "./data",
		MemoryLimit: 512 * MiB,
		Database:    Database{MaxConns: 10},
		Filter: Filter{
			DNSBL:         []string{"zen.spamhaus.org", "bl.spamcop.net"},
			GreylistDelay: Duration(5 * time.Minute),
			MaxPerIPHour:  500,
		},
		Log:  Log{Level: "info", Format: "text"},
		HTTP: HTTP{Listen: ":8080", ClientIPHeader: "X-Forwarded-For"},
		TLS:  TLS{Mode: "off"},
		SMTP: SMTP{
			Listen:         ":25",
			Submission:     ":587",
			SubmissionTLS:  ":465",
			MaxMessageSize: 25 * MiB,
			MaxConnections: 200,
		},
		IMAP:     IMAP{Listen: ":143", ListenTLS: ":993"},
		Outbound: Outbound{Mode: "relay", Relay: Relay{Port: 587, Timeout: Duration(30 * time.Second)}},
	}
}

// Load reads path on top of the defaults. An empty path returns the defaults.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		dec := toml.NewDecoder(strings.NewReader(string(b))).DisallowUnknownFields()
		if err := dec.Decode(&cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	if u := os.Getenv(DatabaseURLEnv); u != "" {
		cfg.Database.URL = u
	}
	return cfg, cfg.Validate()
}

// Validate reports configuration errors that would stop the server starting.
func (c Config) Validate() error {
	var errs []error
	if c.Hostname == "" {
		errs = append(errs, errors.New("hostname is required"))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir is required"))
	}
	if c.Database.URL == "" {
		errs = append(errs, errors.New("database.url is required (or set "+DatabaseURLEnv+")"))
	} else if !strings.HasPrefix(c.Database.URL, "postgres://") && !strings.HasPrefix(c.Database.URL, "postgresql://") {
		errs = append(errs, errors.New("database.url must be a postgres:// URL"))
	}
	if c.Database.MaxConns < 0 {
		errs = append(errs, errors.New("database.max_conns must not be negative"))
	}
	switch c.Outbound.Mode {
	case "direct":
	case "relay":
		if c.Outbound.Relay.Port != 587 && c.Outbound.Relay.Port != 465 && c.Outbound.Relay.Port != 25 && c.Outbound.Relay.Port != 2525 {
			errs = append(errs, fmt.Errorf("outbound.relay.port %d: use 587, 465, 2525 or 25", c.Outbound.Relay.Port))
		}
	default:
		errs = append(errs, fmt.Errorf("outbound.mode %q: must be relay or direct", c.Outbound.Mode))
	}
	switch c.TLS.Mode {
	case "off":
		if c.HTTP.ListenTLS != "" {
			errs = append(errs, errors.New("http.listen_tls needs certificates: set tls.mode to acme or files"))
		}
	case "acme":
		if c.HTTP.ListenTLS == "" {
			errs = append(errs, errors.New(`tls.mode "acme" needs http.listen_tls (port 443 reachable from the internet)`))
		}
	case "files":
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			errs = append(errs, errors.New("tls.mode files needs cert_file and key_file"))
		}
	default:
		errs = append(errs, fmt.Errorf("tls.mode %q: must be acme, files or off", c.TLS.Mode))
	}
	switch c.HTTP.ClientIPHeader {
	case "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP":
	default:
		errs = append(errs, fmt.Errorf("http.client_ip_header %q: use X-Forwarded-For, X-Real-IP or CF-Connecting-IP", c.HTTP.ClientIPHeader))
	}
	for _, list := range [][]string{c.HTTP.TrustedProxies, c.SMTP.TrustedProxies, c.IMAP.TrustedProxies, c.POP3.TrustedProxies} {
		if _, err := ParsePrefixes(list); err != nil {
			errs = append(errs, err)
		}
	}
	for name, pp := range map[string]ProxyProtocol{"smtp": c.SMTP.ProxyProtocol, "imap": c.IMAP.ProxyProtocol, "pop3": c.POP3.ProxyProtocol} {
		if pp.UpstreamTLS && len(pp.TrustedProxies) == 0 {
			errs = append(errs, fmt.Errorf("%s.upstream_tls needs %s.trusted_proxies: only the gateway's connections count as encrypted", name, name))
		}
	}
	if c.Ingest.Enabled && c.Ingest.TokenFile == "" {
		errs = append(errs, errors.New("ingest.enabled needs ingest.token_file"))
	}
	return errors.Join(errs...)
}

// ParsePrefixes parses CIDRs or bare IPs into prefixes.
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: not an IP or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
