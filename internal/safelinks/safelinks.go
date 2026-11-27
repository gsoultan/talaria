// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package safelinks checks links in mail when they are clicked. The
// webmail sends every link through a redirect that looks it up in threat
// feeds (URLhaus, OpenPhish or any list of URLs or hosts) and in a few
// tells of phishing, and warns before opening anything bad.
package safelinks

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Feed is a list of bad URLs or hosts, one per line; # starts a comment.
type Feed struct {
	Name string
	URL  string
	// Hosts means each line is a host name: everything on it is bad.
	// Otherwise lines are URLs, and only those URLs are bad (they are
	// often single pages on hacked but otherwise good sites).
	Hosts bool
}

// DefaultFeeds are free feeds that need no account.
var DefaultFeeds = []Feed{
	{Name: "URLhaus", URL: "https://urlhaus.abuse.ch/downloads/text_online/"},
	{Name: "OpenPhish", URL: "https://openphish.com/feed.txt"},
}

// Level is how bad a link is.
type Level int

const (
	Safe Level = iota
	// Suspicious links get a warning with a way through.
	Suspicious
	// Malicious links are not opened.
	Malicious
)

// Verdict is the result of a check.
type Verdict struct {
	Level  Level
	Reason string
}

// Checker holds the feeds. It is safe for concurrent use.
type Checker struct {
	Feeds  []Feed
	Dir    string // caches the feeds across restarts; "" keeps none
	Client *http.Client
	Log    *slog.Logger
	// Block lists hosts the admin never wants opened, with subdomains.
	Block []string

	mu    sync.RWMutex
	urls  map[string]string // normalized URL -> feed
	hosts map[string]string // host -> feed
	raw   map[string][]byte // feed URL -> body, when there is no Dir
}

// Check looks a link up.
func (c *Checker) Check(raw string) Verdict {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Verdict{Malicious, "This is not a web address."}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Verdict{Malicious, "Only web links can be opened from mail."}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, b := range c.Block {
		if b = strings.ToLower(strings.TrimSpace(b)); b != "" && (host == b || strings.HasSuffix(host, "."+b)) {
			return Verdict{Malicious, "Your organization blocks " + b + "."}
		}
	}
	c.mu.RLock()
	feed, bad := c.urls[normalize(u)]
	if !bad {
		for h := host; h != ""; {
			if feed, bad = c.hosts[h]; bad {
				break
			}
			_, rest, ok := strings.Cut(h, ".")
			if !ok || !strings.Contains(rest, ".") {
				break
			}
			h = rest
		}
	}
	c.mu.RUnlock()
	if bad {
		return Verdict{Malicious, fmt.Sprintf("%s lists this link as malware or phishing.", feed)}
	}
	switch {
	case u.User != nil:
		return Verdict{Suspicious, "The address hides its real destination behind a user name (" + u.User.Username() + "@)."}
	case net.ParseIP(host) != nil:
		return Verdict{Suspicious, "The link goes to a bare IP address instead of a named site."}
	case strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--"):
		return Verdict{Suspicious, "The site name uses look-alike international characters."}
	case u.Port() != "" && u.Port() != "80" && u.Port() != "443":
		return Verdict{Suspicious, "The link uses an unusual port (" + u.Port() + ")."}
	}
	return Verdict{Safe, ""}
}

// normalize makes equivalent URLs compare equal: lower-case scheme and
// host, no default port, no fragment, no trailing slash.
func normalize(u *url.URL) string {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if p := u.Port(); p != "" && !(u.Scheme == "http" && p == "80") && !(u.Scheme == "https" && p == "443") {
		host = net.JoinHostPort(host, p)
	}
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	s := strings.ToLower(u.Scheme) + "://" + host + path
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	return s
}

// Size is how many URLs and hosts are loaded.
func (c *Checker) Size() (urls, hosts int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.urls), len(c.hosts)
}

// Run loads cached feeds, then refreshes them every interval until ctx
// ends.
func (c *Checker) Run(ctx context.Context, every time.Duration) {
	c.load(ctx, true)
	c.Refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Refresh(ctx)
		}
	}
}

// Refresh downloads every feed. A feed that fails keeps its last copy.
func (c *Checker) Refresh(ctx context.Context) {
	for _, f := range c.Feeds {
		if err := c.fetch(ctx, f); err != nil {
			c.log().Warn("safe links feed", "feed", f.Name, "err", err)
		}
	}
	c.load(ctx, false)
}

func (c *Checker) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

func (c *Checker) cachePath(f Feed) string {
	sum := sha256.Sum256([]byte(f.URL))
	return filepath.Join(c.Dir, hex.EncodeToString(sum[:8])+".txt")
}

func (c *Checker) fetch(ctx context.Context, f Feed) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Talaria safe links")
	cl := c.Client
	if cl == nil {
		cl = http.DefaultClient
	}
	res, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return err
	}
	if c.Dir == "" {
		c.mu.Lock()
		if c.raw == nil {
			c.raw = map[string][]byte{}
		}
		c.raw[f.URL] = b
		c.mu.Unlock()
		return nil
	}
	if err := os.MkdirAll(c.Dir, 0o750); err != nil {
		return err
	}
	tmp := c.cachePath(f) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, c.cachePath(f))
}

// load rebuilds the lookup tables from the downloaded feeds.
func (c *Checker) load(ctx context.Context, startup bool) {
	urls, hosts := map[string]string{}, map[string]string{}
	for _, f := range c.Feeds {
		var b []byte
		if c.Dir == "" {
			c.mu.RLock()
			b = c.raw[f.URL]
			c.mu.RUnlock()
		} else {
			b, _ = os.ReadFile(c.cachePath(f))
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 64<<10), 64<<10)
		for sc.Scan() && ctx.Err() == nil {
			line := strings.TrimSpace(sc.Text())
			if line == "" || line[0] == '#' {
				continue
			}
			if f.Hosts {
				if fields := strings.Fields(line); len(fields) > 0 {
					// Also accepts hosts-file lines: "0.0.0.0 bad.example".
					h := fields[len(fields)-1]
					hosts[strings.TrimSuffix(strings.ToLower(h), ".")] = f.Name
				}
				continue
			}
			if u, err := url.Parse(line); err == nil && u.Host != "" {
				urls[normalize(u)] = f.Name
			}
		}
	}
	if startup && len(urls)+len(hosts) == 0 {
		return
	}
	c.mu.Lock()
	c.urls, c.hosts = urls, hosts
	c.mu.Unlock()
	c.log().Info("safe links feeds loaded", "urls", len(urls), "hosts", len(hosts))
}
