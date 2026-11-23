// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"io"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"

	"github.com/gsoultan/talaria/internal/store"
)

// Action is what delivery should do with a message after authentication.
type Action int

const (
	Accept Action = iota
	Quarantine
	Reject
)

// Verdict is the outcome of SPF, DKIM and DMARC checks.
type Verdict struct {
	Action Action
	Bits   int64  // store.Auth* bits
	Header string // Authentication-Results value
	Reason string
}

// Resolver is the DNS used by the checks; tests replace it.
type Resolver = spf.DNSResolver

// Checker runs sender authentication.
type Checker struct {
	Hostname string
	DNS      Resolver
	// Timeout bounds all DNS work for one message.
	Timeout time.Duration
}

// Envelope is what the SMTP session knows about a message.
type Envelope struct {
	RemoteIP net.IP // nil when unknown (HTTP ingest)
	Helo     string
	MailFrom string
}

// Check verifies msg (a re-readable source of the raw message).
func (c *Checker) Check(ctx context.Context, env Envelope, fromAddr string, open func() (io.ReadCloser, error)) Verdict {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dns := c.DNS
	if dns == nil {
		dns = net.DefaultResolver
	}
	lookup := func(name string) ([]string, error) { return dns.LookupTXT(ctx, name) }

	var v Verdict
	var results []authres.Result

	// SPF on the envelope sender (or HELO for bounces).
	spfRes := spf.None
	spfDomain := domainOf(env.MailFrom)
	if spfDomain == "" {
		spfDomain = strings.ToLower(env.Helo)
	}
	if env.RemoteIP != nil {
		sender := env.MailFrom
		if sender == "" {
			sender = "postmaster@" + env.Helo
		}
		spfRes, _ = spf.CheckHostWithSender(env.RemoteIP, env.Helo, sender, spf.WithContext(ctx), spf.WithResolver(dns))
		results = append(results, &authres.SPFResult{Value: authres.ResultValue(spfRes), From: env.MailFrom, Helo: env.Helo})
	}
	if spfRes == spf.Pass {
		v.Bits |= store.AuthSPFPass
	}

	// DKIM.
	var dkimPass []string
	if r, err := open(); err == nil {
		verifs, _ := dkim.VerifyWithOptions(r, &dkim.VerifyOptions{LookupTXT: lookup, MaxVerifications: 5})
		r.Close()
		for _, vr := range verifs {
			var val authres.ResultValue = authres.ResultPass
			switch {
			case vr.Err == nil:
				dkimPass = append(dkimPass, strings.ToLower(vr.Domain))
			case dkim.IsTempFail(vr.Err):
				val = authres.ResultTempError
			case dkim.IsPermFail(vr.Err):
				val = authres.ResultPermError
			default:
				val = authres.ResultFail
			}
			results = append(results, &authres.DKIMResult{Value: val, Domain: vr.Domain, Identifier: vr.Identifier})
		}
		if len(verifs) == 0 {
			results = append(results, &authres.DKIMResult{Value: authres.ResultNone})
		}
	}
	if len(dkimPass) > 0 {
		v.Bits |= store.AuthDKIMPass
	}

	// DMARC on the From header domain.
	fromDomain := domainOf(fromAddr)
	if fromDomain != "" {
		rec, err := dmarc.LookupWithOptions(fromDomain, &dmarc.LookupOptions{LookupTXT: lookup})
		switch {
		case err == nil:
			aligned := false
			for _, d := range dkimPass {
				if align(d, fromDomain, rec.DKIMAlignment) {
					aligned = true
				}
			}
			if spfRes == spf.Pass && align(spfDomain, fromDomain, rec.SPFAlignment) {
				aligned = true
			}
			if aligned {
				v.Bits |= store.AuthDMARCPass
				results = append(results, &authres.DMARCResult{Value: authres.ResultPass, From: fromDomain})
			} else {
				results = append(results, &authres.DMARCResult{Value: authres.ResultFail, From: fromDomain})
				policy := rec.Policy
				if orgDomain(fromDomain) != fromDomain && rec.SubdomainPolicy != "" {
					policy = rec.SubdomainPolicy
				}
				switch policy {
				case dmarc.PolicyReject:
					v.Action, v.Reason = Reject, "DMARC policy of "+fromDomain+" rejects this message"
				case dmarc.PolicyQuarantine:
					v.Action, v.Reason = Quarantine, "DMARC quarantine"
				}
				if v.Action != Accept && rec.Percent != nil && *rec.Percent < 100 {
					// Sampled policy: be lenient and quarantine instead of rejecting.
					v.Action = Quarantine
				}
			}
		case dmarc.IsTempFail(err):
			results = append(results, &authres.DMARCResult{Value: authres.ResultTempError, From: fromDomain})
		default:
			results = append(results, &authres.DMARCResult{Value: authres.ResultNone, From: fromDomain})
		}
	}
	if v.Action == Accept && spfRes == spf.Fail && v.Bits&store.AuthDKIMPass == 0 {
		v.Action, v.Reason = Quarantine, "SPF fail"
	}
	v.Header = authres.Format(c.Hostname, results)
	return v
}

func domainOf(addr string) string {
	addr = strings.Trim(addr, "<> ")
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(addr[i+1:], "."))
}

func orgDomain(d string) string {
	o, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return o
}

func align(a, b string, mode dmarc.AlignmentMode) bool {
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(a, b)
	}
	return strings.EqualFold(orgDomain(a), orgDomain(b))
}
