// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package audit records who did what: sign-ins, admin changes, admin access
// to mail, and policy hits. Entries go to the append-only audit_log table.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gsoultan/talaria/internal/store"
)

// Actions.
const (
	SignIn        = "sign_in"
	SignInFailed  = "sign_in_failed"
	SignOut       = "sign_out"
	PasswordSet   = "password_change"
	PolicyDLP     = "policy.dlp"
	PolicyLink    = "policy.link"
	QuarantineOut = "quarantine.release" // a user released held mail
)

// Recorder writes entries. A nil Recorder records nothing.
type Recorder struct {
	Store *store.Store
	Log   *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time
}

// Record appends an entry, logging (not returning) a failure: the action
// it describes has already happened.
func (r *Recorder) Record(ctx context.Context, e store.AuditEntry) {
	if r == nil || r.Store == nil {
		return
	}
	if err := r.Store.Audit(context.WithoutCancel(ctx), e); err != nil && r.Log != nil {
		r.Log.Error("audit", "action", e.Action, "err", err)
	}
}

// Detail encodes fields as the entry's JSON detail.
func Detail(fields map[string]any) string {
	if len(fields) == 0 {
		return ""
	}
	b, _ := json.Marshal(fields)
	return string(b)
}

// recent reports whether key was seen within d, and marks it seen.
func (r *Recorder) recent(key string, d time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	if len(r.seen) > 50_000 { // forget old keys rather than grow
		for k, t := range r.seen {
			if now.Sub(t) > 24*time.Hour {
				delete(r.seen, k)
			}
		}
	}
	if t, ok := r.seen[key]; ok && now.Sub(t) < d {
		return true
	}
	r.seen[key] = now
	return false
}

// SignIn records a sign-in attempt. proto is web, imap, pop3 or smtp. u
// is the account the address belongs to (zero when there is none).
//
// Mail apps sign in again every few minutes, so a success over IMAP, POP3
// or SMTP is recorded once a day per account, address and protocol; a
// failure at most once a minute per address, IP and protocol.
func (r *Recorder) SignIn(ctx context.Context, proto, address string, u store.User, ip string, ok bool, reason string) {
	if r == nil {
		return
	}
	address = strings.ToLower(strings.TrimSpace(address))
	if len(address) > 200 {
		address = address[:200]
	}
	e := store.AuditEntry{TenantID: u.TenantID, ActorID: u.ID, Actor: address, IP: ip, Action: SignIn, Target: address,
		Detail: Detail(map[string]any{"via": proto})}
	if ok {
		if proto != "web" && r.recent("ok|"+proto+"|"+address+"|"+ip, 24*time.Hour) {
			return
		}
	} else {
		if r.recent("fail|"+proto+"|"+address+"|"+ip, time.Minute) {
			return
		}
		e.Action, e.Outcome = SignInFailed, reason
		if u.ID == 0 {
			// No such account: file it under the tenant that owns the
			// domain, if any, so its admins see attempts on their names.
			if _, dom, err := store.SplitAddress(address); err == nil {
				if d, err := r.Store.DomainByName(ctx, dom); err == nil {
					e.TenantID = d.TenantID
				}
			}
		}
	}
	r.Record(ctx, e)
}

// FailReason names why a password sign-in failed, for the log.
func FailReason(u store.User, passwordOK bool) string {
	switch {
	case u.ID == 0:
		return "unknown account"
	case !passwordOK:
		return "wrong password"
	case u.Suspended:
		return "account suspended"
	}
	return ""
}
