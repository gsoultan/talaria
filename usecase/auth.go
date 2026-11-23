// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/store"
)

const (
	sessionTTL  = 12 * time.Hour
	rememberTTL = 30 * 24 * time.Hour
	loginLimit  = 10 // failures per window per address; three times that per IP
	loginWindow = 15 * time.Minute
)

// Build information, set with -ldflags at build time.
var (
	Version = "dev"
	Commit  = "unknown"
)

// Auth signs users in and out and serves the account endpoints.
type Auth struct {
	Store   *store.Store
	Cookies Cookies
	IP      ClientIP

	byIP    *auth.Limiter
	byEmail *auth.Limiter
}

// NewAuth returns the auth usecases.
func NewAuth(st *store.Store, cookies Cookies, ip ClientIP) *Auth {
	return &Auth{Store: st, Cookies: cookies, IP: ip,
		byIP: auth.NewLimiter(loginLimit*3, loginWindow), byEmail: auth.NewLimiter(loginLimit, loginWindow)}
}

// Resolve turns a session token into the caller, for the transport.
func (a *Auth) Resolve(ctx context.Context, token string) (Caller, error) {
	if token == "" {
		return Caller{}, kakarot.E(kakarot.CodeUnauthorized, "sign in required", nil)
	}
	u, err := a.Store.SessionUser(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return Caller{}, kakarot.E(kakarot.CodeUnauthorized, "sign in required", nil)
	}
	if err != nil {
		return Caller{}, internal(err)
	}
	if u.Suspended {
		return Caller{}, forbidden("account suspended")
	}
	return Caller{User: u, Token: token}, nil
}

var errBadLogin = kakarot.E(kakarot.CodeUnauthorized, "wrong email or password", nil)

// Login checks the password and starts a session.
func (a *Auth) Login(ctx context.Context, in domain.Login) (domain.Session, error) {
	ip := a.IP(ctx)
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !a.byIP.Allowed(ip) || !a.byEmail.Allowed(email) {
		return domain.Session{}, kakarot.E(domain.CodeRateLimited, "too many attempts, try again in a few minutes", nil)
	}
	u, err := a.Store.UserByAddress(ctx, email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return domain.Session{}, internal(err)
	}
	if !auth.CheckPassword(u.PasswordHash, in.Password) {
		a.byIP.Fail(ip)
		a.byEmail.Fail(email)
		return domain.Session{}, errBadLogin
	}
	if u.Suspended {
		return domain.Session{}, forbidden("account suspended")
	}
	a.byEmail.Reset(email)
	ttl := sessionTTL
	if in.Remember {
		ttl = rememberTTL
	}
	tok := auth.NewToken()
	if err := a.Store.CreateSession(ctx, tok, u.ID, int64(ttl/time.Second), in.UserAgent, ip); err != nil {
		return domain.Session{}, internal(err)
	}
	a.Cookies.SetSession(ctx, tok, ttl, in.Remember)
	return domain.Session{User: a.withTenant(ctx, u)}, nil
}

// Logout ends the current session.
func (a *Auth) Logout(ctx context.Context, _ domain.Logout) (domain.Done, error) {
	if tok := CallerFrom(ctx).Token; tok != "" {
		if err := a.Store.DeleteSession(ctx, tok); err != nil {
			return domain.Done{}, internal(err)
		}
	}
	a.Cookies.ClearSession(ctx)
	return domain.Done{}, nil
}

// Me returns the signed-in user.
func (a *Auth) Me(ctx context.Context, _ domain.GetMe) (domain.Session, error) {
	return domain.Session{User: a.withTenant(ctx, userOf(ctx))}, nil
}

// ChangePassword replaces the password after checking the current one.
func (a *Auth) ChangePassword(ctx context.Context, in domain.ChangePassword) (domain.Done, error) {
	u := userOf(ctx)
	if !auth.CheckPassword(u.PasswordHash, in.CurrentPassword) {
		return domain.Done{}, forbidden("current password is wrong")
	}
	hash, err := auth.HashPassword(in.NewPassword)
	if err != nil {
		return domain.Done{}, kakarot.Invalid(err.Error(), map[string]string{"newPassword": err.Error()})
	}
	// SetPassword signs out every session, including this one.
	if err := a.Store.SetPassword(ctx, u.ID, hash); err != nil {
		return domain.Done{}, storeErr(err)
	}
	a.Cookies.ClearSession(ctx)
	return domain.Done{}, nil
}

func (a *Auth) withTenant(ctx context.Context, u store.User) domain.User {
	d := userDTO(u)
	if t, err := a.Store.Tenant(ctx, u.TenantID); err == nil {
		d.TenantName = t.DisplayName
	}
	return d
}

// System answers public questions about the server.
type System struct{}

// GetInfo reports the version only; memory and uptime are in the admin
// stats, for platform admins.
func (System) GetInfo(context.Context, domain.GetInfo) (domain.Info, error) {
	return domain.Info{Version: Version, Commit: Commit, GoVersion: runtime.Version()}, nil
}
