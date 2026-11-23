// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"net/http"
	"time"

	"github.com/gsoultan/kakarot/auth"

	"github.com/gsoultan/talaria/usecase"
)

// CookieName holds the session token.
const CookieName = "talaria_session"

type writerKey struct{}

// sessions is transport middleware: it resolves the session cookie into a
// usecase.Caller, and keeps the response writer so Login and Logout can set
// the cookie.
func sessions(a *usecase.Auth) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), writerKey{}, w)
			if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
				if caller, err := a.Resolve(ctx, c.Value); err == nil {
					ctx = auth.With(ctx, caller)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// cookies implements usecase.Cookies on the current response.
type cookies struct{}

func (cookies) set(ctx context.Context, c *http.Cookie) {
	if w, ok := ctx.Value(writerKey{}).(http.ResponseWriter); ok {
		http.SetCookie(w, c)
	}
}

func (k cookies) SetSession(ctx context.Context, token string, maxAge time.Duration, persistent bool) {
	c := &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
	if persistent {
		c.MaxAge = int(maxAge / time.Second)
	}
	k.set(ctx, c)
}

func (k cookies) ClearSession(ctx context.Context) {
	k.set(ctx, &http.Cookie{Name: CookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}
