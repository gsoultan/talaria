// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/clientip"
	"github.com/gsoultan/talaria/internal/store"
)

// CookieName holds the session token.
const CookieName = "talaria_session"

const (
	sessionTTL   = 12 * time.Hour
	rememberTTL  = 30 * 24 * time.Hour
	loginLimit   = 10 // failures per window per IP and per address
	loginWindow  = 15 * time.Minute
	publicPrefix = "/talaria.v1.SystemService/"
)

// Auth resolves sessions and guards every procedure except Login and the
// public system endpoints.
type Auth struct {
	Store   *store.Store
	byIP    *auth.Limiter
	byEmail *auth.Limiter
}

// NewAuth returns an authenticator.
func NewAuth(st *store.Store) *Auth {
	return &Auth{Store: st, byIP: auth.NewLimiter(loginLimit*3, loginWindow), byEmail: auth.NewLimiter(loginLimit, loginWindow)}
}

type userKey struct{}

// UserFrom returns the authenticated user of a request.
func UserFrom(ctx context.Context) store.User {
	u, _ := ctx.Value(userKey{}).(store.User)
	return u
}

func sessionToken(h http.Header) string {
	for _, c := range (&http.Request{Header: h}).CookiesNamed(CookieName) {
		return c.Value
	}
	return ""
}

var errUnauthenticated = connect.NewError(connect.CodeUnauthenticated, errors.New("sign in required"))

// User resolves the session in h.
func (a *Auth) User(ctx context.Context, h http.Header) (store.User, error) {
	tok := sessionToken(h)
	if tok == "" {
		return store.User{}, errUnauthenticated
	}
	u, err := a.Store.SessionUser(ctx, tok)
	if errors.Is(err, store.ErrNotFound) {
		return u, errUnauthenticated
	}
	if err != nil {
		return u, internal(err)
	}
	if u.Suspended {
		return u, connect.NewError(connect.CodePermissionDenied, errors.New("account suspended"))
	}
	return u, nil
}

func public(procedure string) bool {
	return strings.HasPrefix(procedure, publicPrefix) || procedure == talariav1connect.AuthServiceLoginProcedure
}

// WrapUnary implements connect.Interceptor.
func (a *Auth) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if public(req.Spec().Procedure) {
			return next(ctx, req)
		}
		u, err := a.User(ctx, req.Header())
		if err != nil {
			return nil, err
		}
		return next(context.WithValue(ctx, userKey{}, u), req)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (a *Auth) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (a *Auth) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		u, err := a.User(ctx, conn.RequestHeader())
		if err != nil {
			return err
		}
		return next(context.WithValue(ctx, userKey{}, u), conn)
	}
}

// AuthServer implements talaria.v1.AuthService.
type AuthServer struct{ a *Auth }

var _ talariav1connect.AuthServiceHandler = (*AuthServer)(nil)

// NewAuthServer returns the auth service.
func NewAuthServer(a *Auth) *AuthServer { return &AuthServer{a: a} }

var errBadLogin = connect.NewError(connect.CodeUnauthenticated, errors.New("wrong email or password"))

func (s *AuthServer) Login(ctx context.Context, req *connect.Request[talariav1.LoginRequest]) (*connect.Response[talariav1.LoginResponse], error) {
	ip := clientip.From(ctx).String()
	email := strings.ToLower(strings.TrimSpace(req.Msg.Email))
	if !s.a.byIP.Allowed(ip) || !s.a.byEmail.Allowed(email) {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many attempts, try again in a few minutes"))
	}
	u, err := s.a.Store.UserByAddress(ctx, email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, internal(err)
	}
	if !auth.CheckPassword(u.PasswordHash, req.Msg.Password) {
		s.a.byIP.Fail(ip)
		s.a.byEmail.Fail(email)
		return nil, errBadLogin
	}
	if u.Suspended {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("account suspended"))
	}
	s.a.byEmail.Reset(email)
	ttl := sessionTTL
	if req.Msg.Remember {
		ttl = rememberTTL
	}
	tok := auth.NewToken()
	if err := s.a.Store.CreateSession(ctx, tok, u.ID, int64(ttl/time.Second), req.Header().Get("User-Agent"), ip); err != nil {
		return nil, internal(err)
	}
	res := connect.NewResponse(&talariav1.LoginResponse{User: s.userProto(ctx, u)})
	c := &http.Cookie{Name: CookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
	if req.Msg.Remember {
		c.MaxAge = int(ttl / time.Second)
	}
	res.Header().Add("Set-Cookie", c.String())
	return res, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *connect.Request[talariav1.LogoutRequest]) (*connect.Response[talariav1.LogoutResponse], error) {
	if tok := sessionToken(req.Header()); tok != "" {
		if err := s.a.Store.DeleteSession(ctx, tok); err != nil {
			return nil, internal(err)
		}
	}
	res := connect.NewResponse(&talariav1.LogoutResponse{})
	res.Header().Add("Set-Cookie", (&http.Cookie{Name: CookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}).String())
	return res, nil
}

func (s *AuthServer) Me(ctx context.Context, _ *connect.Request[talariav1.MeRequest]) (*connect.Response[talariav1.MeResponse], error) {
	return connect.NewResponse(&talariav1.MeResponse{User: s.userProto(ctx, UserFrom(ctx))}), nil
}

func (s *AuthServer) ChangePassword(ctx context.Context, req *connect.Request[talariav1.ChangePasswordRequest]) (*connect.Response[talariav1.ChangePasswordResponse], error) {
	u := UserFrom(ctx)
	if !auth.CheckPassword(u.PasswordHash, req.Msg.CurrentPassword) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("current password is wrong"))
	}
	hash, err := auth.HashPassword(req.Msg.NewPassword)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	// SetPassword signs out every session, including this one.
	if err := s.a.Store.SetPassword(ctx, u.ID, hash); err != nil {
		return nil, internal(err)
	}
	return connect.NewResponse(&talariav1.ChangePasswordResponse{}), nil
}

func (s *AuthServer) userProto(ctx context.Context, u store.User) *talariav1.User {
	p := userToProto(u)
	if t, err := s.a.Store.Tenant(ctx, u.TenantID); err == nil {
		p.TenantName = t.DisplayName
	}
	return p
}
