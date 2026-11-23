// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package usecase carries out the webmail API: it checks who may do what,
// then works through the mail store, the blob store and the outbound queue.
// It knows no transport: the caller arrives in the context, and anything
// that belongs to HTTP (the session cookie, the client address) comes
// through the ports declared here.
package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/gsoultan/kakarot"
	"github.com/gsoultan/kakarot/auth"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

// Caller is the signed-in user of a request, with the session token that
// identified them.
type Caller struct {
	User  store.User
	Token string
}

// CallerFrom returns the signed-in user. The transport demands one before
// any usecase that calls it runs.
func CallerFrom(ctx context.Context) Caller {
	c, _ := auth.From[Caller](ctx)
	return c
}

func userOf(ctx context.Context) store.User { return CallerFrom(ctx).User }

// Cookies sets and clears the session cookie on the current response.
type Cookies interface {
	SetSession(ctx context.Context, token string, maxAge time.Duration, persistent bool)
	ClearSession(ctx context.Context)
}

// Uploads holds files attached to messages being written.
type Uploads interface {
	// Read returns an upload of userID, or a CodeNotFound error when it does
	// not exist or has expired.
	Read(ctx context.Context, userID int64, id string) (domain.Upload, []byte, error)
}

// ClientIP returns the address of the client behind the request.
type ClientIP func(ctx context.Context) string

func internal(err error) error { return kakarot.E(kakarot.CodeInternal, "internal error", err) }

// storeErr maps store errors to API errors without leaking internals.
func storeErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return kakarot.E(kakarot.CodeNotFound, "not found", err)
	case errors.Is(err, store.ErrExists):
		return kakarot.E(kakarot.CodeConflict, "already exists", err)
	case errors.Is(err, store.ErrQuotaExceeded):
		return kakarot.E(domain.CodeLimit, "mailbox is full", err)
	case errors.Is(err, store.ErrSeatLimit):
		return kakarot.E(domain.CodeLimit, "the tenant has no free seats", err)
	case errors.Is(err, store.ErrSendLimit):
		return kakarot.E(domain.CodeLimit, "daily sending limit reached", err)
	case errors.Is(err, store.ErrInvalid):
		return kakarot.E(kakarot.CodeInvalid, err.Error(), err)
	case errors.Is(err, mail.ErrTooLarge):
		return kakarot.E(kakarot.CodeInvalid, "message is too large", err)
	case errors.Is(err, outbound.ErrSenderNotAllowed):
		return kakarot.E(kakarot.CodeForbidden, err.Error(), err)
	}
	return internal(err)
}

func forbidden(msg string) error { return kakarot.E(kakarot.CodeForbidden, msg, nil) }

func conflict(msg string) error { return kakarot.E(kakarot.CodeConflict, msg, nil) }

func roleOf(r store.Role) domain.Role {
	switch r {
	case store.RolePlatformAdmin:
		return domain.RolePlatformAdmin
	case store.RoleTenantAdmin:
		return domain.RoleTenantAdmin
	}
	return domain.RoleUser
}

func storeRole(r domain.Role) store.Role {
	switch r {
	case domain.RolePlatformAdmin:
		return store.RolePlatformAdmin
	case domain.RoleTenantAdmin:
		return store.RoleTenantAdmin
	}
	return store.RoleUser
}

func userDTO(u store.User) domain.User {
	return domain.User{
		ID: u.ID, Email: u.Address(), DisplayName: u.DisplayName, Role: roleOf(u.Role),
		TenantID: u.TenantID, QuotaBytes: u.QuotaBytes, UsedBytes: u.UsedBytes, Suspended: u.Suspended, CreatedAt: u.CreatedAt,
	}
}

func summary(m store.Message) domain.MessageSummary {
	return domain.MessageSummary{
		ID: m.ID, MailboxID: m.MailboxID, ThreadID: m.ThreadID, Date: m.InternalDate, SentDate: m.SentDate, Size: m.Size,
		Subject: m.Subject, FromName: m.FromName, FromAddr: m.FromAddr, To: m.To, Cc: m.Cc, Preview: m.Preview,
		Seen: m.Flags&store.FlagSeen != 0, Flagged: m.Flags&store.FlagFlagged != 0, Answered: m.Flags&store.FlagAnswered != 0,
		Draft: m.Flags&store.FlagDraft != 0, HasAttachments: m.HasAttachments,
		SPFPass: m.Auth&store.AuthSPFPass != 0, DKIMPass: m.Auth&store.AuthDKIMPass != 0, DMARCPass: m.Auth&store.AuthDMARCPass != 0,
		ModSeq: m.ModSeq,
	}
}

func summaries(ms []store.Message) []domain.MessageSummary {
	out := make([]domain.MessageSummary, len(ms))
	for i, m := range ms {
		out[i] = summary(m)
	}
	return out
}

// list returns s, or an empty slice for nil, so JSON lists are never null.
func list[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
