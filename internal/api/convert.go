// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"errors"
	"log/slog"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/internal/store"
)

func userToProto(u store.User) *talariav1.User {
	return &talariav1.User{
		Id: u.ID, Email: u.Address(), DisplayName: u.DisplayName, Role: roleToProto(u.Role),
		TenantId: u.TenantID, QuotaBytes: u.QuotaBytes, UsedBytes: u.UsedBytes, Suspended: u.Suspended, CreatedAt: u.CreatedAt,
	}
}

func roleToProto(r store.Role) talariav1.Role {
	switch r {
	case store.RolePlatformAdmin:
		return talariav1.Role_ROLE_PLATFORM_ADMIN
	case store.RoleTenantAdmin:
		return talariav1.Role_ROLE_TENANT_ADMIN
	}
	return talariav1.Role_ROLE_USER
}

func roleFromProto(r talariav1.Role) store.Role {
	switch r {
	case talariav1.Role_ROLE_PLATFORM_ADMIN:
		return store.RolePlatformAdmin
	case talariav1.Role_ROLE_TENANT_ADMIN:
		return store.RoleTenantAdmin
	}
	return store.RoleUser
}

func summaryToProto(m store.Message) *talariav1.MessageSummary {
	return &talariav1.MessageSummary{
		Id: m.ID, MailboxId: m.MailboxID, ThreadId: m.ThreadID, Date: m.InternalDate, SentDate: m.SentDate, Size: m.Size,
		Subject: m.Subject, FromName: m.FromName, FromAddr: m.FromAddr, To: m.To, Cc: m.Cc, Preview: m.Preview,
		Seen: m.Flags&store.FlagSeen != 0, Flagged: m.Flags&store.FlagFlagged != 0, Answered: m.Flags&store.FlagAnswered != 0,
		Draft: m.Flags&store.FlagDraft != 0, HasAttachments: m.HasAttachments,
		SpfPass: m.Auth&store.AuthSPFPass != 0, DkimPass: m.Auth&store.AuthDKIMPass != 0, DmarcPass: m.Auth&store.AuthDMARCPass != 0,
		Modseq: m.ModSeq,
	}
}

func summaries(ms []store.Message) []*talariav1.MessageSummary {
	out := make([]*talariav1.MessageSummary, len(ms))
	for i, m := range ms {
		out[i] = summaryToProto(m)
	}
	return out
}

func flagFromProto(f talariav1.Flag) store.Flag {
	switch f {
	case talariav1.Flag_FLAG_SEEN:
		return store.FlagSeen
	case talariav1.Flag_FLAG_ANSWERED:
		return store.FlagAnswered
	case talariav1.Flag_FLAG_FLAGGED:
		return store.FlagFlagged
	case talariav1.Flag_FLAG_DELETED:
		return store.FlagDeleted
	case talariav1.Flag_FLAG_DRAFT:
		return store.FlagDraft
	}
	return 0
}

// storeErr maps store errors to Connect codes without leaking internals.
func storeErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, store.ErrExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, store.ErrQuotaExceeded), errors.Is(err, store.ErrSeatLimit):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, store.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return internal(err)
}

func internal(err error) error {
	slog.Error("internal error", "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}
