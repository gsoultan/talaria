// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package service is the webmail API's contract. kakarot gen reads these
// interfaces and writes the endpoint layer and the HTTP bindings; the
// OpenAPI document and the web client's types follow from them.
package service

//go:generate ../scripts/kakarot.sh gen

import (
	"context"
	"iter"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/usecase"
)

// SystemService answers without a sign-in.
//
//kakarot:service system
type SystemService interface {
	//kakarot:http GET /api/v1/info
	GetInfo(ctx context.Context, in domain.GetInfo) (domain.Info, error)
}

// SessionService signs in. It needs no session.
//
//kakarot:service session
type SessionService interface {
	//kakarot:http POST /api/v1/session
	Login(ctx context.Context, in domain.Login) (domain.Session, error)
}

// AccountService is the signed-in user's own account.
//
//kakarot:service account
type AccountService interface {
	//kakarot:http GET /api/v1/me
	Me(ctx context.Context, in domain.GetMe) (domain.Session, error)
	//kakarot:http DELETE /api/v1/session
	Logout(ctx context.Context, in domain.Logout) (domain.Done, error)
	//kakarot:http POST /api/v1/me/password
	ChangePassword(ctx context.Context, in domain.ChangePassword) (domain.Done, error)
}

// MailService reads, organizes and sends the signed-in user's mail.
//
//kakarot:service mail
type MailService interface {
	//kakarot:http GET /api/v1/mailboxes
	ListMailboxes(ctx context.Context, in domain.ListMailboxes) (domain.Mailboxes, error)
	//kakarot:http POST /api/v1/mailboxes
	CreateMailbox(ctx context.Context, in domain.CreateMailbox) (domain.MailboxCreated, error)
	//kakarot:http PATCH /api/v1/mailboxes/{id}
	RenameMailbox(ctx context.Context, in domain.RenameMailbox) (domain.Done, error)
	//kakarot:http DELETE /api/v1/mailboxes/{id}
	DeleteMailbox(ctx context.Context, in domain.DeleteMailbox) (domain.Done, error)
	//kakarot:http GET /api/v1/mailboxes/{mailboxId}/messages
	ListMessages(ctx context.Context, in domain.ListMessages) (domain.MessagePage, error)
	//kakarot:http GET /api/v1/search
	Search(ctx context.Context, in domain.Search) (domain.Messages, error)
	//kakarot:http GET /api/v1/messages/{id}
	GetMessage(ctx context.Context, in domain.GetMessage) (domain.Message, error)
	//kakarot:http GET /api/v1/messages/{id}/parts/{part}/preview
	GetAttachmentPreview(ctx context.Context, in domain.GetAttachmentPreview) (domain.AttachmentPreview, error)
	//kakarot:http GET /api/v1/threads/{threadId}
	GetThread(ctx context.Context, in domain.GetThread) (domain.Messages, error)
	//kakarot:http POST /api/v1/messages/flags
	UpdateFlags(ctx context.Context, in domain.UpdateFlags) (domain.Done, error)
	//kakarot:http POST /api/v1/messages/move
	MoveMessages(ctx context.Context, in domain.MoveMessages) (domain.Done, error)
	//kakarot:http POST /api/v1/messages/delete
	DeleteMessages(ctx context.Context, in domain.DeleteMessages) (domain.Done, error)
	//kakarot:http GET /api/v1/identities
	ListIdentities(ctx context.Context, in domain.ListIdentities) (domain.Identities, error)
	//kakarot:http POST /api/v1/messages/send
	SendMessage(ctx context.Context, in domain.SendMessage) (domain.Sent, error)
	//kakarot:http POST /api/v1/drafts
	SaveDraft(ctx context.Context, in domain.SaveDraft) (domain.DraftSaved, error)
	//kakarot:http GET /api/v1/quarantine
	ListQuarantine(ctx context.Context, in domain.ListQuarantine) (domain.HeldMessages, error)
	//kakarot:http POST /api/v1/quarantine/{id}/release
	ReleaseQuarantined(ctx context.Context, in domain.ReleaseQuarantined) (domain.Done, error)
	//kakarot:http DELETE /api/v1/quarantine/{id}
	DeleteQuarantined(ctx context.Context, in domain.DeleteQuarantined) (domain.Done, error)
	//kakarot:http GET /api/v1/mail-settings
	GetMailSettings(ctx context.Context, in domain.GetMailSettings) (domain.MailSettings, error)
	// Watch is a server-sent event stream of folder changes.
	//
	//kakarot:http GET /api/v1/watch
	Watch(ctx context.Context, in domain.Watch) iter.Seq2[domain.Change, error]
}

// AdminService manages tenants, domains, users, aliases and the queue.
//
//kakarot:service admin
type AdminService interface {
	//kakarot:http GET /api/v1/admin/tenants
	ListTenants(ctx context.Context, in domain.ListTenants) (domain.Tenants, error)
	//kakarot:http POST /api/v1/admin/tenants
	CreateTenant(ctx context.Context, in domain.CreateTenant) (domain.TenantCreated, error)
	//kakarot:http PUT /api/v1/admin/tenants/{id}
	UpdateTenant(ctx context.Context, in domain.UpdateTenant) (domain.Done, error)
	//kakarot:http DELETE /api/v1/admin/tenants/{id}
	DeleteTenant(ctx context.Context, in domain.DeleteTenant) (domain.Done, error)
	//kakarot:http GET /api/v1/admin/domains
	ListDomains(ctx context.Context, in domain.ListDomains) (domain.Domains, error)
	//kakarot:http POST /api/v1/admin/domains
	CreateDomain(ctx context.Context, in domain.CreateDomain) (domain.DomainCreated, error)
	//kakarot:http DELETE /api/v1/admin/domains/{id}
	DeleteDomain(ctx context.Context, in domain.DeleteDomain) (domain.Done, error)
	//kakarot:http GET /api/v1/admin/domains/{domainId}/setup
	GetDomainSetup(ctx context.Context, in domain.GetDomainSetup) (domain.DomainSetup, error)
	//kakarot:http POST /api/v1/admin/domains/{domainId}/dkim
	RotateDKIM(ctx context.Context, in domain.RotateDKIM) (domain.DKIMRotated, error)
	//kakarot:http GET /api/v1/admin/queue
	ListQueue(ctx context.Context, in domain.ListQueue) (domain.Queue, error)
	//kakarot:http POST /api/v1/admin/queue/retry
	RetryQueue(ctx context.Context, in domain.RetryQueue) (domain.Done, error)
	//kakarot:http POST /api/v1/admin/queue/cancel
	CancelQueue(ctx context.Context, in domain.CancelQueue) (domain.Done, error)
	//kakarot:http GET /api/v1/admin/stats
	GetStats(ctx context.Context, in domain.GetStats) (domain.Stats, error)
	//kakarot:http GET /api/v1/admin/users
	ListUsers(ctx context.Context, in domain.ListUsers) (domain.Users, error)
	//kakarot:http POST /api/v1/admin/users
	CreateUser(ctx context.Context, in domain.CreateUser) (domain.UserCreated, error)
	//kakarot:http PUT /api/v1/admin/users/{id}
	UpdateUser(ctx context.Context, in domain.UpdateUser) (domain.Done, error)
	//kakarot:http POST /api/v1/admin/users/{id}/password
	SetUserPassword(ctx context.Context, in domain.SetUserPassword) (domain.Done, error)
	//kakarot:http DELETE /api/v1/admin/users/{id}
	DeleteUser(ctx context.Context, in domain.DeleteUser) (domain.Done, error)
	//kakarot:http GET /api/v1/admin/aliases
	ListAliases(ctx context.Context, in domain.ListAliases) (domain.Aliases, error)
	//kakarot:http POST /api/v1/admin/aliases
	CreateAlias(ctx context.Context, in domain.CreateAlias) (domain.AliasCreated, error)
	//kakarot:http DELETE /api/v1/admin/aliases/{id}
	DeleteAlias(ctx context.Context, in domain.DeleteAlias) (domain.Done, error)
	//kakarot:http GET /api/v1/admin/sender-rules
	ListSenderRules(ctx context.Context, in domain.ListSenderRules) (domain.SenderRules, error)
	//kakarot:http POST /api/v1/admin/sender-rules
	CreateSenderRule(ctx context.Context, in domain.CreateSenderRule) (domain.SenderRuleCreated, error)
	//kakarot:http DELETE /api/v1/admin/sender-rules/{id}
	DeleteSenderRule(ctx context.Context, in domain.DeleteSenderRule) (domain.Done, error)
	//kakarot:http GET /api/v1/admin/dlp-policies
	ListDLPPolicies(ctx context.Context, in domain.ListDLPPolicies) (domain.DLPPolicies, error)
	//kakarot:http POST /api/v1/admin/dlp-policies
	SaveDLPPolicy(ctx context.Context, in domain.SaveDLPPolicy) (domain.DLPPolicySaved, error)
	//kakarot:http DELETE /api/v1/admin/dlp-policies/{id}
	DeleteDLPPolicy(ctx context.Context, in domain.DeleteDLPPolicy) (domain.Done, error)
	//kakarot:http POST /api/v1/admin/dlp-policies/test
	TestDLP(ctx context.Context, in domain.TestDLP) (domain.DLPTestResult, error)
	//kakarot:http GET /api/v1/admin/quarantine
	ListHeldMail(ctx context.Context, in domain.ListHeldMail) (domain.HeldMessages, error)
	//kakarot:http GET /api/v1/admin/quarantine/{id}
	GetHeldMail(ctx context.Context, in domain.GetHeldMail) (domain.HeldMailDetail, error)
	//kakarot:http POST /api/v1/admin/quarantine/{id}/release
	ReleaseHeldMail(ctx context.Context, in domain.ReleaseHeldMail) (domain.Done, error)
	//kakarot:http DELETE /api/v1/admin/quarantine/{id}
	DeleteHeldMail(ctx context.Context, in domain.DeleteHeldMail) (domain.Done, error)
}

// The usecases implement the contract; the compiler checks it here.
var (
	_ SystemService  = usecase.System{}
	_ SessionService = (*usecase.Auth)(nil)
	_ AccountService = (*usecase.Auth)(nil)
	_ MailService    = (*usecase.Mail)(nil)
	_ AdminService   = (*usecase.Admin)(nil)
)
