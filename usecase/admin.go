// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package usecase

import (
	"context"

	"github.com/gsoultan/kakarot"

	"github.com/gsoultan/talaria/domain"
	"github.com/gsoultan/talaria/internal/audit"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/blob"
	"github.com/gsoultan/talaria/internal/mail"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

// Admin manages tenants, domains, users, aliases and the outbound queue.
// Every call is scoped: tenant admins see and change only their own tenant,
// and only platform admins manage tenants or grant the platform admin role.
type Admin struct {
	Store   *store.Store
	Blobs   *blob.Store
	Deliver *mail.Deliverer
	// Quarantine is the held-mail policy.
	Quarantine QuarantinePolicy
	Keys       *outbound.Keys
	Hostname   string
	// Route describes where outbound mail goes, for the queue view.
	Route     string
	RelayHost string
	// Wake nudges the outbound queue after "retry now".
	Wake func()
	// Audit records exports of the audit log; IP names the caller's address.
	Audit *audit.Recorder
	IP    ClientIP
}

func (s *Admin) ip(ctx context.Context) string {
	if s.IP == nil {
		return ""
	}
	return s.IP(ctx)
}

var (
	errAdminOnly    = forbidden("admin access required")
	errPlatformOnly = forbidden("platform admin access required")
)

// scope returns the caller and the tenant they may act on.
func scope(ctx context.Context, tenantID int64) (store.User, int64, error) {
	u := userOf(ctx)
	if u.Role < store.RoleTenantAdmin {
		return u, 0, errAdminOnly
	}
	if tenantID == 0 {
		return u, u.TenantID, nil
	}
	if tenantID != u.TenantID && u.Role != store.RolePlatformAdmin {
		return u, 0, forbidden("not your tenant")
	}
	return u, tenantID, nil
}

func platform(ctx context.Context) error {
	if userOf(ctx).Role != store.RolePlatformAdmin {
		return errPlatformOnly
	}
	return nil
}

// target loads a user the caller may manage.
func (s *Admin) target(ctx context.Context, id int64) (store.User, error) {
	t, err := s.Store.User(ctx, id)
	if err != nil {
		return t, storeErr(err)
	}
	caller, _, err := scope(ctx, t.TenantID)
	if err != nil {
		return t, err
	}
	if t.Role == store.RolePlatformAdmin && caller.Role != store.RolePlatformAdmin {
		return t, errPlatformOnly
	}
	return t, nil
}

func tenantDTO(t store.Tenant) domain.Tenant {
	return domain.Tenant{ID: t.ID, Name: t.Name, DisplayName: t.DisplayName, SeatLimit: t.SeatLimit, QuotaBytes: t.QuotaBytes,
		DailySendLimit: t.DailySendLimit, Suspended: t.Suspended, CreatedAt: t.CreatedAt, Domains: t.Domains, Users: t.Users, UsedBytes: t.UsedBytes}
}

func domainDTO(d store.Domain) domain.Domain {
	return domain.Domain{ID: d.ID, TenantID: d.TenantID, Name: d.Name, CreatedAt: d.CreatedAt}
}

// ListTenants returns every tenant to platform admins, and their own to
// tenant admins.
func (s *Admin) ListTenants(ctx context.Context, _ domain.ListTenants) (domain.Tenants, error) {
	u, _, err := scope(ctx, 0)
	if err != nil {
		return domain.Tenants{}, err
	}
	all, err := s.Store.ListTenants(ctx)
	if err != nil {
		return domain.Tenants{}, storeErr(err)
	}
	out := domain.Tenants{Tenants: []domain.Tenant{}}
	for _, t := range all {
		if u.Role == store.RolePlatformAdmin || t.ID == u.TenantID {
			out.Tenants = append(out.Tenants, tenantDTO(t))
		}
	}
	return out, nil
}

// CreateTenant adds a tenant.
func (s *Admin) CreateTenant(ctx context.Context, in domain.CreateTenant) (domain.TenantCreated, error) {
	if err := platform(ctx); err != nil {
		return domain.TenantCreated{}, err
	}
	t, err := s.Store.CreateTenant(ctx, store.Tenant{Name: in.Name, DisplayName: in.DisplayName, SeatLimit: in.SeatLimit,
		QuotaBytes: in.QuotaBytes, DailySendLimit: in.DailySendLimit})
	if err != nil {
		return domain.TenantCreated{}, storeErr(err)
	}
	return domain.TenantCreated{Tenant: tenantDTO(t)}, nil
}

// UpdateTenant changes a tenant.
func (s *Admin) UpdateTenant(ctx context.Context, in domain.UpdateTenant) (domain.Done, error) {
	if err := platform(ctx); err != nil {
		return domain.Done{}, err
	}
	if in.Suspended && in.ID == userOf(ctx).TenantID {
		return domain.Done{}, conflict("you cannot suspend your own tenant")
	}
	err := s.Store.UpdateTenant(ctx, store.Tenant{ID: in.ID, DisplayName: in.DisplayName, SeatLimit: in.SeatLimit, QuotaBytes: in.QuotaBytes,
		DailySendLimit: in.DailySendLimit, Suspended: in.Suspended})
	return domain.Done{}, storeErr(err)
}

// DeleteTenant removes a tenant.
func (s *Admin) DeleteTenant(ctx context.Context, in domain.DeleteTenant) (domain.Done, error) {
	if err := platform(ctx); err != nil {
		return domain.Done{}, err
	}
	if in.ID == userOf(ctx).TenantID {
		return domain.Done{}, conflict("you cannot delete your own tenant")
	}
	return domain.Done{}, storeErr(s.Store.DeleteTenant(ctx, in.ID))
}

// ListDomains returns a tenant's domains.
func (s *Admin) ListDomains(ctx context.Context, in domain.ListDomains) (domain.Domains, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Domains{}, err
	}
	ds, err := s.Store.ListDomains(ctx, tid)
	if err != nil {
		return domain.Domains{}, storeErr(err)
	}
	out := domain.Domains{Domains: make([]domain.Domain, len(ds))}
	for i, d := range ds {
		out.Domains[i] = domainDTO(d)
	}
	return out, nil
}

// CreateDomain adds a domain.
func (s *Admin) CreateDomain(ctx context.Context, in domain.CreateDomain) (domain.DomainCreated, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.DomainCreated{}, err
	}
	d, err := s.Store.CreateDomain(ctx, tid, in.Name)
	if err != nil {
		return domain.DomainCreated{}, storeErr(err)
	}
	return domain.DomainCreated{Domain: domainDTO(d)}, nil
}

// DeleteDomain removes a domain.
func (s *Admin) DeleteDomain(ctx context.Context, in domain.DeleteDomain) (domain.Done, error) {
	u, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Done{}, err
	}
	if in.ID == u.DomainID {
		return domain.Done{}, conflict("you cannot delete the domain of your own account")
	}
	return domain.Done{}, storeErr(s.Store.DeleteDomain(ctx, tid, in.ID))
}

// ListUsers returns a tenant's users.
func (s *Admin) ListUsers(ctx context.Context, in domain.ListUsers) (domain.Users, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Users{}, err
	}
	us, err := s.Store.ListUsers(ctx, tid)
	if err != nil {
		return domain.Users{}, storeErr(err)
	}
	out := domain.Users{Users: make([]domain.User, len(us))}
	for i, u := range us {
		out.Users[i] = userDTO(u)
	}
	return out, nil
}

func badPassword(err error) error {
	return kakarot.Invalid(err.Error(), map[string]string{"password": err.Error()})
}

// CreateUser adds a user.
func (s *Admin) CreateUser(ctx context.Context, in domain.CreateUser) (domain.UserCreated, error) {
	caller, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.UserCreated{}, err
	}
	role := storeRole(in.Role)
	if role == store.RolePlatformAdmin && caller.Role != store.RolePlatformAdmin {
		return domain.UserCreated{}, errPlatformOnly
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return domain.UserCreated{}, badPassword(err)
	}
	u, err := s.Store.CreateUser(ctx, tid, in.Email, in.DisplayName, hash, role, in.QuotaBytes)
	if err != nil {
		return domain.UserCreated{}, storeErr(err)
	}
	return domain.UserCreated{User: userDTO(u)}, nil
}

// UpdateUser changes a user.
func (s *Admin) UpdateUser(ctx context.Context, in domain.UpdateUser) (domain.Done, error) {
	t, err := s.target(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	caller := userOf(ctx)
	role := storeRole(in.Role)
	if role == store.RolePlatformAdmin && caller.Role != store.RolePlatformAdmin {
		return domain.Done{}, errPlatformOnly
	}
	if t.ID == caller.ID && (role < caller.Role || in.Suspended) {
		return domain.Done{}, conflict("you cannot demote or suspend yourself")
	}
	t.DisplayName, t.Role, t.QuotaBytes, t.Suspended = in.DisplayName, role, in.QuotaBytes, in.Suspended
	if err := s.Store.UpdateUser(ctx, t); err != nil {
		return domain.Done{}, storeErr(err)
	}
	if t.Suspended {
		// Suspension signs the user out everywhere.
		s.Store.DeleteSessions(ctx, t.ID)
	}
	return domain.Done{}, nil
}

// SetUserPassword sets a user's password.
func (s *Admin) SetUserPassword(ctx context.Context, in domain.SetUserPassword) (domain.Done, error) {
	t, err := s.target(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return domain.Done{}, badPassword(err)
	}
	return domain.Done{}, storeErr(s.Store.SetPassword(ctx, t.ID, hash))
}

// DeleteUser removes a user.
func (s *Admin) DeleteUser(ctx context.Context, in domain.DeleteUser) (domain.Done, error) {
	t, err := s.target(ctx, in.ID)
	if err != nil {
		return domain.Done{}, err
	}
	if t.ID == userOf(ctx).ID {
		return domain.Done{}, conflict("you cannot delete yourself")
	}
	return domain.Done{}, storeErr(s.Store.DeleteUser(ctx, t.TenantID, t.ID))
}

// ListAliases returns a tenant's aliases.
func (s *Admin) ListAliases(ctx context.Context, in domain.ListAliases) (domain.Aliases, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Aliases{}, err
	}
	as, err := s.Store.ListAliases(ctx, tid, in.UserID)
	if err != nil {
		return domain.Aliases{}, storeErr(err)
	}
	out := domain.Aliases{Aliases: make([]domain.Alias, len(as))}
	for i, a := range as {
		out.Aliases[i] = domain.Alias{ID: a.ID, TenantID: tid, Address: a.Address, UserID: a.UserID}
	}
	return out, nil
}

// CreateAlias adds an alias.
func (s *Admin) CreateAlias(ctx context.Context, in domain.CreateAlias) (domain.AliasCreated, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.AliasCreated{}, err
	}
	a, err := s.Store.CreateAlias(ctx, tid, in.Address, in.UserID)
	if err != nil {
		return domain.AliasCreated{}, storeErr(err)
	}
	return domain.AliasCreated{Alias: domain.Alias{ID: a.ID, TenantID: tid, Address: a.Address, UserID: a.UserID}}, nil
}

// DeleteAlias removes an alias.
func (s *Admin) DeleteAlias(ctx context.Context, in domain.DeleteAlias) (domain.Done, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Done{}, err
	}
	return domain.Done{}, storeErr(s.Store.DeleteAlias(ctx, tid, in.ID))
}

func senderRuleOf(r store.SenderRule) domain.SenderRule {
	return domain.SenderRule{ID: r.ID, TenantID: r.TenantID, Kind: r.Kind, Value: r.Value, Action: r.Action, Note: r.Note, CreatedAt: r.CreatedAt}
}

// ListSenderRules returns a tenant's allow and block lists.
func (s *Admin) ListSenderRules(ctx context.Context, in domain.ListSenderRules) (domain.SenderRules, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.SenderRules{}, err
	}
	rs, err := s.Store.ListSenderRules(ctx, tid)
	if err != nil {
		return domain.SenderRules{}, storeErr(err)
	}
	out := domain.SenderRules{Rules: make([]domain.SenderRule, len(rs))}
	for i, r := range rs {
		out.Rules[i] = senderRuleOf(r)
	}
	return out, nil
}

// CreateSenderRule adds an allow or block rule.
func (s *Admin) CreateSenderRule(ctx context.Context, in domain.CreateSenderRule) (domain.SenderRuleCreated, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.SenderRuleCreated{}, err
	}
	r, err := s.Store.CreateSenderRule(ctx, store.SenderRule{TenantID: tid, Kind: in.Kind, Value: in.Value, Action: in.Action, Note: in.Note})
	if err != nil {
		return domain.SenderRuleCreated{}, storeErr(err)
	}
	return domain.SenderRuleCreated{Rule: senderRuleOf(r)}, nil
}

// DeleteSenderRule removes a rule.
func (s *Admin) DeleteSenderRule(ctx context.Context, in domain.DeleteSenderRule) (domain.Done, error) {
	_, tid, err := scope(ctx, in.TenantID)
	if err != nil {
		return domain.Done{}, err
	}
	return domain.Done{}, storeErr(s.Store.DeleteSenderRule(ctx, tid, in.ID))
}
