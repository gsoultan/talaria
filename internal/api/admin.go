// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
	"github.com/gsoultan/talaria/internal/auth"
	"github.com/gsoultan/talaria/internal/outbound"
	"github.com/gsoultan/talaria/internal/store"
)

// AdminServer implements talaria.v1.AdminService. Every call is scoped:
// tenant admins see and change only their own tenant, and only platform
// admins manage tenants or grant the platform admin role.
type AdminServer struct {
	Store    *store.Store
	Keys     *outbound.Keys
	Hostname string
	// Route describes where outbound mail goes, for the queue view.
	Route     string
	RelayHost string
	// Wake nudges the outbound queue after "retry now".
	Wake func()
}

var _ talariav1connect.AdminServiceHandler = (*AdminServer)(nil)

var (
	errAdminOnly    = connect.NewError(connect.CodePermissionDenied, errors.New("admin access required"))
	errPlatformOnly = connect.NewError(connect.CodePermissionDenied, errors.New("platform admin access required"))
)

// scope returns the tenant the caller may act on.
func scope(ctx context.Context, tenantID int64) (store.User, int64, error) {
	u := UserFrom(ctx)
	if u.Role < store.RoleTenantAdmin {
		return u, 0, errAdminOnly
	}
	if tenantID == 0 {
		return u, u.TenantID, nil
	}
	if tenantID != u.TenantID && u.Role != store.RolePlatformAdmin {
		return u, 0, connect.NewError(connect.CodePermissionDenied, errors.New("not your tenant"))
	}
	return u, tenantID, nil
}

func platform(ctx context.Context) error {
	if UserFrom(ctx).Role != store.RolePlatformAdmin {
		return errPlatformOnly
	}
	return nil
}

// target loads a user the caller may manage.
func (s *AdminServer) target(ctx context.Context, id int64) (store.User, error) {
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

func tenantToProto(t store.Tenant) *talariav1.Tenant {
	return &talariav1.Tenant{Id: t.ID, Name: t.Name, DisplayName: t.DisplayName, SeatLimit: t.SeatLimit, QuotaBytes: t.QuotaBytes,
		DailySendLimit: t.DailySendLimit, Suspended: t.Suspended, CreatedAt: t.CreatedAt, Domains: t.Domains, Users: t.Users, UsedBytes: t.UsedBytes}
}

func (s *AdminServer) ListTenants(ctx context.Context, _ *connect.Request[talariav1.ListTenantsRequest]) (*connect.Response[talariav1.ListTenantsResponse], error) {
	u, _, err := scope(ctx, 0)
	if err != nil {
		return nil, err
	}
	all, err := s.Store.ListTenants(ctx)
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListTenantsResponse{}
	for _, t := range all {
		if u.Role == store.RolePlatformAdmin || t.ID == u.TenantID {
			res.Tenants = append(res.Tenants, tenantToProto(t))
		}
	}
	return connect.NewResponse(res), nil
}

func (s *AdminServer) CreateTenant(ctx context.Context, req *connect.Request[talariav1.CreateTenantRequest]) (*connect.Response[talariav1.CreateTenantResponse], error) {
	if err := platform(ctx); err != nil {
		return nil, err
	}
	m := req.Msg
	t, err := s.Store.CreateTenant(ctx, store.Tenant{Name: m.Name, DisplayName: m.DisplayName, SeatLimit: m.SeatLimit, QuotaBytes: m.QuotaBytes, DailySendLimit: m.DailySendLimit})
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.CreateTenantResponse{Tenant: tenantToProto(t)}), nil
}

func (s *AdminServer) UpdateTenant(ctx context.Context, req *connect.Request[talariav1.UpdateTenantRequest]) (*connect.Response[talariav1.UpdateTenantResponse], error) {
	if err := platform(ctx); err != nil {
		return nil, err
	}
	t := req.Msg.Tenant
	if t == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("tenant is required"))
	}
	if t.Suspended && t.Id == UserFrom(ctx).TenantID {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you cannot suspend your own tenant"))
	}
	err := s.Store.UpdateTenant(ctx, store.Tenant{ID: t.Id, DisplayName: t.DisplayName, SeatLimit: t.SeatLimit, QuotaBytes: t.QuotaBytes,
		DailySendLimit: t.DailySendLimit, Suspended: t.Suspended})
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.UpdateTenantResponse{}), nil
}

func (s *AdminServer) DeleteTenant(ctx context.Context, req *connect.Request[talariav1.DeleteTenantRequest]) (*connect.Response[talariav1.DeleteTenantResponse], error) {
	if err := platform(ctx); err != nil {
		return nil, err
	}
	if req.Msg.Id == UserFrom(ctx).TenantID {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you cannot delete your own tenant"))
	}
	if err := s.Store.DeleteTenant(ctx, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.DeleteTenantResponse{}), nil
}

func (s *AdminServer) ListDomains(ctx context.Context, req *connect.Request[talariav1.ListDomainsRequest]) (*connect.Response[talariav1.ListDomainsResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	ds, err := s.Store.ListDomains(ctx, tid)
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListDomainsResponse{}
	for _, d := range ds {
		res.Domains = append(res.Domains, &talariav1.Domain{Id: d.ID, TenantId: d.TenantID, Name: d.Name, CreatedAt: d.CreatedAt})
	}
	return connect.NewResponse(res), nil
}

func (s *AdminServer) CreateDomain(ctx context.Context, req *connect.Request[talariav1.CreateDomainRequest]) (*connect.Response[talariav1.CreateDomainResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	d, err := s.Store.CreateDomain(ctx, tid, req.Msg.Name)
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.CreateDomainResponse{Domain: &talariav1.Domain{Id: d.ID, TenantId: d.TenantID, Name: d.Name, CreatedAt: d.CreatedAt}}), nil
}

func (s *AdminServer) DeleteDomain(ctx context.Context, req *connect.Request[talariav1.DeleteDomainRequest]) (*connect.Response[talariav1.DeleteDomainResponse], error) {
	u, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if req.Msg.Id == u.DomainID {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you cannot delete the domain of your own account"))
	}
	if err := s.Store.DeleteDomain(ctx, tid, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.DeleteDomainResponse{}), nil
}

func (s *AdminServer) ListUsers(ctx context.Context, req *connect.Request[talariav1.ListUsersRequest]) (*connect.Response[talariav1.ListUsersResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	us, err := s.Store.ListUsers(ctx, tid)
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListUsersResponse{Users: make([]*talariav1.User, len(us))}
	for i, u := range us {
		res.Users[i] = userToProto(u)
	}
	return connect.NewResponse(res), nil
}

func (s *AdminServer) CreateUser(ctx context.Context, req *connect.Request[talariav1.CreateUserRequest]) (*connect.Response[talariav1.CreateUserResponse], error) {
	caller, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	role := roleFromProto(req.Msg.Role)
	if role == store.RolePlatformAdmin && caller.Role != store.RolePlatformAdmin {
		return nil, errPlatformOnly
	}
	hash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	u, err := s.Store.CreateUser(ctx, tid, req.Msg.Email, req.Msg.DisplayName, hash, role, req.Msg.QuotaBytes)
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.CreateUserResponse{User: userToProto(u)}), nil
}

func (s *AdminServer) UpdateUser(ctx context.Context, req *connect.Request[talariav1.UpdateUserRequest]) (*connect.Response[talariav1.UpdateUserResponse], error) {
	t, err := s.target(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	caller := UserFrom(ctx)
	role := roleFromProto(req.Msg.Role)
	if role == store.RolePlatformAdmin && caller.Role != store.RolePlatformAdmin {
		return nil, errPlatformOnly
	}
	if t.ID == caller.ID && (role < caller.Role || req.Msg.Suspended) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you cannot demote or suspend yourself"))
	}
	t.DisplayName, t.Role, t.QuotaBytes, t.Suspended = req.Msg.DisplayName, role, req.Msg.QuotaBytes, req.Msg.Suspended
	if err := s.Store.UpdateUser(ctx, t); err != nil {
		return nil, storeErr(err)
	}
	if t.Suspended {
		// Suspension signs the user out everywhere.
		s.Store.DeleteSessions(ctx, t.ID)
	}
	return connect.NewResponse(&talariav1.UpdateUserResponse{}), nil
}

func (s *AdminServer) SetUserPassword(ctx context.Context, req *connect.Request[talariav1.SetUserPasswordRequest]) (*connect.Response[talariav1.SetUserPasswordResponse], error) {
	t, err := s.target(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(req.Msg.Password)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.Store.SetPassword(ctx, t.ID, hash); err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.SetUserPasswordResponse{}), nil
}

func (s *AdminServer) DeleteUser(ctx context.Context, req *connect.Request[talariav1.DeleteUserRequest]) (*connect.Response[talariav1.DeleteUserResponse], error) {
	t, err := s.target(ctx, req.Msg.Id)
	if err != nil {
		return nil, err
	}
	if t.ID == UserFrom(ctx).ID {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("you cannot delete yourself"))
	}
	if err := s.Store.DeleteUser(ctx, t.TenantID, t.ID); err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.DeleteUserResponse{}), nil
}

func (s *AdminServer) ListAliases(ctx context.Context, req *connect.Request[talariav1.ListAliasesRequest]) (*connect.Response[talariav1.ListAliasesResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	as, err := s.Store.ListAliases(ctx, tid, req.Msg.UserId)
	if err != nil {
		return nil, storeErr(err)
	}
	res := &talariav1.ListAliasesResponse{}
	for _, a := range as {
		res.Aliases = append(res.Aliases, &talariav1.Alias{Id: a.ID, TenantId: tid, Address: a.Address, UserId: a.UserID})
	}
	return connect.NewResponse(res), nil
}

func (s *AdminServer) CreateAlias(ctx context.Context, req *connect.Request[talariav1.CreateAliasRequest]) (*connect.Response[talariav1.CreateAliasResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	a, err := s.Store.CreateAlias(ctx, tid, req.Msg.Address, req.Msg.UserId)
	if err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.CreateAliasResponse{Alias: &talariav1.Alias{Id: a.ID, TenantId: tid, Address: a.Address, UserId: a.UserID}}), nil
}

func (s *AdminServer) DeleteAlias(ctx context.Context, req *connect.Request[talariav1.DeleteAliasRequest]) (*connect.Response[talariav1.DeleteAliasResponse], error) {
	_, tid, err := scope(ctx, req.Msg.TenantId)
	if err != nil {
		return nil, err
	}
	if err := s.Store.DeleteAlias(ctx, tid, req.Msg.Id); err != nil {
		return nil, storeErr(err)
	}
	return connect.NewResponse(&talariav1.DeleteAliasResponse{}), nil
}
