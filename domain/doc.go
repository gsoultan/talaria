// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package domain holds the types the webmail API sends and receives. They
// are the API's DTOs: every transport encodes them as they are, and the
// OpenAPI document and the web client's types are generated from them.
//
// Times are Unix seconds and sizes are bytes. Fields a client may leave out
// are tagged omitzero; every other field is always present in a response.
package domain

import "github.com/gsoultan/kakarot"

// Codes the API adds to kakarot's own. The transport maps each to a status.
var (
	// CodeLimit means a quota, seat limit or sending limit was reached.
	CodeLimit = kakarot.NewCode("limit_reached")
	// CodeRateLimited means too many attempts; try again later.
	CodeRateLimited = kakarot.NewCode("rate_limited")
)

// Done is the answer of an operation that returns nothing else.
type Done struct{}

// Role is what a user may administer.
type Role string

// Roles, from least to most access.
const (
	RoleUser          Role = "user"
	RoleTenantAdmin   Role = "tenant_admin"
	RolePlatformAdmin Role = "platform_admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	return r == RoleUser || r == RoleTenantAdmin || r == RolePlatformAdmin
}

func invalid(field, problem string) error {
	return kakarot.Invalid(problem, map[string]string{field: problem})
}

func checkIDs(ids []int64) error {
	if len(ids) == 0 || len(ids) > MaxBatch {
		return invalid("ids", "give 1 to 1000 message ids")
	}
	return nil
}

// MaxBatch is the most messages one call may change.
const MaxBatch = 1000
