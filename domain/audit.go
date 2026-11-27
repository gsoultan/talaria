// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package domain

// ListAudit searches the audit log, newest first. The same filters work
// for the CSV export at GET /api/v1/admin/audit.csv.
type ListAudit struct {
	TenantScope
	// Action is a prefix: sign_in, admin., policy. and so on.
	Action string `json:"-" query:"action"`
	// Query is words to find in the actor, target, IP or detail.
	Query  string `json:"-" query:"q"`
	Since  int64  `json:"-" query:"since"`
	Until  int64  `json:"-" query:"until"`
	Before int64  `json:"-" query:"before"`
}

// AuditEntry is one thing that happened.
type AuditEntry struct {
	ID      int64  `json:"id"`
	At      int64  `json:"at"`
	Actor   string `json:"actor"`
	IP      string `json:"ip"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	// Detail is a JSON object, or empty.
	Detail string `json:"detail"`
}

// AuditLog is a page of entries. More is set when older ones remain;
// pass the last ID as Before to get them.
type AuditLog struct {
	Entries []AuditEntry `json:"entries"`
	More    bool         `json:"more"`
}
