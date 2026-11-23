// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package store

import "context"

// Stats summarizes one tenant, or every tenant when TenantID is 0.
type Stats struct {
	Tenants, Domains, Users  int64
	UsedBytes                int64 // mailbox usage, as quotas count it
	StoredBytes, RawBytes    int64 // blob bytes on disk, and before compression
	ReceivedToday, JunkToday int64
}

// Stats counts a tenant's domains, users, storage and mail received in the
// last 24 hours (tenantID 0 = all tenants).
func (s *Store) Stats(ctx context.Context, tenantID int64) (Stats, error) {
	var st Stats
	since := s.unix() - 86400
	err := s.r.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM tenants WHERE ?=0 OR id=?),
		(SELECT COUNT(*) FROM domains WHERE ?=0 OR tenant_id=?),
		(SELECT COUNT(*) FROM users WHERE ?=0 OR tenant_id=?),
		(SELECT COALESCE(SUM(used_bytes),0) FROM users WHERE ?=0 OR tenant_id=?),
		(SELECT COALESCE(SUM(stored_size),0) FROM blobs WHERE ?=0 OR tenant_id=?),
		(SELECT COALESCE(SUM(size),0) FROM blobs WHERE ?=0 OR tenant_id=?)`,
		tenantID, tenantID, tenantID, tenantID, tenantID, tenantID, tenantID, tenantID, tenantID, tenantID, tenantID, tenantID).
		Scan(&st.Tenants, &st.Domains, &st.Users, &st.UsedBytes, &st.StoredBytes, &st.RawBytes)
	if err != nil {
		return st, err
	}
	err = s.r.QueryRowContext(ctx, `SELECT COALESCE(SUM(b.special_use IN ('\Inbox','\Junk')),0), COALESCE(SUM(b.special_use='\Junk'),0)
		FROM messages m JOIN mailboxes b ON b.id=m.mailbox_id JOIN users u ON u.id=b.user_id
		WHERE (?=0 OR u.tenant_id=?) AND b.special_use IN ('\Inbox','\Junk') AND m.internal_date>=?`, tenantID, tenantID, since).
		Scan(&st.ReceivedToday, &st.JunkToday)
	return st, err
}
