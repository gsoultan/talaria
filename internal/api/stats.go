// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"runtime/debug"
	"runtime/metrics"
	"time"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
)

var started = time.Now()

func heapBytes() uint64 {
	// runtime/metrics is cheap; ReadMemStats would stop the world.
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() == metrics.KindUint64 {
		return sample[0].Value.Uint64()
	}
	return 0
}

func (s *AdminServer) GetStats(ctx context.Context, req *connect.Request[talariav1.GetStatsRequest]) (*connect.Response[talariav1.GetStatsResponse], error) {
	var tenantID int64
	server := req.Msg.Server
	if server {
		if err := platform(ctx); err != nil {
			return nil, err
		}
	} else {
		_, t, err := scope(ctx, req.Msg.TenantId)
		if err != nil {
			return nil, err
		}
		tenantID = t
	}
	st, err := s.Store.Stats(ctx, tenantID)
	if err != nil {
		return nil, internal(err)
	}
	waiting, sent, bounced, err := s.Store.QueueStats(ctx, tenantID)
	if err != nil {
		return nil, internal(err)
	}
	res := &talariav1.GetStatsResponse{
		Tenants: st.Tenants, Domains: st.Domains, Users: st.Users, UsedBytes: st.UsedBytes,
		StoredBytes: st.StoredBytes, RawBytes: st.RawBytes, ReceivedToday: st.ReceivedToday, JunkToday: st.JunkToday,
		QueueWaiting: waiting, SentToday: sent, BouncedToday: bounced, Route: s.Route,
	}
	if server {
		res.HeapBytes = heapBytes()
		res.MemoryLimitBytes = debug.SetMemoryLimit(-1)
		res.UptimeSeconds = int64(time.Since(started).Seconds())
	} else if t, err := s.Store.Tenant(ctx, tenantID); err == nil {
		res.SeatLimit, res.QuotaBytes = t.SeatLimit, t.QuotaBytes
	}
	return connect.NewResponse(res), nil
}
