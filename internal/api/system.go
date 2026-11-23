// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package api implements the Connect RPC services used by the webmail.
package api

import (
	"context"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"time"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
)

// Build information, set with -ldflags at build time.
var (
	Version = "dev"
	Commit  = "unknown"
)

// SystemServer implements talaria.v1.SystemService.
type SystemServer struct {
	started time.Time
}

var _ talariav1connect.SystemServiceHandler = (*SystemServer)(nil)

func NewSystemServer() *SystemServer { return &SystemServer{started: time.Now()} }

func (s *SystemServer) GetInfo(context.Context, *connect.Request[talariav1.GetInfoRequest]) (*connect.Response[talariav1.GetInfoResponse], error) {
	// runtime/metrics is cheap; ReadMemStats would stop the world.
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	var heap uint64
	if sample[0].Value.Kind() == metrics.KindUint64 {
		heap = sample[0].Value.Uint64()
	}
	return connect.NewResponse(&talariav1.GetInfoResponse{
		Version:          Version,
		Commit:           Commit,
		GoVersion:        runtime.Version(),
		HeapBytes:        heap,
		MemoryLimitBytes: debug.SetMemoryLimit(-1),
		UptimeSeconds:    int64(time.Since(s.started).Seconds()),
	}), nil
}
