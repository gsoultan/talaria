// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Package api implements the Connect RPC services used by the webmail.
package api

import (
	"context"
	"runtime"
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

// GetInfo is public, so it reports only the version. Memory and uptime are
// in AdminService.GetStats, for platform admins.
func (s *SystemServer) GetInfo(context.Context, *connect.Request[talariav1.GetInfoRequest]) (*connect.Response[talariav1.GetInfoResponse], error) {
	return connect.NewResponse(&talariav1.GetInfoResponse{Version: Version, Commit: Commit, GoVersion: runtime.Version()}), nil
}
