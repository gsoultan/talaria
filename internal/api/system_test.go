// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	talariav1 "github.com/gsoultan/talaria/gen/go/talaria/v1"
	"github.com/gsoultan/talaria/gen/go/talaria/v1/talariav1connect"
)

func TestGetInfoOverConnect(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(talariav1connect.NewSystemServiceHandler(NewSystemServer()))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for name, opts := range map[string][]connect.ClientOption{
		"connect": nil,
		"grpcweb": {connect.WithGRPCWeb()},
	} {
		client := talariav1connect.NewSystemServiceClient(srv.Client(), srv.URL, opts...)
		res, err := client.GetInfo(context.Background(), connect.NewRequest(&talariav1.GetInfoRequest{}))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Msg.GetGoVersion() == "" || res.Msg.GetVersion() == "" {
			t.Fatalf("%s: empty info %+v", name, res.Msg)
		}
	}
}
