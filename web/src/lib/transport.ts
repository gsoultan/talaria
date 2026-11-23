// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createConnectTransport } from '@connectrpc/connect-web'

// Connect protocol over plain HTTP POST. It passes through Cloudflare Tunnel
// and ordinary web gateways untouched, unlike raw gRPC, which needs
// end-to-end HTTP/2 trailers.
export const transport = createConnectTransport({
  baseUrl: window.location.origin,
  useBinaryFormat: true,
  // Idempotent RPCs go out as GET, so the browser and CDN can cache them.
  useHttpGet: true,
})
