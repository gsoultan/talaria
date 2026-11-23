// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from '@connectrpc/connect-query'
import { AuthService, Role, type User } from '../../gen/talaria/v1/auth_pb'

export function useMe() {
  return useQuery(AuthService.method.me, {}, { staleTime: 5 * 60_000, retry: false })
}

export function isAdmin(u: User | undefined): boolean {
  return !!u && (u.role === Role.TENANT_ADMIN || u.role === Role.PLATFORM_ADMIN)
}

export function isPlatformAdmin(u: User | undefined): boolean {
  return u?.role === Role.PLATFORM_ADMIN
}
