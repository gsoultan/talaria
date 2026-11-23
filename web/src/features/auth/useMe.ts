// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { type User, useApiQuery } from '../../lib/api'

export const Role = { USER: 'user', TENANT_ADMIN: 'tenant_admin', PLATFORM_ADMIN: 'platform_admin' } as const
export type Role = (typeof Role)[keyof typeof Role]

export function useMe() {
  return useApiQuery('account.Me', {}, { staleTime: 5 * 60_000, retry: false })
}

export function isAdmin(u: User | undefined): boolean {
  return !!u && (u.role === Role.TENANT_ADMIN || u.role === Role.PLATFORM_ADMIN)
}

export function isPlatformAdmin(u: User | undefined): boolean {
  return u?.role === Role.PLATFORM_ADMIN
}
