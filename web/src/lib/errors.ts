// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Code, ConnectError } from '@connectrpc/connect'

/** A message fit to show people, from any error. */
export function errorText(err: unknown): string {
  if (err instanceof ConnectError) {
    if (err.code === Code.Unavailable || err.code === Code.Unknown && /fetch|network/i.test(err.rawMessage)) {
      return 'Can’t reach the server. Check your connection.'
    }
    return sentence(err.rawMessage)
  }
  return sentence(err instanceof Error ? err.message : String(err))
}

export function isUnauthenticated(err: unknown): boolean {
  return err instanceof ConnectError && err.code === Code.Unauthenticated
}

export function isNetworkError(err: unknown): boolean {
  if (!navigator.onLine) return true
  return err instanceof ConnectError && (err.code === Code.Unavailable || (err.code === Code.Unknown && /fetch|network/i.test(err.rawMessage)))
}

// Server messages are lower-case fragments; show them as sentences.
function sentence(s: string): string {
  if (!s) return 'Something went wrong.'
  const t = s.charAt(0).toUpperCase() + s.slice(1)
  return /[.!?]$/.test(t) ? t : t + '.'
}
