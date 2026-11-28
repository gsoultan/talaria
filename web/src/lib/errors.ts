// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { ApiError } from './api'

/** A message fit to show people, from any error. */
export function errorText(err: unknown): string {
  if (isNetworkError(err)) return 'Can’t reach the server. Check your connection.'
  if (err instanceof ApiError) {
    const field = Object.values(err.fields)[0]
    return sentence(field || err.message)
  }
  return sentence(err instanceof Error ? err.message : String(err))
}

export function isUnauthenticated(err: unknown): boolean {
  return err instanceof ApiError && err.status === 401
}

/** No answer from the server at all: offline, or the server is down. */
export function isNetworkError(err: unknown): boolean {
  if (!navigator.onLine) return true
  if (err instanceof ApiError) return err.status === 502 || err.status === 503 || err.status === 504
  // fetch rejects with a TypeError when the request never got an answer.
  return err instanceof TypeError
}

// Server messages are lower-case fragments; show them as sentences.
function sentence(s: string): string {
  if (!s) return 'Something went wrong.'
  const t = s.charAt(0).toUpperCase() + s.slice(1)
  return /[.!?]$/.test(t) ? t : t + '.'
}
