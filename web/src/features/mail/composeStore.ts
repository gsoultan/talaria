// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useSyncExternalStore } from 'react'

/** What a compose window starts with. */
export type Draft = {
  key: number
  from?: string
  to: string[]
  cc: string[]
  bcc: string[]
  subject: string
  body: string
  inReplyTo?: string
  references?: string[]
  draftId?: number
}

let state: Draft | null = null
let nextKey = 1
const subs = new Set<() => void>()

function emit() {
  for (const s of subs) s()
}

export function openCompose(d: Partial<Omit<Draft, 'key'>> = {}) {
  state = { key: nextKey++, to: [], cc: [], bcc: [], subject: '', body: '', ...d }
  emit()
}

export function closeCompose() {
  state = null
  emit()
}

export function useCompose(): Draft | null {
  return useSyncExternalStore(
    (fn) => {
      subs.add(fn)
      return () => subs.delete(fn)
    },
    () => state,
  )
}
