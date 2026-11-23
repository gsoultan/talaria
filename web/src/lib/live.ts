// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createClient } from '@connectrpc/connect'
import { useEffect, useState } from 'react'
import { MailService } from '../gen/talaria/v1/mail_pb'
import { flushOutbox } from './outbox'
import { queryClient } from './queryClient'
import { transport } from './transport'

export type LiveState = 'live' | 'connecting' | 'offline'

const client = createClient(MailService, transport)

// Mailbox counts, lists and threads; open messages stay as they are.
const changed = new Set(['ListMailboxes', 'ListMessages', 'GetThread', 'Search'])

function refresh() {
  void queryClient.invalidateQueries({
    predicate: (q) => changed.has((q.queryKey[1] as { methodName?: string } | undefined)?.methodName ?? ''),
  })
}

/** Keeps one Watch stream open while signed in, and refreshes on changes. */
export function useLive(enabled: boolean): LiveState {
  const [state, setState] = useState<LiveState>(navigator.onLine ? 'connecting' : 'offline')
  useEffect(() => {
    if (!enabled) return
    let stop = false
    let ctrl: AbortController | undefined
    let delay = 1000
    const run = async () => {
      while (!stop) {
        if (!navigator.onLine) {
          setState('offline')
          await new Promise((r) => window.addEventListener('online', r, { once: true }))
          continue
        }
        ctrl = new AbortController()
        setState('connecting')
        try {
          let first = true
          for await (const ev of client.watch({}, { signal: ctrl.signal })) {
            if (first) {
              // Catch up on anything missed while disconnected.
              setState('live')
              delay = 1000
              first = false
              void flushOutbox()
              refresh()
            } else if (ev.mailboxIds.length > 0) {
              refresh()
            }
          }
        } catch {
          // Reconnect below.
        }
        if (stop) return
        setState(navigator.onLine ? 'connecting' : 'offline')
        await new Promise((r) => setTimeout(r, delay))
        delay = Math.min(delay * 2, 30_000)
      }
    }
    void run()
    const off = () => {
      setState('offline')
      ctrl?.abort()
    }
    window.addEventListener('offline', off)
    return () => {
      stop = true
      ctrl?.abort()
      window.removeEventListener('offline', off)
    }
  }, [enabled])
  return state
}
