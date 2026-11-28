// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useEffect, useState } from 'react'
import { type Change, ofOps, urlOf } from './api'
import { flushOutbox } from './outbox'
import { queryClient } from './queryClient'

export type LiveState = 'live' | 'connecting' | 'offline'

// Mailbox counts, lists and threads; open messages stay as they are.
const refresh = () => void queryClient.invalidateQueries({ predicate: ofOps('mail.ListMailboxes', 'mail.ListMessages', 'mail.GetThread', 'mail.Search') })

/**
 * Keeps one Watch stream (server-sent events) open while signed in, and
 * refreshes lists when a folder changes. The server sends an empty change
 * first and every 25 seconds; a silent minute means the stream is stuck.
 */
export function useLive(enabled: boolean): LiveState {
  const [state, setState] = useState<LiveState>(navigator.onLine ? 'connecting' : 'offline')
  useEffect(() => {
    if (!enabled) return
    let es: EventSource | undefined
    let retry: ReturnType<typeof setTimeout> | undefined
    let watchdog: ReturnType<typeof setTimeout> | undefined
    let delay = 1000
    let stopped = false

    const reconnect = () => {
      es?.close()
      es = undefined
      clearTimeout(watchdog)
      if (stopped) return
      if (!navigator.onLine) {
        setState('offline')
        return
      }
      setState('connecting')
      retry = setTimeout(open, delay)
      delay = Math.min(delay * 2, 30_000)
    }
    const alive = () => {
      clearTimeout(watchdog)
      watchdog = setTimeout(reconnect, 60_000)
    }
    const open = () => {
      if (stopped) return
      let first = true
      es = new EventSource(urlOf('mail.Watch', {}))
      es.onmessage = (ev) => {
        alive()
        const c = JSON.parse(ev.data) as Change
        if (first) {
          // Catch up on anything missed while disconnected.
          first = false
          delay = 1000
          setState('live')
          void flushOutbox()
          refresh()
        } else if (c.mailboxIds.length > 0) {
          refresh()
        }
      }
      // The browser would retry by itself, without backoff and through a
      // 401; close and retry here instead. A 401 also fails the next query,
      // which sends the app to sign-in.
      es.onerror = reconnect
      es.addEventListener('error', reconnect)
    }
    const online = () => {
      clearTimeout(retry)
      delay = 1000
      reconnect()
    }
    const offline = () => {
      es?.close()
      es = undefined
      clearTimeout(retry)
      clearTimeout(watchdog)
      setState('offline')
    }
    window.addEventListener('online', online)
    window.addEventListener('offline', offline)
    if (navigator.onLine) open()
    return () => {
      stopped = true
      es?.close()
      clearTimeout(retry)
      clearTimeout(watchdog)
      window.removeEventListener('online', online)
      window.removeEventListener('offline', offline)
    }
  }, [enabled])
  return state
}
