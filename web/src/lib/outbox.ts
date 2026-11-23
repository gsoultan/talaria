// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { create, type MessageInitShape } from '@bufbuild/protobuf'
import { createClient } from '@connectrpc/connect'
import { createStore, del, entries, set } from 'idb-keyval'
import { ComposeSchema, MailService } from '../gen/talaria/v1/mail_pb'
import { isNetworkError } from './errors'
import { transport } from './transport'

// Mail written while offline waits here and goes out on reconnect.

type Item = { id: string; compose: MessageInitShape<typeof ComposeSchema>; at: number }

const store = createStore('talaria-outbox', 'outbox')
const client = createClient(MailService, transport)
const listeners = new Set<(n: number) => void>()

async function count(): Promise<number> {
  return (await entries(store)).length
}

async function notify() {
  const n = await count()
  for (const l of listeners) l(n)
}

export function onOutboxChange(fn: (n: number) => void): () => void {
  listeners.add(fn)
  void count().then(fn)
  return () => listeners.delete(fn)
}

export async function queueOffline(compose: MessageInitShape<typeof ComposeSchema>) {
  const id = crypto.randomUUID()
  await set(id, { id, compose, at: Date.now() } satisfies Item, store)
  await notify()
}

let flushing = false

/** Sends whatever waits in the outbox. Stops at the first network error. */
export async function flushOutbox(): Promise<number> {
  if (flushing || !navigator.onLine) return 0
  flushing = true
  let sent = 0
  try {
    const items = (await entries<string, Item>(store)).map(([, v]) => v).sort((a, b) => a.at - b.at)
    for (const it of items) {
      try {
        await client.sendMessage({ message: create(ComposeSchema, it.compose) })
        await del(it.id, store)
        sent++
      } catch (err) {
        if (isNetworkError(err)) break
        // A permanent error (bad address, quota): file it as a draft so
        // nothing is lost and the person can fix it.
        await client.saveDraft({ message: create(ComposeSchema, it.compose) }).catch(() => {})
        await del(it.id, store)
      }
    }
  } finally {
    flushing = false
    await notify()
  }
  return sent
}

window.addEventListener('online', () => void flushOutbox())
