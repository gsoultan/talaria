// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createStore, del, entries, set } from 'idb-keyval'
import { type Compose, call, upload } from './api'
import { isNetworkError } from './errors'

// Mail written while offline waits here and goes out on reconnect. Files
// can't be uploaded offline, so they wait too, and are uploaded first.

/** A file to attach that has not been uploaded yet. */
export type PendingFile = { file: File; contentId?: string }

type Item = { id: string; compose: Compose; files: PendingFile[]; at: number }

const store = createStore('talaria-outbox', 'outbox')
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

export async function queueOffline(compose: Compose, files: PendingFile[] = []) {
  const id = crypto.randomUUID()
  await set(id, { id, compose, files, at: Date.now() } satisfies Item, store)
  await notify()
}

/** Uploads the files and adds them to the message's attachments. */
export async function withFiles(compose: Compose, files: PendingFile[]): Promise<Compose> {
  if (files.length === 0) return compose
  const added = []
  for (const f of files) {
    const u = await upload(f.file, f.file.name)
    added.push({ uploadId: u.id, contentId: f.contentId })
  }
  return { ...compose, attachments: [...(compose.attachments ?? []), ...added] }
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
      let message = it.compose
      try {
        message = await withFiles(it.compose, it.files ?? [])
        await call('mail.SendMessage', { message })
        await del(it.id, store)
        sent++
      } catch (err) {
        if (isNetworkError(err)) break
        // A permanent error (bad address, quota): file it as a draft so
        // nothing is lost and the person can fix it.
        await call('mail.SaveDraft', { message }).catch(() => {})
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
