// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { MimeRequest, MimeResponse } from '../workers/mime.worker'

type Result = { text: string; hasRemote?: boolean }

let worker: Worker | undefined
let nextId = 1
const pending = new Map<number, { resolve: (r: Result) => void; reject: (e: Error) => void }>()

function getWorker(): Worker {
  // Created lazily, so the inbox's first paint never waits for it.
  if (!worker) {
    worker = new Worker(new URL('../workers/mime.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e: MessageEvent<MimeResponse>) => {
      const p = pending.get(e.data.id)
      if (!p) return
      pending.delete(e.data.id)
      if (e.data.ok) p.resolve({ text: e.data.text, hasRemote: e.data.hasRemote })
      else p.reject(new Error(e.data.error))
    }
  }
  return worker
}

type Without<T> = T extends unknown ? Omit<T, 'id'> : never

function call(req: Without<MimeRequest>): Promise<Result> {
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    getWorker().postMessage({ ...req, id } as MimeRequest)
  })
}

export async function decodeBase64(data: string): Promise<string> {
  return (await call({ kind: 'decode-base64', data })).text
}

/** Wraps a message's HTML in a locked-down document for a sandboxed frame. */
export async function prepareHtml(html: string, cids: Record<string, string>, allowRemote: boolean) {
  const r = await call({ kind: 'prepare-html', html, cids, allowRemote, origin: window.location.origin })
  return { html: r.text, hasRemote: !!r.hasRemote }
}
