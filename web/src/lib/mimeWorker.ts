// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { MimeRequest, MimeResponse } from '../workers/mime.worker'

let worker: Worker | undefined
let nextId = 1
const pending = new Map<number, { resolve: (s: string) => void; reject: (e: Error) => void }>()

function getWorker(): Worker {
  // Created lazily, so the inbox's first paint never waits for it.
  if (!worker) {
    worker = new Worker(new URL('../workers/mime.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e: MessageEvent<MimeResponse>) => {
      const p = pending.get(e.data.id)
      if (!p) return
      pending.delete(e.data.id)
      if (e.data.ok) p.resolve(e.data.text)
      else p.reject(new Error(e.data.error))
    }
  }
  return worker
}

export function decodeBase64(data: string): Promise<string> {
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    getWorker().postMessage({ id, kind: 'decode-base64', data } satisfies MimeRequest)
  })
}
