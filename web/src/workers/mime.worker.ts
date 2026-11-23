/// <reference lib="webworker" />
// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Heavy message work runs here, off the main thread: MIME decoding, HTML
// preparation and, in later phases, the local search index.

export type MimeRequest = { id: number; kind: 'decode-base64'; data: string }
export type MimeResponse = { id: number; ok: true; text: string } | { id: number; ok: false; error: string }

declare const self: DedicatedWorkerGlobalScope

self.onmessage = (e: MessageEvent<MimeRequest>) => {
  const { id, data } = e.data
  try {
    const bin = atob(data)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    const text = new TextDecoder().decode(bytes)
    self.postMessage({ id, ok: true, text } satisfies MimeResponse)
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err) } satisfies MimeResponse)
  }
}
