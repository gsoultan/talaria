/// <reference lib="webworker" />
// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Heavy message work runs here, off the main thread.

export type PrepareHtml = { id: number; kind: 'prepare-html'; html: string; cids: Record<string, string>; allowRemote: boolean; origin: string }
export type MimeRequest = { id: number; kind: 'decode-base64'; data: string } | PrepareHtml
export type MimeResponse =
  | { id: number; ok: true; text: string; hasRemote?: boolean }
  | { id: number; ok: false; error: string }

declare const self: DedicatedWorkerGlobalScope

const remoteRef = /(?:\bsrc|\bbackground|\bposter|srcset)\s*=\s*["']?\s*(?:https?:)?\/\/|url\(\s*["']?\s*(?:https?:)?\/\//i

function prepare(r: PrepareHtml): { text: string; hasRemote: boolean } {
  let html = r.html
  // Inline images point at the message's own parts.
  html = html.replace(/cid:([^"'\s)>]+)/gi, (m, cid: string) => r.cids[cid.replace(/^<|>$/g, '')] ?? m)
  // Nothing in a message may move the frame elsewhere on its own.
  html = html.replace(/<meta[^>]+http-equiv[^>]*>/gi, '').replace(/<base[^>]*>/gi, '')
  const hasRemote = remoteRef.test(html)
  const img = r.allowRemote ? `data: ${r.origin} https: http:` : `data: ${r.origin}`
  // No scripts, frames, forms or plugins; styles inline; images as allowed.
  const csp = `default-src 'none'; style-src 'unsafe-inline' ${r.allowRemote ? 'https:' : ''}; img-src ${img}; media-src ${img}; font-src data: ${r.allowRemote ? 'https:' : ''}`
  const head = `<meta http-equiv="Content-Security-Policy" content="${csp}"><base target="_blank"><meta name="color-scheme" content="light"><style>html{margin:0;padding:0}body{margin:0;padding:12px 14px;font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1a1d21;background:#fff;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}table{max-width:100%}</style>`
  return { text: `<!doctype html><html><head>${head}</head><body>${html}</body></html>`, hasRemote }
}

self.onmessage = (e: MessageEvent<MimeRequest>) => {
  const req = e.data
  try {
    if (req.kind === 'prepare-html') {
      const { text, hasRemote } = prepare(req)
      self.postMessage({ id: req.id, ok: true, text, hasRemote } satisfies MimeResponse)
      return
    }
    const bin = atob(req.data)
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
    self.postMessage({ id: req.id, ok: true, text: new TextDecoder().decode(bytes) } satisfies MimeResponse)
  } catch (err) {
    self.postMessage({ id: req.id, ok: false, error: String(err) } satisfies MimeResponse)
  }
}
