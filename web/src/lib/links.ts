// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

/** The safe-links redirect for a web link in a message: the server checks
 * it against threat feeds when it is clicked. */
export function safeHref(url: string, origin = ''): string {
  return `${origin}/api/v1/link?u=${encodeURIComponent(url)}`
}

const entities: Record<string, string> = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' }

/** Decodes the character references an HTML attribute value may hold. */
export function decodeAttr(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, e: string) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)
      return Number.isFinite(n) && n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m
    }
    return entities[e.toLowerCase()] ?? m
  })
}

const hrefRe = /(<a\b[^>]*?\bhref\s*=\s*)(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi

/** Points every web link in HTML at the safe-links redirect. The original
 * address stays visible on hover. */
export function rewriteLinks(html: string, origin: string): string {
  return html.replace(hrefRe, (m, pre: string, dq?: string, sq?: string, bare?: string) => {
    const url = decodeAttr((dq ?? sq ?? bare ?? '').trim())
    if (!/^https?:\/\//i.test(url)) return m
    const safe = safeHref(url, origin).replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    const shown = url.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')
    return `${pre}"${safe}" title="${shown}"`
  })
}
