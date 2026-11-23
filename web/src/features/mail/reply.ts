// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { MessageDetail, MessageSummary } from '../../lib/api'
import { fullDate, splitAddresses } from '../../lib/format'
import { openCompose } from './composeStore'

function prefixed(subject: string, p: 'Re' | 'Fwd'): string {
  const re = new RegExp(`^\\s*${p}:`, 'i')
  return re.test(subject) ? subject : `${p}: ${subject}`
}

function quote(m: MessageSummary, d: MessageDetail | undefined): string {
  const text = (d?.textBody ?? m.preview).replace(/\s+$/, '')
  const who = m.fromName ? `${m.fromName} <${m.fromAddr}>` : m.fromAddr
  return `\n\nOn ${fullDate(m.sentDate || m.date)}, ${who} wrote:\n` + text.split('\n').map((l) => `> ${l}`).join('\n')
}

function addrOf(s: string): string {
  const m = /<([^>]+)>/.exec(s)
  return (m?.[1] ?? s).trim().toLowerCase()
}

export function reply(m: MessageSummary, d: MessageDetail | undefined, all: boolean, me: string[]) {
  const mine = new Set(me.map((a) => a.toLowerCase()))
  const to = [d?.replyTo || (m.fromName ? `${m.fromName} <${m.fromAddr}>` : m.fromAddr)]
  let cc: string[] = []
  if (all) {
    const seen = new Set(to.map(addrOf))
    cc = [...splitAddresses(m.to), ...splitAddresses(m.cc)].filter((a) => {
      const k = addrOf(a)
      if (mine.has(k) || seen.has(k)) return false
      seen.add(k)
      return true
    })
  }
  const refs = d ? [...(d.headers.find((h) => h.name.toLowerCase() === 'references')?.value.split(/\s+/).filter(Boolean) ?? []), d.messageId].filter(Boolean) : []
  openCompose({
    to,
    cc,
    subject: prefixed(m.subject, 'Re'),
    body: quote(m, d),
    inReplyTo: d?.messageId,
    references: refs,
  })
}

export function forward(m: MessageSummary, d: MessageDetail | undefined) {
  const who = m.fromName ? `${m.fromName} <${m.fromAddr}>` : m.fromAddr
  const head = `\n\n---------- Forwarded message ----------\nFrom: ${who}\nDate: ${fullDate(m.sentDate || m.date)}\nSubject: ${m.subject}\nTo: ${m.to}\n\n`
  openCompose({ subject: prefixed(m.subject, 'Fwd'), body: head + (d?.textBody ?? m.preview) })
}
