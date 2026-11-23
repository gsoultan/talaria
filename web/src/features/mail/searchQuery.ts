// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import type { Mailbox } from '../../lib/api'
import { displayName } from './mailboxes'

export type Parsed = {
  text: string
  from: string
  unread: boolean
  flagged: boolean
  hasAttachments: boolean
  after: number
  before: number
  mailbox: string
}

function toUnix(s: string): number {
  const t = Date.parse(s)
  return Number.isNaN(t) ? 0 : Math.floor(t / 1000)
}

/** Parses Gmail-style operators: from: is:unread is:starred has:attachment before: after: in: */
export function parseQuery(q: string): Parsed {
  const out: Parsed = { text: '', from: '', unread: false, flagged: false, hasAttachments: false, after: 0, before: 0, mailbox: '' }
  const words: string[] = []
  for (const tok of q.match(/(?:[^\s"]+|"[^"]*")+/g) ?? []) {
    const m = /^(from|is|has|before|after|in):(.+)$/i.exec(tok)
    const val = m?.[2]?.replace(/^"|"$/g, '') ?? ''
    switch (m?.[1]?.toLowerCase()) {
      case 'from':
        out.from = val
        break
      case 'is':
        if (/^unread$/i.test(val)) out.unread = true
        else if (/^(starred|flagged)$/i.test(val)) out.flagged = true
        else words.push(tok)
        break
      case 'has':
        if (/^attachments?$/i.test(val)) out.hasAttachments = true
        else words.push(tok)
        break
      case 'before':
        out.before = toUnix(val)
        break
      case 'after':
        out.after = toUnix(val)
        break
      case 'in':
        out.mailbox = val
        break
      default:
        words.push(tok)
    }
  }
  out.text = words.join(' ')
  return out
}

export function resolveMailbox(list: readonly Mailbox[] | undefined, name: string): Mailbox | undefined {
  if (!name || !list) return undefined
  const n = name.toLowerCase()
  const alias: Record<string, string> = { spam: '\\Junk', junk: '\\Junk', inbox: '\\Inbox', sent: '\\Sent', trash: '\\Trash', drafts: '\\Drafts', archive: '\\Archive' }
  return list.find((m) => (alias[n] && m.specialUse === alias[n]) || displayName(m).toLowerCase() === n)
}

/** Toggles one operator token in a query string. */
export function toggleToken(q: string, token: string): string {
  const parts = q.split(/\s+/).filter(Boolean)
  const i = parts.findIndex((p) => p.toLowerCase() === token.toLowerCase())
  if (i >= 0) parts.splice(i, 1)
  else parts.push(token)
  return parts.join(' ')
}
