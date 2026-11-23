// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { type Mailbox, useApiQuery } from '../../lib/api'

export const specialOrder = ['\\Inbox', '\\Drafts', '\\Sent', '\\Archive', '\\Junk', '\\Trash']

export const specialSlug: Record<string, string> = {
  '\\Inbox': 'inbox',
  '\\Sent': 'sent',
  '\\Drafts': 'drafts',
  '\\Junk': 'junk',
  '\\Trash': 'trash',
  '\\Archive': 'archive',
}

export function useMailboxes() {
  return useApiQuery('mail.ListMailboxes', {}, { staleTime: 60_000 })
}

/** Folders in display order: special ones first, then by name. */
export function sortMailboxes(list: readonly Mailbox[]): Mailbox[] {
  const rank = (m: Mailbox) => {
    const i = specialOrder.indexOf(m.specialUse)
    return i < 0 ? specialOrder.length : i
  }
  return [...list].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name))
}

/** The URL segment for a folder: a slug for special ones, else its id. */
export function slugOf(m: Mailbox): string {
  return specialSlug[m.specialUse] ?? m.id.toString()
}

export function findMailbox(list: readonly Mailbox[] | undefined, slug: string): Mailbox | undefined {
  if (!list) return undefined
  return list.find((m) => slugOf(m) === slug) ?? list.find((m) => m.id.toString() === slug)
}

export function bySpecial(list: readonly Mailbox[] | undefined, use: string): Mailbox | undefined {
  return list?.find((m) => m.specialUse === use)
}

export function displayName(m: Mailbox): string {
  return m.specialUse === '\\Inbox' ? 'Inbox' : m.name
}
