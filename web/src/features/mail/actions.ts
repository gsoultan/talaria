// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { type MessageSummary, ofOps, useApiMutation } from '../../lib/api'
import { errorText } from '../../lib/errors'

type Lists = { pages?: { messages: MessageSummary[] }[]; messages?: MessageSummary[] }

type Flag = 'seen' | 'flagged' | 'answered' | 'deleted' | 'draft'

const isList = ofOps('mail.ListMessages', 'mail.Search', 'mail.GetThread')

/** Mail actions that update the lists at once, then confirm with the server. */
export function useMailActions() {
  const qc = useQueryClient()
  const flags = useApiMutation('mail.UpdateFlags')
  const move = useApiMutation('mail.MoveMessages')
  const remove = useApiMutation('mail.DeleteMessages')

  // Applies fn to every cached list entry with one of ids.
  const patch = (ids: number[], fn: (m: MessageSummary) => MessageSummary | null) => {
    const want = new Set(ids)
    const apply = (list: MessageSummary[]) => list.flatMap((m) => (want.has(m.id) ? (fn(m) ?? []) : [m]))
    for (const q of qc.getQueryCache().getAll()) {
      if (!isList(q)) continue
      qc.setQueryData<Lists>(q.queryKey, (old) => {
        if (!old) return old
        if (old.pages) return { ...old, pages: old.pages.map((p) => ({ ...p, messages: apply(p.messages) })) }
        if (old.messages) return { ...old, messages: apply(old.messages) }
        return old
      })
    }
  }

  const settle = () => {
    void qc.invalidateQueries({ predicate: ofOps('mail.ListMailboxes') })
  }

  const fail = (err: unknown) => {
    notifications.show({ color: 'red', title: 'That didn’t work', message: errorText(err) })
    void qc.invalidateQueries({ predicate: isList })
  }

  const setFlag = (ids: number[], flag: Flag, on: boolean) => {
    const field = flag === 'seen' || flag === 'flagged' ? flag : null
    if (field) patch(ids, (m) => ({ ...m, [field]: on }))
    flags.mutate({ ids, add: on ? [flag] : [], remove: on ? [] : [flag] }, { onSuccess: settle, onError: fail })
  }

  return {
    markSeen: (ids: number[], seen: boolean) => setFlag(ids, 'seen', seen),
    star: (ids: number[], on: boolean) => setFlag(ids, 'flagged', on),
    move: (ids: number[], mailboxId: number, label = 'Moved') => {
      patch(ids, () => null)
      move.mutate(
        { ids, mailboxId },
        {
          onSuccess: () => {
            settle()
            notifications.show({ message: label, autoClose: 2500 })
          },
          onError: fail,
        },
      )
    },
    /** Moves to Trash; deletes for good from Trash and Junk. */
    remove: (ids: number[], label = 'Moved to Trash') => {
      patch(ids, () => null)
      remove.mutate(
        { ids },
        {
          onSuccess: () => {
            settle()
            notifications.show({ message: label, autoClose: 2500 })
          },
          onError: fail,
        },
      )
    },
  }
}
