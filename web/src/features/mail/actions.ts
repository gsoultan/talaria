// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation } from '@connectrpc/connect-query'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { Flag, MailService, type MessageSummary } from '../../gen/talaria/v1/mail_pb'
import { errorText } from '../../lib/errors'

type Lists = { pages?: { messages: MessageSummary[] }[]; messages?: MessageSummary[] }

const listMethods = new Set(['ListMessages', 'Search', 'GetThread'])

function methodOf(key: readonly unknown[]): string {
  return (key[1] as { methodName?: string } | undefined)?.methodName ?? ''
}

/** Mail actions that update the lists at once, then confirm with the server. */
export function useMailActions() {
  const qc = useQueryClient()
  const flags = useMutation(MailService.method.updateFlags)
  const move = useMutation(MailService.method.moveMessages)
  const remove = useMutation(MailService.method.deleteMessages)

  // Applies fn to every cached list entry with one of ids.
  const patch = (ids: bigint[], fn: (m: MessageSummary) => MessageSummary | null) => {
    const want = new Set(ids)
    const apply = (list: MessageSummary[]) => list.flatMap((m) => (want.has(m.id) ? (fn(m) ?? []) : [m]))
    for (const q of qc.getQueryCache().getAll()) {
      if (!listMethods.has(methodOf(q.queryKey))) continue
      qc.setQueryData<Lists>(q.queryKey, (old) => {
        if (!old) return old
        if (old.pages) return { ...old, pages: old.pages.map((p) => ({ ...p, messages: apply(p.messages) })) }
        if (old.messages) return { ...old, messages: apply(old.messages) }
        return old
      })
    }
  }

  const settle = () => {
    void qc.invalidateQueries({ predicate: (q) => methodOf(q.queryKey) === 'ListMailboxes' })
  }

  const fail = (err: unknown) => {
    notifications.show({ color: 'red', title: 'That didn’t work', message: errorText(err) })
    void qc.invalidateQueries({ predicate: (q) => listMethods.has(methodOf(q.queryKey)) })
  }

  const setFlag = (ids: bigint[], flag: Flag, on: boolean) => {
    const field = flag === Flag.SEEN ? 'seen' : flag === Flag.FLAGGED ? 'flagged' : null
    if (field) patch(ids, (m) => ({ ...m, [field]: on }))
    flags.mutate({ ids, add: on ? [flag] : [], remove: on ? [] : [flag] }, { onSuccess: settle, onError: fail })
  }

  return {
    markSeen: (ids: bigint[], seen: boolean) => setFlag(ids, Flag.SEEN, seen),
    star: (ids: bigint[], on: boolean) => setFlag(ids, Flag.FLAGGED, on),
    move: (ids: bigint[], mailboxId: bigint, label = 'Moved') => {
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
    remove: (ids: bigint[], label = 'Moved to Trash') => {
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
