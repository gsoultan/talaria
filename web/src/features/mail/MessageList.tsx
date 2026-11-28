// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Avatar, Box, Center, Group, Loader, Text } from '@mantine/core'
import { useHotkeys } from '@mantine/hooks'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useEffect, useRef, type ReactNode } from 'react'
import { avatarColor, initials, listDate } from '../../lib/format'
import { Icon, icons } from './Shell'
import { type MessageSummary } from '../../lib/api'

type Props = {
  messages: MessageSummary[]
  selectedId?: number
  onOpen: (m: MessageSummary) => void
  hasMore?: boolean
  loadMore?: () => void
  loading?: boolean
  empty?: ReactNode
  /** Shows recipients instead of senders (Sent, Drafts). */
  showTo?: boolean
  compact?: boolean
}

const ROW = 76

function who(m: MessageSummary, showTo: boolean): string {
  if (showTo) return m.to ? `To: ${m.to.split(',')[0]}` : '(no recipients)'
  return m.fromName || m.fromAddr || '(unknown sender)'
}

/** A virtualized list: only rows in view are rendered, however long the folder. */
export function MessageList({ messages, selectedId, onOpen, hasMore, loadMore, loading, empty, showTo = false, compact = false }: Props) {
  const parent = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: messages.length + (hasMore ? 1 : 0), getScrollElement: () => parent.current, estimateSize: () => ROW, overscan: 8 })
  const items = v.getVirtualItems()
  const last = items[items.length - 1]

  useEffect(() => {
    if (last && hasMore && !loading && last.index >= messages.length - 1) loadMore?.()
  }, [last, hasMore, loading, messages.length, loadMore])

  const idx = messages.findIndex((m) => m.id === selectedId)
  const step = (d: number) => {
    const n = messages[Math.min(Math.max((idx < 0 ? -1 : idx) + d, 0), messages.length - 1)]
    if (n) {
      onOpen(n)
      v.scrollToIndex(messages.indexOf(n), { align: 'auto' })
    }
  }
  useHotkeys([
    ['j', () => step(1)],
    ['k', () => step(-1)],
  ])

  if (loading && messages.length === 0)
    return (
      <Center h="100%">
        <Loader size="sm" />
      </Center>
    )
  if (messages.length === 0) return <Center h="100%" p="xl">{empty ?? <Text c="dimmed">No messages</Text>}</Center>

  return (
    <div ref={parent} style={{ height: '100%', overflow: 'auto', contain: 'strict' }} role="list" aria-label="Messages">
      <div style={{ height: v.getTotalSize(), position: 'relative' }}>
        {items.map((it) => {
          const m = messages[it.index]
          if (!m)
            return (
              <Center key="more" style={{ position: 'absolute', top: 0, left: 0, right: 0, height: it.size, transform: `translateY(${it.start}px)` }}>
                <Loader size="xs" />
              </Center>
            )
          const unread = !m.seen && !showTo
          return (
            <div
              key={m.id.toString()}
              role="listitem"
              tabIndex={0}
              className="t-row"
              data-selected={m.id === selectedId}
              onClick={() => onOpen(m)}
              onKeyDown={(e) => e.key === 'Enter' && onOpen(m)}
              style={{ position: 'absolute', top: 0, left: 0, right: 0, height: it.size, transform: `translateY(${it.start}px)`, padding: '10px 14px', display: 'flex', gap: 12 }}
            >
              {!compact && (
                <Avatar size={36} radius="xl" color={avatarColor(m.fromAddr)} mt={2}>
                  {initials(m.fromName, m.fromAddr)}
                </Avatar>
              )}
              <Box style={{ flex: 1, minWidth: 0 }}>
                <Group gap={6} wrap="nowrap">
                  {unread && <Box w={8} h={8} style={{ borderRadius: 4, background: 'var(--mantine-color-blue-6)', flex: '0 0 auto' }} aria-label="Unread" />}
                  <Text size="sm" fw={unread ? 700 : 500} truncate style={{ flex: 1 }}>
                    {who(m, showTo)}
                  </Text>
                  {m.hasAttachments && <Icon d={icons.paperclip} size={14} />}
                  {m.flagged && (
                    <Box c="yellow.6" style={{ display: 'flex' }} aria-label="Starred">
                      <Icon d={icons.star} size={14} />
                    </Box>
                  )}
                  <Text size="xs" c="dimmed" style={{ flex: '0 0 auto' }}>
                    {listDate(m.date)}
                  </Text>
                </Group>
                <Text size="sm" fw={unread ? 600 : 400} truncate>
                  {m.subject || '(no subject)'}
                </Text>
                <Text size="xs" c="dimmed" truncate>
                  {m.preview}
                </Text>
              </Box>
            </div>
          )
        })}
      </div>
    </div>
  )
}
