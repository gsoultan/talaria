// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useInfiniteQuery, useQuery } from '@connectrpc/connect-query'
import { Box, Center, Group, SegmentedControl, Stack, Text } from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import { useState, type ReactNode } from 'react'
import { MailService, type MessageSummary } from '../../gen/talaria/v1/mail_pb'
import { plural } from '../../lib/format'
import { navigate } from '../../lib/router'
import { useMe } from '../auth/useMe'
import { displayName, findMailbox, useMailboxes } from './mailboxes'
import { MessageList } from './MessageList'
import { Reader } from './Reader'
import { Icon, icons } from './Shell'

function useMyAddresses(): string[] {
  const ids = useQuery(MailService.method.listIdentities, {}, { staleTime: 10 * 60_000 }).data?.identities ?? []
  const me = useMe().data?.user?.email
  return [...ids.map((i) => i.address), ...(me ? [me] : [])]
}

/** List on the left, open message on the right; one at a time on phones. */
export function SplitView({ header, list, open, onClose, me }: { header: ReactNode; list: ReactNode; open?: MessageSummary; onClose: () => void; me: string[] }) {
  const narrow = useMediaQuery('(max-width: 62em)', false)
  if (narrow) {
    return (
      <Box style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', background: 'var(--t-surface)' }}>
        {open ? (
          <Reader key={open.id.toString()} summary={open} onClose={onClose} me={me} />
        ) : (
          <>
            {header}
            <Box style={{ flex: 1, minHeight: 0 }}>{list}</Box>
          </>
        )}
      </Box>
    )
  }
  return (
    <Group gap={12} align="stretch" wrap="nowrap" style={{ flex: 1, minWidth: 0 }}>
      <Stack gap={0} className="t-pane" style={{ width: 'clamp(320px, 32vw, 440px)', flex: '0 0 auto' }}>
        {header}
        <Box style={{ flex: 1, minHeight: 0 }}>{list}</Box>
      </Stack>
      <Box className="t-pane" style={{ flex: 1, minWidth: 0 }}>
        {open ? (
          <Reader key={open.id.toString()} summary={open} me={me} />
        ) : (
          <Center h="100%" c="dimmed">
            <Stack align="center" gap={6}>
              <Icon d={icons.mail} size={40} />
              <Text size="sm">Select a message to read it</Text>
              <Text size="xs">j and k move, r replies, e archives, c composes</Text>
            </Stack>
          </Center>
        )}
      </Box>
    </Group>
  )
}

export function ListHeader({ title, sub, right }: { title: string; sub?: string; right?: ReactNode }) {
  return (
    <Group justify="space-between" px="md" py="sm" style={{ borderBottom: '1px solid var(--t-border)' }} wrap="nowrap">
      <Box style={{ minWidth: 0 }}>
        <Text component="h2" fw={700} size="lg" lh={1.3} m={0} truncate>
          {title}
        </Text>
        {sub && (
          <Text size="xs" c="dimmed">
            {sub}
          </Text>
        )}
      </Box>
      {right}
    </Group>
  )
}

export function MailboxPage({ slug, messageId }: { slug: string; messageId?: string }) {
  const boxes = useMailboxes()
  const box = findMailbox(boxes.data?.mailboxes, slug)
  const [filter, setFilter] = useState<'all' | 'unread'>('all')
  const me = useMyAddresses()
  const q = useInfiniteQuery(
    MailService.method.listMessages,
    { mailboxId: box?.id ?? 0n, limit: 100, cursor: '', unreadOnly: filter === 'unread' },
    { pageParamKey: 'cursor', getNextPageParam: (p) => p.nextCursor || undefined, enabled: !!box },
  )
  const messages = q.data?.pages.flatMap((p) => p.messages) ?? []
  const open = messageId ? messages.find((m) => m.id.toString() === messageId) : undefined
  const sent = box?.specialUse === '\\Sent' || box?.specialUse === '\\Drafts'

  if (boxes.isSuccess && !box)
    return (
      <Center style={{ flex: 1 }}>
        <Text c="dimmed">This folder no longer exists.</Text>
      </Center>
    )

  return (
    <SplitView
      me={me}
      open={open}
      onClose={() => navigate(`/mail/${slug}`)}
      header={
        <ListHeader
          title={box ? displayName(box) : ''}
          sub={box ? `${plural(box.total, 'message')}${box.unread > 0n ? `, ${box.unread.toLocaleString()} unread` : ''}` : undefined}
          right={
            !sent && (
              <SegmentedControl
                size="xs"
                value={filter}
                onChange={(v) => setFilter(v as 'all' | 'unread')}
                data={[
                  { label: 'All', value: 'all' },
                  { label: 'Unread', value: 'unread' },
                ]}
              />
            )
          }
        />
      }
      list={
        <MessageList
          messages={messages}
          selectedId={open?.id}
          showTo={sent}
          loading={q.isPending || q.isFetchingNextPage}
          hasMore={q.hasNextPage}
          loadMore={() => void q.fetchNextPage()}
          onOpen={(m) => navigate(`/mail/${slug}/${m.id}`, { replace: !!open })}
          empty={<Text c="dimmed">{filter === 'unread' ? 'No unread messages' : 'Nothing here yet'}</Text>}
        />
      }
    />
  )
}

export function StarredPage({ messageId }: { messageId?: string }) {
  const me = useMyAddresses()
  const q = useQuery(MailService.method.search, { query: '', flagged: true, limit: 200 })
  const messages = q.data?.messages ?? []
  const open = messageId ? messages.find((m) => m.id.toString() === messageId) : undefined
  return (
    <SplitView
      me={me}
      open={open}
      onClose={() => navigate('/starred')}
      header={<ListHeader title="Starred" sub={plural(messages.length, 'message')} />}
      list={
        <MessageList
          messages={messages}
          selectedId={open?.id}
          loading={q.isPending}
          onOpen={(m) => navigate(`/starred/${m.id}`, { replace: !!open })}
          empty={<Text c="dimmed">Star a message to keep it here</Text>}
        />
      }
    />
  )
}

export { useMyAddresses }
