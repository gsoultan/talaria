// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useQuery } from '@connectrpc/connect-query'
import { Box, Chip, Code, Group, Paper, Stack, Text } from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import { MailService } from '../../gen/talaria/v1/mail_pb'
import { errorText } from '../../lib/errors'
import { plural } from '../../lib/format'
import { navigate } from '../../lib/router'
import { useMailboxes } from './mailboxes'
import { ListHeader, SplitView, useMyAddresses } from './MailPage'
import { MessageList } from './MessageList'
import { parseQuery, resolveMailbox, toggleToken } from './searchQuery'

const chips = [
  { token: 'is:unread', label: 'Unread' },
  { token: 'is:starred', label: 'Starred' },
  { token: 'has:attachment', label: 'Has attachment' },
  { token: 'in:inbox', label: 'Inbox only' },
]

const help: [string, string][] = [
  ['from:', 'sender'],
  ['has:attachment', 'with files'],
  ['is:unread', 'unread only'],
  ['is:starred', 'starred only'],
  ['before: after:', 'date range, e.g. after:2026-01-01'],
  ['in:spam', 'one folder'],
]

export function SearchPage({ q, messageId }: { q: string; messageId?: string }) {
  const boxes = useMailboxes().data?.mailboxes
  const me = useMyAddresses()
  const wide = useMediaQuery('(min-width: 88em)', false)
  const p = parseQuery(q)
  const box = resolveMailbox(boxes, p.mailbox)
  const res = useQuery(
    MailService.method.search,
    { query: p.text, from: p.from, unread: p.unread, flagged: p.flagged, hasAttachments: p.hasAttachments, after: p.after, before: p.before, mailboxId: box?.id ?? 0n, limit: 200 },
    { enabled: q.trim() !== '', staleTime: 15_000 },
  )
  const messages = res.data?.messages ?? []
  const open = messageId ? messages.find((m) => m.id.toString() === messageId) : undefined
  const base = `/search?q=${encodeURIComponent(q)}`

  const header = (
    <Box>
      <ListHeader title="Search" sub={q.trim() === '' ? 'Type in the search box above' : res.isPending ? 'Searching…' : res.error ? errorText(res.error) : plural(messages.length, 'result')} />
      <Group gap={6} px="md" py="xs" style={{ borderBottom: '1px solid var(--t-border)' }}>
        {chips.map((c) => (
          <Chip key={c.token} size="xs" checked={q.toLowerCase().split(/\s+/).includes(c.token)} onChange={() => navigate(`/search?q=${encodeURIComponent(toggleToken(q, c.token))}`, { replace: true })}>
            {c.label}
          </Chip>
        ))}
      </Group>
    </Box>
  )

  return (
    <Group gap={12} align="stretch" wrap="nowrap" style={{ flex: 1, minWidth: 0 }}>
      <SplitView
        me={me}
        open={open}
        onClose={() => navigate(base)}
        header={header}
        list={
          <MessageList
            messages={messages}
            selectedId={open?.id}
            loading={res.isPending && q.trim() !== ''}
            onOpen={(m) => navigate(`${base}&m=${m.id}`, { replace: !!open })}
            empty={<Text c="dimmed">{q.trim() ? 'No messages match' : 'Search by words, people or operators'}</Text>}
          />
        }
      />
      {wide && (
        <Paper className="t-pane" p="md" w={240} style={{ flex: '0 0 auto', alignSelf: 'flex-start' }}>
          <Text fw={600} size="sm" mb="sm">
            Search operators
          </Text>
          <Stack gap={8}>
            {help.map(([op, what]) => (
              <Box key={op}>
                <Code>{op}</Code>
                <Text size="xs" c="dimmed">
                  {what}
                </Text>
              </Box>
            ))}
          </Stack>
        </Paper>
      )}
    </Group>
  )
}
