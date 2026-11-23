// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Anchor, Avatar, Box, Button, Center, Group, Loader, Paper, ScrollArea, Stack, Text, Textarea, Title, UnstyledButton } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { errorText, isNetworkError } from '../../lib/errors'
import { avatarColor, fullDate, initials, listDate, plural, splitAddresses } from '../../lib/format'
import { queueOffline } from '../../lib/outbox'
import { useMailActions } from './actions'
import { MessageBody } from './MessageBody'
import { Attachments } from './Reader'
import { reply } from './reply'
import { Icon, icons } from './Shell'
import { useMyAddresses } from './MailPage'
import { type MessageSummary, ofOps, useApiMutation, useApiQuery } from '../../lib/api'

function Expanded({ m }: { m: MessageSummary }) {
  const q = useApiQuery('mail.GetMessage', { id: m.id }, { staleTime: 10 * 60_000 })
  const d = q.data?.message
  return (
    <Box>
      <Group align="flex-start" gap="sm" wrap="nowrap" mb="md">
        <Avatar radius="xl" color={avatarColor(m.fromAddr)}>
          {initials(m.fromName, m.fromAddr)}
        </Avatar>
        <Box style={{ flex: 1, minWidth: 0 }}>
          <Group gap={6}>
            <Text fw={600} size="sm">
              {m.fromName || m.fromAddr}
            </Text>
            {m.fromName && (
              <Text size="sm" c="dimmed">
                &lt;{m.fromAddr}&gt;
              </Text>
            )}
            {m.dmarcPass && (
              <Text size="xs" c="green.7" fw={500}>
                Verified sender
              </Text>
            )}
          </Group>
          <Text size="xs" c="dimmed" truncate>
            to {m.to} · {fullDate(m.sentDate || m.date)}
          </Text>
        </Box>
      </Group>
      {d ? (
        <>
          <MessageBody id={m.id} detail={d} sender={m.fromAddr} />
          <Attachments id={m.id} list={d.attachments} />
        </>
      ) : q.error ? (
        <Text c="red" size="sm">
          {errorText(q.error)}
        </Text>
      ) : (
        <Loader size="sm" />
      )}
    </Box>
  )
}

function QuickReply({ last, me }: { last: MessageSummary; me: string[] }) {
  const qc = useQueryClient()
  const detail = useApiQuery('mail.GetMessage', { id: last.id }, { staleTime: 10 * 60_000 }).data?.message
  const send = useApiMutation('mail.SendMessage')
  const [text, setText] = useState('')
  const mine = new Set(me.map((a) => a.toLowerCase()))
  const others = [...new Set([last.fromAddr, ...splitAddresses(last.to), ...splitAddresses(last.cc)].map((a) => (/<([^>]+)>/.exec(a)?.[1] ?? a).trim().toLowerCase()))].filter((a) => a && !mine.has(a))
  const nameOf = (a: string) => (a === last.fromAddr.toLowerCase() && last.fromName ? last.fromName : a)
  const names = others.map(nameOf).join(', ')

  const submit = async () => {
    if (!text.trim() || others.length === 0) return
    const refs = [...(detail?.headers.find((h) => h.name.toLowerCase() === 'references')?.value.split(/\s+/).filter(Boolean) ?? []), detail?.messageId ?? ''].filter(Boolean)
    const msg = {
      to: [others[0]!],
      cc: others.slice(1),
      subject: /^re:/i.test(last.subject) ? last.subject : `Re: ${last.subject}`,
      textBody: text,
      inReplyTo: detail?.messageId ?? '',
      references: refs,
    }
    try {
      await send.mutateAsync({ message: msg })
      setText('')
      notifications.show({ color: 'green', message: 'Sent', autoClose: 2500 })
      void qc.invalidateQueries({ predicate: ofOps('mail.GetThread', 'mail.ListMailboxes') })
    } catch (err) {
      if (isNetworkError(err)) {
        await queueOffline(msg)
        setText('')
        notifications.show({ color: 'orange', message: 'You’re offline. It’s in the outbox.' })
      } else notifications.show({ color: 'red', message: errorText(err) })
    }
  }

  return (
    <Paper withBorder radius="md" p="sm">
      <Text size="xs" c="dimmed" mb={6}>
        Reply to all: {names || 'nobody else'}
      </Text>
      <Textarea
        aria-label="Reply"
        placeholder="Write a reply"
        value={text}
        onChange={(e) => setText(e.currentTarget.value)}
        autosize
        minRows={3}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault()
            void submit()
          }
        }}
      />
      <Group mt="sm" gap="sm">
        <Button size="sm" onClick={() => void submit()} loading={send.isPending} disabled={!text.trim() || others.length === 0}>
          Send
        </Button>
        <Anchor size="sm" onClick={() => reply(last, detail, true, me)}>
          Open full editor
        </Anchor>
        <Text size="xs" c="dimmed" ml="auto" visibleFrom="sm">
          Ctrl + Enter to send
        </Text>
      </Group>
    </Paper>
  )
}

export function ThreadPage({ id }: { id: string }) {
  const q = useApiQuery('mail.GetThread', { threadId: Number(id) })
  const me = useMyAddresses()
  const act = useMailActions()
  const msgs = q.data?.messages ?? []
  const [open, setOpen] = useState<Set<number>>(new Set())
  const last = msgs[msgs.length - 1]

  useEffect(() => {
    const unseen = msgs.filter((m) => !m.seen).map((m) => m.id)
    if (unseen.length) act.markSeen(unseen, true)
    // Only when the thread first loads.
  }, [q.isSuccess, id])

  if (q.isPending)
    return (
      <Center style={{ flex: 1 }}>
        <Loader size="sm" />
      </Center>
    )
  if (!last)
    return (
      <Center style={{ flex: 1 }}>
        <Text c="dimmed">{q.error ? errorText(q.error) : 'This conversation is empty.'}</Text>
      </Center>
    )

  return (
    <Box className="t-pane" style={{ flex: 1, minWidth: 0 }}>
      <ScrollArea h="100%">
        <Box p="lg" maw={920} mx="auto">
          <Anchor size="sm" onClick={() => window.history.back()} mb="sm" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
            <Icon d={icons.back} size={14} /> Back
          </Anchor>
          <Title order={2} style={{ overflowWrap: 'anywhere' }}>
            {msgs[0]?.subject || '(no subject)'}
          </Title>
          <Text size="sm" c="dimmed" mb="lg">
            {plural(msgs.length, 'message')}
          </Text>
          <Stack gap="sm">
            {msgs.map((m) =>
              m === last || open.has(m.id) ? (
                <Paper key={m.id.toString()} withBorder radius="md" p="md">
                  <Expanded m={m} />
                </Paper>
              ) : (
                <UnstyledButton key={m.id.toString()} onClick={() => setOpen(new Set(open).add(m.id))} className="t-row" style={{ border: '1px solid var(--t-border)', borderRadius: 8, padding: '10px 14px', display: 'flex', gap: 12, alignItems: 'center' }}>
                  <Avatar size={30} radius="xl" color={avatarColor(m.fromAddr)}>
                    {initials(m.fromName, m.fromAddr)}
                  </Avatar>
                  <Text size="sm" fw={600} style={{ flex: '0 0 auto' }}>
                    {m.fromName || m.fromAddr}
                  </Text>
                  <Text size="sm" c="dimmed" truncate style={{ flex: 1 }}>
                    {m.preview}
                  </Text>
                  <Text size="xs" c="dimmed">
                    {listDate(m.date)}
                  </Text>
                </UnstyledButton>
              ),
            )}
            <QuickReply last={last} me={me} />
          </Stack>
        </Box>
      </ScrollArea>
    </Box>
  )
}
