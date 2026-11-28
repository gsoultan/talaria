// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { ActionIcon, Anchor, Avatar, Badge, Box, Button, Center, Group, Loader, Menu, Paper, ScrollArea, Stack, Text, Title, Tooltip } from '@mantine/core'
import { useHotkeys } from '@mantine/hooks'
import { useEffect, useState } from 'react'
import { errorText } from '../../lib/errors'
import { avatarColor, bytes, fullDate, initials } from '../../lib/format'
import { Link } from '../../lib/router'
import { useMailActions } from './actions'
import { openCompose } from './composeStore'
import { bySpecial, displayName, sortMailboxes, useMailboxes } from './mailboxes'
import { AttachmentPreview } from './AttachmentPreview'
import { SecureMessage } from './SecureMessage'
import { forward, reply } from './reply'
import { Icon, icons } from './Shell'
import { type Attachment, type MessageSummary, useApiQuery } from '../../lib/api'

function ext(a: Attachment): string {
  const e = a.filename.split('.').pop()
  return (e && e !== a.filename ? e : a.contentType.split('/')[1] ?? 'file').slice(0, 4).toUpperCase()
}

function AuthBadges({ m }: { m: MessageSummary }) {
  if (!m.dkimPass && !m.spfPass && !m.dmarcPass) return null
  const b = (ok: boolean, label: string) =>
    ok && (
      <Badge key={label} size="sm" variant="light" color="green" radius="sm" tt="none">
        {label} pass
      </Badge>
    )
  return (
    <Group gap={4}>
      {b(m.dkimPass, 'DKIM')}
      {b(m.spfPass, 'SPF')}
      {b(m.dmarcPass, 'DMARC')}
    </Group>
  )
}

export function Attachments({ id, list }: { id: number; list: Attachment[] }) {
  const [open, setOpen] = useState<Attachment | null>(null)
  const files = list.filter((a) => !(a.inline && a.contentId))
  if (files.length === 0) return null
  return (
    <Group gap="sm" mt="lg">
      {files.map((a) => (
        <Paper
          key={a.part}
          withBorder
          p="xs"
          radius="md"
          component="button"
          type="button"
          onClick={() => setOpen(a)}
          title={`Preview ${a.filename || 'attachment'}`}
          className="t-plain"
          style={{ display: 'flex', alignItems: 'center', gap: 10, maxWidth: 280, cursor: 'pointer', textAlign: 'left', background: 'var(--t-surface)', font: 'inherit', color: 'inherit' }}
        >
          <Center w={36} h={36} bg={a.risky ? 'orange.0' : 'red.0'} c={a.risky ? 'orange.8' : 'red.8'} style={{ borderRadius: 6, fontSize: 11, fontWeight: 700, flex: '0 0 auto' }}>
            {ext(a)}
          </Center>
          <Box style={{ minWidth: 0 }}>
            <Text size="sm" fw={500} truncate>
              {a.filename || 'attachment'}
            </Text>
            <Text size="xs" c="dimmed">
              {bytes(a.size)} · Preview
            </Text>
          </Box>
        </Paper>
      ))}
      {open && <AttachmentPreview id={id} a={open} onClose={() => setOpen(null)} />}
    </Group>
  )
}

/** One open message, with its actions. onClose returns to the list on phones. */
export function Reader({ summary, onClose, me }: { summary: MessageSummary; onClose?: () => void; me: string[] }) {
  const q = useApiQuery('mail.GetMessage', { id: summary.id }, { staleTime: 10 * 60_000 })
  const boxes = useMailboxes().data?.mailboxes
  const act = useMailActions()
  // Opening marks read with a POST, so GetMessage stays free of side effects.
  const unseen = !summary.seen
  useEffect(() => {
    if (unseen) act.markSeen([summary.id], true)
  }, [summary.id])
  const d = q.data?.message
  const box = boxes?.find((b) => b.id === summary.mailboxId)
  const archive = bySpecial(boxes, '\\Archive')
  const junk = bySpecial(boxes, '\\Junk')
  const isDraft = box?.specialUse === '\\Drafts'

  const doArchive = () => {
    if (archive && box?.id !== archive.id) {
      act.move([summary.id], archive.id, 'Archived')
      onClose?.()
    }
  }
  const doDelete = () => {
    const purge = box?.specialUse === '\\Trash' || box?.specialUse === '\\Junk'
    act.remove([summary.id], purge ? 'Deleted' : 'Moved to Trash')
    onClose?.()
  }
  useHotkeys([
    ['r', () => reply(summary, d, false, me)],
    ['a', () => reply(summary, d, true, me)],
    ['f', () => forward(summary, d)],
    ['e', doArchive],
    ['#', doDelete],
    ['s', () => act.star([summary.id], !summary.flagged)],
    ['shift+u', () => act.markSeen([summary.id], false)],
  ])

  return (
    <Stack gap={0} h="100%">
      <Group gap={6} p="sm" style={{ borderBottom: '1px solid var(--t-border)' }} wrap="nowrap">
        {onClose && (
          <ActionIcon variant="subtle" color="gray" size="lg" onClick={onClose} aria-label="Back">
            <Icon d={icons.back} />
          </ActionIcon>
        )}
        {isDraft ? (
          <Button
            size="compact-md"
            onClick={() =>
              openCompose({
                draftId: summary.id,
                to: summary.to ? summary.to.split(',').map((s) => s.trim()) : [],
                cc: summary.cc ? summary.cc.split(',').map((s) => s.trim()) : [],
                subject: summary.subject,
                body: d?.textBody ?? '',
                inReplyTo: d?.inReplyTo || undefined,
              })
            }
          >
            Edit draft
          </Button>
        ) : (
          <Button.Group>
            <Button size="compact-md" variant="default" leftSection={<Icon d={icons.reply} size={15} />} onClick={() => reply(summary, d, false, me)}>
              Reply
            </Button>
            <Button size="compact-md" variant="default" leftSection={<Icon d={icons.replyAll} size={15} />} onClick={() => reply(summary, d, true, me)} visibleFrom="sm">
              Reply all
            </Button>
            <Button size="compact-md" variant="default" leftSection={<Icon d={icons.forward} size={15} />} onClick={() => forward(summary, d)}>
              Forward
            </Button>
          </Button.Group>
        )}
        <Group gap={2} ml="auto" wrap="nowrap">
          {archive && box?.id !== archive.id && (
            <Tooltip label="Archive (e)">
              <ActionIcon variant="subtle" color="gray" size="lg" onClick={doArchive} aria-label="Archive">
                <Icon d={icons.archive} />
              </ActionIcon>
            </Tooltip>
          )}
          <Tooltip label="Delete (#)">
            <ActionIcon variant="subtle" color="gray" size="lg" onClick={doDelete} aria-label="Delete">
              <Icon d={icons.trash} />
            </ActionIcon>
          </Tooltip>
          <Tooltip label={summary.flagged ? 'Unstar (s)' : 'Star (s)'}>
            <ActionIcon variant="subtle" color={summary.flagged ? 'yellow' : 'gray'} size="lg" onClick={() => act.star([summary.id], !summary.flagged)} aria-label="Star" aria-pressed={summary.flagged}>
              <Icon d={icons.star} />
            </ActionIcon>
          </Tooltip>
          <Menu position="bottom-end">
            <Menu.Target>
              <ActionIcon variant="subtle" color="gray" size="lg" aria-label="More">
                <Icon d={icons.more} />
              </ActionIcon>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item onClick={() => act.markSeen([summary.id], false)}>Mark as unread</Menu.Item>
              {junk && box?.id !== junk.id && (
                <Menu.Item
                  onClick={() => {
                    act.move([summary.id], junk.id, 'Moved to Junk')
                    onClose?.()
                  }}
                >
                  Report junk
                </Menu.Item>
              )}
              {summary.threadId > 0 && (
                <Menu.Item component={Link} to={`/thread/${summary.threadId}`}>
                  Show conversation
                </Menu.Item>
              )}
              <Menu.Item component="a" href={`/api/v1/messages/${summary.id}/raw`} download>
                Download original
              </Menu.Item>
              <Menu.Divider />
              <Menu.Label>Move to</Menu.Label>
              {sortMailboxes(boxes ?? [])
                .filter((b) => b.id !== summary.mailboxId && b.specialUse !== '\\Drafts' && b.specialUse !== '\\Sent')
                .map((b) => (
                  <Menu.Item
                    key={b.id.toString()}
                    onClick={() => {
                      act.move([summary.id], b.id, `Moved to ${displayName(b)}`)
                      onClose?.()
                    }}
                  >
                    {displayName(b)}
                  </Menu.Item>
                ))}
            </Menu.Dropdown>
          </Menu>
        </Group>
      </Group>
      <ScrollArea style={{ flex: 1 }} type="auto">
        <Box p="lg" maw={920}>
          <Title order={3} mb="md" style={{ overflowWrap: 'anywhere' }}>
            {summary.subject || '(no subject)'}
          </Title>
          <Group align="flex-start" gap="sm" wrap="nowrap" mb="lg">
            <Avatar radius="xl" color={avatarColor(summary.fromAddr)}>
              {initials(summary.fromName, summary.fromAddr)}
            </Avatar>
            <Box style={{ flex: 1, minWidth: 0 }}>
              <Group gap={6} wrap="wrap">
                <Text fw={600} size="sm">
                  {summary.fromName || summary.fromAddr}
                </Text>
                {summary.fromName && (
                  <Text size="sm" c="dimmed">
                    &lt;{summary.fromAddr}&gt;
                  </Text>
                )}
              </Group>
              <Text size="xs" c="dimmed" truncate>
                to {summary.to || 'undisclosed recipients'}
                {summary.cc ? `, cc ${summary.cc}` : ''} · {fullDate(summary.sentDate || summary.date)}
              </Text>
            </Box>
            <AuthBadges m={summary} />
          </Group>
          {q.isPending && !d ? (
            <Center p="xl">
              <Loader size="sm" />
            </Center>
          ) : q.error && !d ? (
            <Text c="red" size="sm">
              {errorText(q.error)}{' '}
              <Anchor size="sm" onClick={() => void q.refetch()}>
                Try again
              </Anchor>
            </Text>
          ) : d ? (
            <>
              <SecureMessage id={summary.id} detail={d} sender={summary.fromAddr} />
            </>
          ) : null}
        </Box>
      </ScrollArea>
    </Stack>
  )
}
