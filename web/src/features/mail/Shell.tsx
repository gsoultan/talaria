// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery } from '@connectrpc/connect-query'
import { ActionIcon, Avatar, Badge, Box, Burger, Button, Drawer, Group, Kbd, Menu, Progress, ScrollArea, Stack, Text, TextInput, Tooltip, UnstyledButton } from '@mantine/core'
import { useDisclosure, useHotkeys, useMediaQuery } from '@mantine/hooks'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { LogoMark } from '../../components/Logo'
import { AuthService } from '../../gen/talaria/v1/auth_pb'
import { MailService } from '../../gen/talaria/v1/mail_pb'
import { bytes, initials } from '../../lib/format'
import type { LiveState } from '../../lib/live'
import { onOutboxChange } from '../../lib/outbox'
import { clearCache } from '../../lib/queryClient'
import { Link, navigate, useLocation } from '../../lib/router'
import { isAdmin, useMe } from '../auth/useMe'
import { openCompose } from './composeStore'
import { displayName, slugOf, sortMailboxes, useMailboxes } from './mailboxes'

function Icon({ d, size = 18 }: { d: string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={d} />
    </svg>
  )
}

export const icons = {
  inbox: 'M22 12h-6l-2 3h-4l-2-3H2 M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z',
  sent: 'M22 2 11 13 M22 2l-7 20-4-9-9-4 20-7z',
  drafts: 'M12 20h9 M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
  archive: 'M21 8v13H3V8 M1 3h22v5H1z M10 12h4',
  junk: 'M12 9v4 M12 17h.01 M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  trash: 'M3 6h18 M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6 M10 11v6 M14 11v6 M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2',
  folder: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z',
  star: 'M12 2l3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z',
  search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14z M21 21l-4.35-4.35',
  plus: 'M12 5v14 M5 12h14',
  settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2 M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  back: 'M19 12H5 M12 19l-7-7 7-7',
  reply: 'M9 17l-5-5 5-5 M20 18v-2a4 4 0 0 0-4-4H4',
  replyAll: 'M7 17l-5-5 5-5 M12 17l-5-5 5-5 M22 18v-2a4 4 0 0 0-4-4H7',
  forward: 'M15 17l5-5-5-5 M4 18v-2a4 4 0 0 1 4-4h12',
  mail: 'M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z M22 6l-10 7L2 6',
  paperclip: 'M21.4 11.1l-9.2 9.2a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2a2 2 0 0 1-2.8-2.8l8.5-8.5',
  close: 'M18 6 6 18 M6 6l12 12',
  more: 'M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z M19 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z M5 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2z',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  thread: 'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z',
}

export { Icon }

const folderIcon: Record<string, string> = {
  '\\Inbox': icons.inbox,
  '\\Sent': icons.sent,
  '\\Drafts': icons.drafts,
  '\\Archive': icons.archive,
  '\\Junk': icons.junk,
  '\\Trash': icons.trash,
}

function LiveBadge({ state, outbox }: { state: LiveState; outbox: number }) {
  if (state === 'live' && outbox === 0)
    return (
      <Badge color="green" variant="light" radius="xl" tt="none" style={{ flexShrink: 0 }}>
        Live
      </Badge>
    )
  if (state === 'offline')
    return (
      <Tooltip label={outbox ? `${outbox} waiting in the outbox` : 'Showing saved mail'}>
        <Badge color="orange" variant="light" radius="xl" tt="none" style={{ flexShrink: 0 }}>
          Offline{outbox ? ` · ${outbox} to send` : ''}
        </Badge>
      </Tooltip>
    )
  return <Badge color="gray" variant="light" radius="xl" tt="none">{outbox ? `Sending ${outbox}…` : 'Connecting…'}</Badge>
}

export function useOutboxCount() {
  const [n, setN] = useState(0)
  useEffect(() => onOutboxChange(setN), [])
  return n
}

function SearchBox({ onDone }: { onDone?: () => void }) {
  const { path, query } = useLocation()
  const [q, setQ] = useState(path === '/search' ? (query.get('q') ?? '') : '')
  const ref = useRef<HTMLInputElement>(null)
  useHotkeys([['/', () => ref.current?.focus()]])
  return (
    <form
      role="search"
      style={{ flex: '1 1 320px', maxWidth: 640 }}
      onSubmit={(e) => {
        e.preventDefault()
        navigate(`/search?q=${encodeURIComponent(q.trim())}`)
        onDone?.()
        ref.current?.blur()
      }}
    >
      <TextInput
        ref={ref}
        aria-label="Search mail"
        placeholder="Search mail   from:  has:attachment  before:"
        value={q}
        onChange={(e) => setQ(e.currentTarget.value)}
        leftSection={<Icon d={icons.search} size={16} />}
        rightSection={<Kbd size="xs" visibleFrom="sm">/</Kbd>}
        variant="filled"
        radius="md"
        size="sm"
      />
    </form>
  )
}

function AccountMenu() {
  const me = useMe().data?.user
  const logout = useMutation(AuthService.method.logout)
  return (
    <Menu position="bottom-end" width={240}>
      <Menu.Target>
        <UnstyledButton aria-label="Account">
          <Avatar color="blue" radius="xl" size={34}>
            {initials(me?.displayName ?? '', me?.email)}
          </Avatar>
        </UnstyledButton>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>
          <Text size="sm" fw={600} c="var(--mantine-color-text)">
            {me?.displayName || me?.email}
          </Text>
          <Text size="xs">{me?.email}</Text>
        </Menu.Label>
        <Menu.Item component={Link} to="/settings">
          Settings
        </Menu.Item>
        {isAdmin(me) && (
          <Menu.Item component={Link} to="/admin">
            Admin
          </Menu.Item>
        )}
        <Menu.Divider />
        <Menu.Item
          color="red"
          onClick={async () => {
            await logout.mutateAsync({}).catch(() => {})
            await clearCache()
            window.location.href = '/'
          }}
        >
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  )
}

function Identities() {
  const { data } = useQuery(MailService.method.listIdentities, {}, { staleTime: 10 * 60_000 })
  const ids = data?.identities ?? []
  if (ids.length < 2) return null
  return (
    <Stack gap={2} mt="md">
      <Text size="xs" fw={600} c="dimmed" tt="uppercase" px={12}>
        Addresses
      </Text>
      {ids.map((i) => (
        <Text key={i.address} size="sm" px={12} py={4} truncate c="dimmed" title={i.address}>
          {i.address}
        </Text>
      ))}
    </Stack>
  )
}

export function Folders({ onPick }: { onPick?: () => void }) {
  const { data } = useMailboxes()
  const { path } = useLocation()
  const me = useMe().data?.user
  const boxes = sortMailboxes(data?.mailboxes ?? [])
  const active = path.split('/')[2] ?? ''
  const quota = me ? Number(me.quotaBytes) : 0
  return (
    <Stack gap={4} h="100%">
      <Button
        size="md"
        radius="md"
        leftSection={<Icon d={icons.plus} size={16} />}
        mb="sm"
        onClick={() => {
          openCompose()
          onPick?.()
        }}
      >
        Compose
      </Button>
      <nav aria-label="Folders">
        <Stack gap={2}>
          {boxes.map((m) => (
            <Link key={m.id.toString()} to={`/mail/${slugOf(m)}`} className="t-folder" data-active={path.startsWith('/mail/') && active === slugOf(m)} onClick={onPick}>
              <Icon d={folderIcon[m.specialUse] ?? icons.folder} size={16} />
              <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{displayName(m)}</span>
              {m.unread > 0n && m.specialUse !== '\\Sent' && m.specialUse !== '\\Trash' && (
                <Text size="xs" fw={600}>
                  {m.unread.toLocaleString()}
                </Text>
              )}
            </Link>
          ))}
          <Link to="/starred" className="t-folder" data-active={path === '/starred'} onClick={onPick}>
            <Icon d={icons.star} size={16} />
            <span style={{ flex: 1 }}>Starred</span>
          </Link>
        </Stack>
      </nav>
      <Identities />
      {me && (
        <Box mt="auto" px={12} pt="md">
          {quota > 0 && <Progress value={(Number(me.usedBytes) / quota) * 100} size="sm" mb={6} aria-label="Storage used" />}
          <Text size="xs" c="dimmed">
            {bytes(me.usedBytes)}
            {quota > 0 ? ` of ${bytes(quota)} used` : ' used'}
          </Text>
        </Box>
      )}
    </Stack>
  )
}

function BottomNav() {
  const { path } = useLocation()
  const item = (to: string, label: string, d: string, active: boolean) => (
    <Link to={to} className="t-plain" style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, padding: '8px 0', color: active ? 'var(--mantine-color-blue-7)' : 'var(--t-muted)' }}>
      <Icon d={d} size={20} />
      <Text size="xs" fw={active ? 600 : 400}>
        {label}
      </Text>
    </Link>
  )
  return (
    <nav aria-label="Sections" style={{ display: 'flex', borderTop: '1px solid var(--t-border)', background: 'var(--t-surface)', paddingBottom: 'env(safe-area-inset-bottom)' }}>
      {item('/mail/inbox', 'Inbox', icons.inbox, path.startsWith('/mail/inbox'))}
      {item('/starred', 'Starred', icons.star, path === '/starred')}
      {item('/mail/sent', 'Sent', icons.sent, path.startsWith('/mail/sent'))}
      {item('/settings', 'Account', icons.user, path.startsWith('/settings'))}
    </nav>
  )
}

/** The signed-in frame: header, folders, and the page in the middle. */
export function Shell({ live, children }: { live: LiveState; children: ReactNode }) {
  const mobile = useMediaQuery('(max-width: 62em)', false)
  const [drawer, { open, close }] = useDisclosure(false)
  const outbox = useOutboxCount()
  useHotkeys([['c', () => openCompose()]])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <header style={{ height: 56, flex: '0 0 auto', display: 'flex', alignItems: 'center', gap: 12, padding: '0 12px', background: 'var(--t-surface)', borderBottom: '1px solid var(--t-border)' }}>
        {mobile && <Burger opened={drawer} onClick={open} size="sm" aria-label="Folders" />}
        <Link to="/mail/inbox" className="t-plain" style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: mobile ? 0 : 204 }}>
          <LogoMark />
          {!mobile && (
            <Text fw={700} size="lg">
              Talaria
            </Text>
          )}
        </Link>
        <SearchBox />
        <Group gap={8} ml="auto" wrap="nowrap">
          {(!mobile || live !== 'live' || outbox > 0) && <LiveBadge state={live} outbox={outbox} />}
          {!mobile && (
            <Tooltip label="Settings">
              <ActionIcon variant="subtle" color="gray" size="lg" component={Link} to="/settings" aria-label="Settings">
                <Icon d={icons.settings} />
              </ActionIcon>
            </Tooltip>
          )}
          <AccountMenu />
        </Group>
      </header>
      <div style={{ flex: 1, minHeight: 0, display: 'flex' }}>
        {!mobile && (
          <aside style={{ width: 236, flex: '0 0 auto', padding: '16px 12px' }}>
            <ScrollArea h="100%" type="hover">
              <div style={{ minHeight: 'calc(100vh - 90px)', display: 'flex', flexDirection: 'column' }}>
                <Folders />
              </div>
            </ScrollArea>
          </aside>
        )}
        <main style={{ flex: 1, minWidth: 0, minHeight: 0, display: 'flex', padding: mobile ? 0 : '12px 12px 12px 0' }}>{children}</main>
      </div>
      {mobile && <BottomNav />}
      <Drawer opened={drawer} onClose={close} size={280} title="Folders">
        <Folders onPick={close} />
      </Drawer>
    </div>
  )
}
