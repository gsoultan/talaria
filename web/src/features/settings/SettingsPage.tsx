// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery } from '@connectrpc/connect-query'
import { Alert, Anchor, Box, Button, Code, CopyButton, Group, Kbd, NavLink, Paper, PasswordInput, SegmentedControl, Stack, Table, Text, Title, useMantineColorScheme } from '@mantine/core'
import { useMediaQuery } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import { useForm } from '@tanstack/react-form'
import type { ReactNode } from 'react'
import { AuthService } from '../../gen/talaria/v1/auth_pb'
import { MailService } from '../../gen/talaria/v1/mail_pb'
import { errorText } from '../../lib/errors'
import { bytes } from '../../lib/format'
import { Link, useLocation } from '../../lib/router'
import { useMe } from '../auth/useMe'

const sections = [
  { id: 'account', label: 'Account and password' },
  { id: 'apps', label: 'Mail apps' },
  { id: 'appearance', label: 'Appearance' },
  { id: 'shortcuts', label: 'Keyboard shortcuts' },
]

function Section({ title, children, sub }: { title: string; sub?: string; children: ReactNode }) {
  return (
    <Paper className="t-pane" p="lg" radius="lg">
      <Title order={3} mb={sub ? 4 : 'md'}>
        {title}
      </Title>
      {sub && (
        <Text size="sm" c="dimmed" mb="md">
          {sub}
        </Text>
      )}
      {children}
    </Paper>
  )
}

function Account() {
  const me = useMe().data?.user
  const change = useMutation(AuthService.method.changePassword)
  const form = useForm({
    defaultValues: { current: '', next: '', confirm: '' },
    onSubmit: async ({ value, formApi }) => {
      try {
        await change.mutateAsync({ currentPassword: value.current, newPassword: value.next })
        notifications.show({ color: 'green', message: 'Password changed. Other devices are signed out.' })
        formApi.reset()
      } catch {
        // Shown below.
      }
    },
  })
  return (
    <Section title="Account and password">
      <Stack gap={4} mb="lg">
        <Text fw={600}>{me?.displayName || me?.email}</Text>
        <Text size="sm" c="dimmed">
          {me?.email} · {me?.tenantName}
        </Text>
        {me && (
          <Text size="sm" c="dimmed">
            {bytes(me.usedBytes)} used{me.quotaBytes > 0n ? ` of ${bytes(me.quotaBytes)}` : ''}
          </Text>
        )}
      </Stack>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void form.handleSubmit()
        }}
      >
        <Stack maw={380} gap="sm">
          <Text fw={600} size="sm">
            Change password
          </Text>
          <form.Field name="current" validators={{ onSubmit: ({ value }) => (value ? undefined : 'Enter your current password') }}>
            {(f) => <PasswordInput label="Current password" autoComplete="current-password" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0]} />}
          </form.Field>
          <form.Field name="next" validators={{ onSubmit: ({ value }) => (value.length >= 8 ? undefined : 'Use at least 8 characters') }}>
            {(f) => <PasswordInput label="New password" autoComplete="new-password" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0]} />}
          </form.Field>
          <form.Field name="confirm" validators={{ onSubmit: ({ value, fieldApi }) => (value === fieldApi.form.getFieldValue('next') ? undefined : 'The passwords don’t match') }}>
            {(f) => <PasswordInput label="New password again" autoComplete="new-password" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0]} />}
          </form.Field>
          {change.error && (
            <Alert color="red" variant="light" p="xs">
              {errorText(change.error)}
            </Alert>
          )}
          <form.Subscribe selector={(s) => s.isSubmitting}>
            {(busy) => (
              <Button type="submit" loading={busy} w="fit-content">
                Change password
              </Button>
            )}
          </form.Subscribe>
        </Stack>
      </form>
    </Section>
  )
}

function Apps() {
  const q = useQuery(MailService.method.getMailSettings, {}, { staleTime: 60 * 60_000 })
  const me = useMe().data?.user
  const host = q.data?.hostname ?? window.location.hostname
  const by = (p: string) => (q.data?.endpoints ?? []).filter((e) => e.protocol === p)
  const rows = [
    { name: 'IMAP', what: 'Reading mail, kept in sync on every device', eps: by('IMAP') },
    { name: 'POP3', what: 'Downloads the Inbox to one device', eps: by('POP3') },
    { name: 'SMTP', what: 'Sending mail', eps: by('SMTP') },
  ].filter((r) => r.eps.length > 0)
  return (
    <Section title="Mail apps" sub="Use these in Thunderbird, Apple Mail, Outlook or any phone mail app. Sign in with your full email address and your password.">
      {q.isPending ? null : rows.length === 0 ? (
        <Alert variant="light" color="gray">
          Mail apps aren’t set up on this server yet. Ask your administrator.
        </Alert>
      ) : (
        <Table withTableBorder={false} verticalSpacing="sm">
          <Table.Tbody>
            {rows.map((r) => (
              <Table.Tr key={r.name}>
                <Table.Td w={90}>
                  <Text fw={600}>{r.name}</Text>
                </Table.Td>
                <Table.Td>
                  <Group gap={6}>
                    <Code>{host}</Code>
                    <CopyButton value={host}>
                      {({ copied, copy }) => (
                        <Anchor size="xs" onClick={copy}>
                          {copied ? 'Copied' : 'Copy'}
                        </Anchor>
                      )}
                    </CopyButton>
                  </Group>
                  <Text size="xs" c="dimmed" mt={4}>
                    {r.eps.map((e) => `${e.port} ${e.security}`).join(', or ')} · {r.what}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
            <Table.Tr>
              <Table.Td>
                <Text fw={600}>Username</Text>
              </Table.Td>
              <Table.Td>
                <Code>{me?.email}</Code>
              </Table.Td>
            </Table.Tr>
          </Table.Tbody>
        </Table>
      )}
    </Section>
  )
}

function Appearance() {
  const { colorScheme, setColorScheme } = useMantineColorScheme()
  return (
    <Section title="Appearance">
      <SegmentedControl
        value={colorScheme}
        onChange={(v) => setColorScheme(v as 'light' | 'dark' | 'auto')}
        data={[
          { value: 'auto', label: 'Match device' },
          { value: 'light', label: 'Light' },
          { value: 'dark', label: 'Dark' },
        ]}
      />
    </Section>
  )
}

const keys: [string, string][] = [
  ['c', 'Compose'],
  ['/', 'Search'],
  ['j / k', 'Next / previous message'],
  ['r', 'Reply'],
  ['a', 'Reply all'],
  ['f', 'Forward'],
  ['e', 'Archive'],
  ['#', 'Delete'],
  ['s', 'Star'],
  ['Shift + u', 'Mark unread'],
  ['Ctrl + Enter', 'Send'],
]

function Shortcuts() {
  return (
    <Section title="Keyboard shortcuts">
      <Table maw={420}>
        <Table.Tbody>
          {keys.map(([k, what]) => (
            <Table.Tr key={k}>
              <Table.Td w={140}>
                <Kbd>{k}</Kbd>
              </Table.Td>
              <Table.Td>{what}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Section>
  )
}

export function SettingsPage({ section }: { section?: string }) {
  const { path } = useLocation()
  const narrow = useMediaQuery('(max-width: 62em)', false)
  const cur = sections.find((s) => s.id === section)?.id ?? 'account'
  const body = { account: <Account />, apps: <Apps />, appearance: <Appearance />, shortcuts: <Shortcuts /> }[cur]
  return (
    <Box style={{ flex: 1, minWidth: 0, overflow: 'auto' }} p={narrow ? 'sm' : 0}>
      <Group align="flex-start" gap="lg" wrap={narrow ? 'wrap' : 'nowrap'} maw={1100}>
        <Stack gap={2} w={narrow ? '100%' : 220} style={{ flex: '0 0 auto' }}>
          <Anchor component={Link} to="/mail/inbox" size="sm" mb="sm">
            ← Back to mail
          </Anchor>
          <Title order={2} mb="sm">
            Settings
          </Title>
          {sections.map((s) => (
            <NavLink key={s.id} component={Link} to={`/settings/${s.id}`} label={s.label} active={path === `/settings/${s.id}` || (cur === s.id && path === '/settings')} style={{ borderRadius: 8 }} />
          ))}
        </Stack>
        <Box style={{ flex: 1, minWidth: 0 }} w="100%">
          {body}
        </Box>
      </Group>
    </Box>
  )
}
