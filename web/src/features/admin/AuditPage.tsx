// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge, Button, Code, Group, Paper, Select, Table, Text, TextInput } from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { Fragment, useState } from 'react'
import { type AuditEntry, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { fullDate } from '../../lib/format'
import { PageTitle, useTenant } from './AdminShell'

const kinds = [
  { value: '', label: 'Everything' },
  { value: 'sign_in', label: 'Sign-ins' },
  { value: 'sign_in_failed', label: 'Failed sign-ins' },
  { value: 'admin.', label: 'Admin actions' },
  { value: 'admin.GetHeldMail', label: 'Admins reading held mail' },
  { value: 'policy.', label: 'Policy matches' },
  { value: 'quarantine.', label: 'Released from quarantine' },
  { value: 'cli.', label: 'Command line' },
]

const ranges = [
  { value: '1', label: 'Last 24 hours' },
  { value: '7', label: 'Last 7 days' },
  { value: '30', label: 'Last 30 days' },
  { value: '365', label: 'Last year' },
  { value: '0', label: 'All time' },
]

/** Admin operation names, as people would say them. */
function words(op: string): string {
  return op
    .replace(/DLP/g, 'Dlp ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .replace(/^./, (c) => c.toUpperCase())
    .replace(/dlp/gi, 'DLP')
    .replace(/dkim/gi, 'DKIM')
    .trim()
}

function describe(e: AuditEntry): string {
  if (e.action === 'sign_in') return 'Signed in'
  if (e.action === 'sign_in_failed') return 'Sign-in failed'
  if (e.action === 'sign_out') return 'Signed out'
  if (e.action === 'password_change') return 'Changed password'
  if (e.action === 'policy.dlp') return 'Data loss prevention match'
  if (e.action === 'policy.link') return 'Opened a flagged link'
  if (e.action === 'quarantine.release') return 'Released held mail'
  if (e.action === 'admin.GetHeldMail') return 'Read held mail'
  if (e.action.startsWith('admin.')) return words(e.action.slice(6))
  if (e.action.startsWith('cli.')) return `Command line: ${e.action.slice(4)}`
  return e.action
}

function via(e: AuditEntry): string {
  try {
    const d = JSON.parse(e.detail || '{}') as { via?: string }
    return d.via ? ` via ${d.via === 'web' ? 'webmail' : d.via.toUpperCase()}` : ''
  } catch {
    return ''
  }
}

function Outcome({ o }: { o: string }) {
  if (o === 'ok') return null
  const color = o === 'warned' ? 'orange' : o === 'encrypt' || o === 'notify' ? 'blue' : 'red'
  return (
    <Badge color={color} variant="light" tt="none" size="sm">
      {o.replace(/_/g, ' ')}
    </Badge>
  )
}

function pretty(detail: string): string {
  try {
    return JSON.stringify(JSON.parse(detail), null, 2)
  } catch {
    return detail
  }
}

export function AuditPage() {
  const tenant = useTenant()
  const [action, setAction] = useState('')
  const [range, setRange] = useState('30')
  const [q, setQ] = useState('')
  const [dq] = useDebouncedValue(q.trim(), 300)
  // Older pages: the stack of "before" cursors.
  const [cursors, setCursors] = useState<number[]>([])
  const [open, setOpen] = useState<number | null>(null)
  const before = cursors.at(-1) ?? 0
  // Whole minutes, so the query key holds still between renders.
  const since = range === '0' ? 0 : Math.floor(Date.now() / 60_000) * 60 - Number(range) * 86400
  const input = { tenantId: tenant, action, q: dq, since, before }
  const res = useApiQuery('admin.ListAudit', input, { placeholderData: (prev) => prev })
  const entries = res.data?.entries ?? []
  const reset = () => setCursors([])
  const csv = new URLSearchParams({ tenantId: String(tenant), action, q: dq, since: String(since) })
  return (
    <>
      <PageTitle
        title="Audit log"
        sub="Sign-ins, admin actions, admins reading held mail, and policy matches. Entries cannot be changed or deleted."
        right={
          <Button component="a" variant="default" href={`/api/v1/admin/audit.csv?${csv}`} download>
            Export CSV
          </Button>
        }
      />
      <Group mb="sm" gap="sm" wrap="wrap">
        <Select aria-label="Show" w={230} value={action} data={kinds} allowDeselect={false} onChange={(v) => (setAction(v ?? ''), reset())} />
        <Select aria-label="Period" w={160} value={range} data={ranges} allowDeselect={false} onChange={(v) => (setRange(v ?? '30'), reset())} />
        <TextInput aria-label="Search" placeholder="Search by address, IP or detail" value={q} onChange={(e) => (setQ(e.currentTarget.value), reset())} style={{ flex: '1 1 240px' }} />
      </Group>
      <Paper className="t-pane" radius="lg">
        <Table.ScrollContainer minWidth={820}>
          <Table verticalSpacing="xs" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th w={190}>When</Table.Th>
                <Table.Th>Who</Table.Th>
                <Table.Th>What</Table.Th>
                <Table.Th>On</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {entries.map((e) => (
                <Fragment key={e.id}>
                  <Table.Tr style={{ cursor: e.detail ? 'pointer' : undefined }} onClick={() => e.detail && setOpen(open === e.id ? null : e.id)} aria-expanded={e.detail ? open === e.id : undefined}>
                    <Table.Td>
                      <Text size="sm">{fullDate(e.at)}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{e.actor || '—'}</Text>
                      {e.ip && (
                        <Text size="xs" c="dimmed">
                          {e.ip}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <Text size="sm">
                          {describe(e)}
                          {via(e)}
                        </Text>
                        <Outcome o={e.outcome} />
                      </Group>
                    </Table.Td>
                    <Table.Td maw={340}>
                      <Text size="sm" c="dimmed" truncate="end" title={e.target}>
                        {e.target || '—'}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                  {open === e.id && (
                    <Table.Tr>
                      <Table.Td colSpan={4}>
                        <Code block>{pretty(e.detail)}</Code>
                      </Table.Td>
                    </Table.Tr>
                  )}
                </Fragment>
              ))}
              {res.isSuccess && entries.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={4}>
                    <Text c="dimmed" size="sm" ta="center" py="md">
                      Nothing matches.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
              {res.error && (
                <Table.Tr>
                  <Table.Td colSpan={4}>
                    <Text c="red" size="sm" ta="center" py="md">
                      {errorText(res.error)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>
      <Group justify="space-between" mt="sm">
        <Button variant="default" size="xs" disabled={cursors.length === 0} onClick={() => setCursors((c) => c.slice(0, -1))}>
          Newer
        </Button>
        <Button variant="default" size="xs" disabled={!res.data?.more} onClick={() => setCursors((c) => [...c, entries.at(-1)!.id])}>
          Older
        </Button>
      </Group>
    </>
  )
}
