// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Button, Code, Drawer, Group, Loader, ScrollArea, SegmentedControl, Stack, Table, Text, TextInput, Title } from '@mantine/core'
import { useDebouncedValue } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { type HeldMessage, ofOps, useApiMutation, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { bytes, fullDate } from '../../lib/format'
import { HeldTable, ReasonBadge } from '../quarantine/HeldTable'
import { PageTitle, useTenant } from './AdminShell'
import { ConfirmButton } from './confirm'

function Review({ id, onClose, onRelease, onDelete }: { id: bigint | number; onClose: () => void; onRelease: () => void; onDelete: () => Promise<unknown> }) {
  const d = useApiQuery('admin.GetHeldMail', { id: Number(id) })
  const m = d.data?.message
  return (
    <Drawer opened onClose={onClose} position="right" size="xl" title={<Title order={4}>Review held mail</Title>}>
      {d.isPending && <Loader size="sm" />}
      {d.error && <Alert color="red">{errorText(d.error)}</Alert>}
      {m && d.data && (
        <Stack gap="md">
          <div>
            <Text fw={600}>{m.subject || '(no subject)'}</Text>
            <Text size="sm">
              From {m.fromName ? `${m.fromName} <${m.fromAddr}>` : m.fromAddr} to {m.recipient}
            </Text>
            <Text size="xs" c="dimmed">
              Held {fullDate(m.createdAt)} · {bytes(m.size)} · envelope sender {m.envFrom || '(none)'}
            </Text>
          </div>
          <Group gap="xs">
            <ReasonBadge m={m} />
          </Group>
          <Alert variant="light" color={m.reason === 'malware' ? 'red' : 'orange'} title="What was found">
            <Text size="sm" style={{ wordBreak: 'break-word' }}>
              {m.detail || 'No details.'}
            </Text>
          </Alert>
          {d.data.attachments.length > 0 && (
            <div>
              <Text size="sm" fw={600} mb={4}>
                Attachments
              </Text>
              {d.data.attachments.map((a) => (
                <Text size="sm" key={a.part}>
                  {a.filename || '(unnamed)'} <Text span c="dimmed" size="xs">{a.contentType}{a.size >= 0 ? ` · ${bytes(a.size)}` : ''}</Text>
                </Text>
              ))}
            </div>
          )}
          <div>
            <Text size="sm" fw={600} mb={4}>
              Text (links are not clickable)
            </Text>
            <ScrollArea.Autosize mah={280} type="auto">
              <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                {d.data.textBody.slice(0, 20000) || '(no text)'}
              </Code>
            </ScrollArea.Autosize>
          </div>
          <details>
            <summary style={{ cursor: 'pointer', fontSize: 14 }}>Headers</summary>
            <Table fz="xs" mt="xs">
              <Table.Tbody>
                {d.data.headers.map((h, i) => (
                  <Table.Tr key={i}>
                    <Table.Td style={{ whiteSpace: 'nowrap', verticalAlign: 'top' }}>{h.name}</Table.Td>
                    <Table.Td style={{ wordBreak: 'break-all' }}>{h.value}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </details>
          <Group justify="flex-end">
            <ConfirmButton variant="subtle" color="red" label="Delete" title="Delete held mail?" body="The message is deleted for good." confirm="Delete" onConfirm={onDelete} />
            <Button onClick={onRelease}>Release to {m.recipient}</Button>
          </Group>
        </Stack>
      )}
    </Drawer>
  )
}

export function QuarantineAdminPage() {
  const qc = useQueryClient()
  const tenant = useTenant()
  const [reason, setReason] = useState('')
  const [q, setQ] = useState('')
  const [dq] = useDebouncedValue(q, 250)
  const [open, setOpen] = useState<HeldMessage | null>(null)
  const list = useApiQuery('admin.ListHeldMail', { tenantId: tenant, reason, q: dq })
  const done = (message: string) => ({
    onSuccess: () => {
      notifications.show({ color: 'green', message })
      setOpen(null)
      void qc.invalidateQueries({ predicate: ofOps('admin.ListHeldMail') })
    },
    onError: (e: unknown) => notifications.show({ color: 'red', message: errorText(e) }),
  })
  const release = useApiMutation('admin.ReleaseHeldMail', done('Released to the recipient’s Inbox.'))
  const del = useApiMutation('admin.DeleteHeldMail', done('Deleted.'))
  return (
    <>
      <PageTitle title="Quarantine" sub={`Mail held for review in this tenant. It is deleted after ${list.data?.keepDays ?? 30} days.`} />
      <Group mb="sm" justify="space-between" wrap="wrap">
        <SegmentedControl
          size="xs"
          value={reason}
          onChange={setReason}
          data={[
            { value: '', label: 'All' },
            { value: 'malware', label: 'Dangerous attachments' },
            { value: 'spam', label: 'Spam' },
          ]}
        />
        <TextInput size="xs" placeholder="Search sender, subject or recipient" value={q} onChange={(e) => setQ(e.currentTarget.value)} w={280} aria-label="Search held mail" />
      </Group>
      <HeldTable rows={list.data?.messages ?? []} loaded={list.isSuccess} showRecipient onOpen={setOpen} onRelease={(m) => release.mutate({ id: m.id })} />
      {open && <Review id={open.id} onClose={() => setOpen(null)} onRelease={() => release.mutate({ id: open.id })} onDelete={() => del.mutateAsync({ id: open.id })} />}
    </>
  )
}
