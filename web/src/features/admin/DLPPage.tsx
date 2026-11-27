// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Badge, Button, Checkbox, Drawer, Group, NumberInput, Paper, Select, Stack, Switch, Table, Text, TextInput, Textarea } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { type DLPDetector, type DLPPolicy, useApiMutation, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { PageTitle, useTenant } from './AdminShell'
import { ConfirmButton } from './confirm'
import { invalidate } from './DomainsPage'

const actions = [
  { value: 'block', label: 'Block', help: 'Refuse to send it.' },
  { value: 'warn', label: 'Warn', help: 'Ask the sender to confirm in the webmail. Mail apps cannot ask, so their mail is sent and you are told.' },
  { value: 'encrypt', label: 'Require encryption', help: 'Send only over a verified encrypted connection, or bounce.' },
  { value: 'notify', label: 'Notify', help: 'Send it, and tell the contact below.' },
]

const actionColor: Record<string, string> = { block: 'red', warn: 'orange', encrypt: 'blue', notify: 'gray' }

function ActionBadge({ a }: { a: string }) {
  return (
    <Badge color={actionColor[a] ?? 'gray'} variant="light" tt="none">
      {actions.find((x) => x.value === a)?.label ?? a}
    </Badge>
  )
}

type Form = { id: number; name: string; detector: string; pattern: string; minCount: number; action: string; externalOnly: boolean; notify: string; enabled: boolean }

const blank: Form = { id: 0, name: '', detector: 'credit_card', pattern: '', minCount: 1, action: 'warn', externalOnly: true, notify: '', enabled: true }

function Editor({ tenant, detectors, value, onClose }: { tenant: number; detectors: DLPDetector[]; value: Form | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [f, setF] = useState<Form>(value ?? blank)
  const save = useApiMutation('admin.SaveDLPPolicy', {
    onSuccess: () => {
      invalidate(qc, 'ListDLPPolicies')
      onClose()
    },
  })
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((cur) => ({ ...cur, [k]: v }))
  const custom = f.detector === 'pattern' || f.detector === 'keywords'
  const fields = save.error && 'fields' in save.error ? (save.error.fields as Record<string, string>) : {}
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        save.mutate({ tenantId: tenant, ...f, name: f.name.trim(), pattern: custom ? f.pattern : '' })
      }}
    >
      <Stack>
        <TextInput label="Name" placeholder="Card numbers" value={f.name} onChange={(e) => set('name', e.currentTarget.value)} error={fields.name} required />
        <Select label="Look for" value={f.detector} onChange={(v) => v && set('detector', v)} allowDeselect={false} data={detectors.map((d) => ({ value: d.kind, label: d.label }))} />
        {custom && (
          <Textarea
            label={f.detector === 'pattern' ? 'Regular expression' : 'Words or phrases, one per line'}
            autosize
            minRows={2}
            value={f.pattern}
            onChange={(e) => set('pattern', e.currentTarget.value)}
            error={fields.pattern}
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          />
        )}
        <NumberInput label="Matches needed" description="How many different values must be found before the policy acts" min={1} max={1000} value={f.minCount} onChange={(v) => set('minCount', Number(v) || 1)} error={fields.minCount} />
        <Select
          label="Then"
          value={f.action}
          onChange={(v) => v && set('action', v)}
          allowDeselect={false}
          data={actions.map((a) => ({ value: a.value, label: a.label }))}
          description={actions.find((a) => a.value === f.action)?.help}
          error={fields.action}
        />
        <TextInput
          label="Contact for notices"
          placeholder="Leave empty for the tenant's admins"
          value={f.notify}
          onChange={(e) => set('notify', e.currentTarget.value)}
          error={fields.notify}
        />
        <Checkbox label="Only when a recipient is outside your domains" checked={f.externalOnly} onChange={(e) => set('externalOnly', e.currentTarget.checked)} />
        <Switch label="Enabled" checked={f.enabled} onChange={(e) => set('enabled', e.currentTarget.checked)} />
        {save.error && Object.keys(fields).length === 0 && (
          <Alert color="red" variant="light">
            {errorText(save.error)}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending} disabled={!f.name.trim()}>
            {f.id ? 'Save' : 'Add policy'}
          </Button>
        </Group>
      </Stack>
    </form>
  )
}

function Tester({ tenant }: { tenant: number }) {
  const [text, setText] = useState('')
  const test = useApiMutation('admin.TestDLP')
  const res = test.data?.matches
  return (
    <Paper className="t-pane" radius="lg" p="md" mt="lg">
      <Text fw={600}>Try your policies</Text>
      <Text size="sm" c="dimmed" mb="sm">
        Paste some text to see which policies would match, including disabled ones. Nothing is stored.
      </Text>
      <Textarea aria-label="Sample text" autosize minRows={3} maxRows={10} value={text} onChange={(e) => setText(e.currentTarget.value)} placeholder="Card 4111 1111 1111 1111, IBAN DE89 3704 0044 0532 0130 00" />
      <Group mt="sm">
        <Button variant="default" loading={test.isPending} disabled={!text.trim()} onClick={() => test.mutate({ tenantId: tenant, text })}>
          Test
        </Button>
        {test.error && (
          <Text size="sm" c="red">
            {errorText(test.error)}
          </Text>
        )}
      </Group>
      {res && (
        <Stack gap={6} mt="md">
          {res.length === 0 && (
            <Text size="sm" c="dimmed">
              No policy matches this text.
            </Text>
          )}
          {res.map((m) => (
            <Group key={m.policyId} gap="sm" wrap="nowrap" align="flex-start">
              <ActionBadge a={m.action} />
              <div>
                <Text size="sm" fw={500}>
                  {m.name} · {m.count} found
                </Text>
                <Text size="xs" c="dimmed" ff="monospace">
                  {m.samples.join('  ')}
                </Text>
              </div>
            </Group>
          ))}
        </Stack>
      )}
    </Paper>
  )
}

export function DLPPage() {
  const qc = useQueryClient()
  const tenant = useTenant()
  const q = useApiQuery('admin.ListDLPPolicies', { tenantId: tenant })
  const [editing, setEditing] = useState<Form | null | undefined>(undefined)
  const del = useApiMutation('admin.DeleteDLPPolicy', {
    onSuccess: () => invalidate(qc, 'ListDLPPolicies'),
    onError: (e) => notifications.show({ color: 'red', message: errorText(e) }),
  })
  const toggle = useApiMutation('admin.SaveDLPPolicy', {
    onSuccess: () => invalidate(qc, 'ListDLPPolicies'),
    onError: (e) => notifications.show({ color: 'red', message: errorText(e) }),
  })
  const detectors = q.data?.detectors ?? []
  const label = (k: string) => detectors.find((d) => d.kind === k)?.label ?? k
  const edit = (p: DLPPolicy) => setEditing({ id: p.id, name: p.name, detector: p.detector, pattern: p.pattern, minCount: p.minCount, action: p.action, externalOnly: p.externalOnly, notify: p.notify, enabled: p.enabled })
  return (
    <>
      <PageTitle
        title="Data loss prevention"
        sub="Checks outgoing mail, including attachments, for card numbers, bank accounts, ID numbers and your own patterns."
        right={
          <Button onClick={() => setEditing(null)} disabled={!q.data}>
            Add policy
          </Button>
        }
      />
      <Paper className="t-pane" radius="lg">
        <Table.ScrollContainer minWidth={760}>
          <Table verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Policy</Table.Th>
                <Table.Th>Looks for</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Applies to</Table.Th>
                <Table.Th>Enabled</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(q.data?.policies ?? []).map((p) => (
                <Table.Tr key={p.id}>
                  <Table.Td>
                    <Text size="sm" fw={500}>
                      {p.name}
                    </Text>
                    <Text size="xs" c="dimmed">
                      Notices to {p.notify || 'the admins'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{label(p.detector)}</Text>
                    {p.minCount > 1 && (
                      <Text size="xs" c="dimmed">
                        {p.minCount} or more
                      </Text>
                    )}
                  </Table.Td>
                  <Table.Td>
                    <ActionBadge a={p.action} />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{p.externalOnly ? 'Outside recipients' : 'All mail'}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Switch aria-label={`Enable ${p.name}`} checked={p.enabled} onChange={(e) => toggle.mutate({ ...p, tenantId: tenant, enabled: e.currentTarget.checked })} />
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4} wrap="nowrap" justify="flex-end">
                      <Button size="compact-xs" variant="default" onClick={() => edit(p)}>
                        Edit
                      </Button>
                      <ConfirmButton
                        size="compact-xs"
                        variant="subtle"
                        color="red"
                        label="Delete"
                        title="Delete this policy?"
                        body={`Outgoing mail will no longer be checked by “${p.name}”.`}
                        confirm="Delete"
                        onConfirm={() => del.mutateAsync({ tenantId: tenant, id: p.id })}
                      />
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
              {q.isSuccess && q.data.policies.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text c="dimmed" size="sm" ta="center" py="md">
                      No policies yet. Outgoing mail is not checked for sensitive data.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
              {q.error && (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text c="red" size="sm" ta="center" py="md">
                      {errorText(q.error)}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>
      <Tester tenant={tenant} />
      <Drawer opened={editing !== undefined} onClose={() => setEditing(undefined)} position="right" title={editing?.id ? 'Edit policy' : 'New policy'} size="md">
        {editing !== undefined && <Editor key={editing?.id ?? 'new'} tenant={tenant} detectors={detectors} value={editing} onClose={() => setEditing(undefined)} />}
      </Drawer>
    </>
  )
}
