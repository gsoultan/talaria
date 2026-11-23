// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Badge, Button, CloseButton, Group, Paper, SegmentedControl, Select, Table, Text, TextInput } from '@mantine/core'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useApiMutation, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { listDate } from '../../lib/format'
import { PageTitle, useTenant } from './AdminShell'
import { invalidate } from './DomainsPage'

const kinds = [
  { value: 'domain', label: 'Domain', placeholder: 'partner.example' },
  { value: 'address', label: 'Address', placeholder: 'billing@partner.example' },
  { value: 'ip', label: 'IP or range', placeholder: '203.0.113.0/24' },
]

function AddRule({ tenant }: { tenant: number }) {
  const qc = useQueryClient()
  const [kind, setKind] = useState('domain')
  const [value, setValue] = useState('')
  const [action, setAction] = useState('block')
  const [note, setNote] = useState('')
  const add = useApiMutation('admin.CreateSenderRule', { onSuccess: () => invalidate(qc, 'ListSenderRules') })
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        add.mutate(
          { tenantId: tenant, kind, value: value.trim(), action, note: note.trim() },
          {
            onSuccess: () => {
              setValue('')
              setNote('')
            },
          },
        )
      }}
    >
      <Group gap="sm" align="flex-start" wrap="wrap">
        <SegmentedControl aria-label="Action" value={action} onChange={setAction} data={[{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }]} />
        <Select aria-label="Match" w={150} value={kind} onChange={(v) => v && setKind(v)} data={kinds} allowDeselect={false} />
        <TextInput
          aria-label="Value"
          placeholder={kinds.find((k) => k.value === kind)?.placeholder}
          value={value}
          onChange={(e) => setValue(e.currentTarget.value)}
          error={add.error ? errorText(add.error) : undefined}
          style={{ flex: '1 1 220px' }}
        />
        <TextInput aria-label="Note" placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.currentTarget.value)} style={{ flex: '1 1 160px' }} />
        <Button type="submit" loading={add.isPending} disabled={!value.trim()}>
          Add rule
        </Button>
      </Group>
    </form>
  )
}

export function FilteringPage() {
  const qc = useQueryClient()
  const tenant = useTenant()
  const q = useApiQuery('admin.ListSenderRules', { tenantId: tenant })
  const del = useApiMutation('admin.DeleteSenderRule', { onSuccess: () => invalidate(qc, 'ListSenderRules') })
  const rules = q.data?.rules ?? []
  return (
    <>
      <PageTitle title="Sender filtering" sub="Allow or block mail from senders and servers, for everyone in this tenant." />
      <Alert variant="light" color="gray" mb="md">
        <Text size="sm">
          <b>Block</b> refuses the mail while the sending server is still connected, so nothing is stored. <b>Allow</b> skips the blocklist, greylisting and reverse DNS checks for a sender you
          trust. A block wins when both match. A domain also covers its subdomains.
        </Text>
      </Alert>
      <Paper className="t-pane" radius="lg" p="md" mb="md">
        <AddRule tenant={tenant} />
      </Paper>
      <Paper className="t-pane" radius="lg">
        {q.error ? (
          <Text c="red" size="sm" p="md">
            {errorText(q.error)}
          </Text>
        ) : rules.length === 0 ? (
          <Text c="dimmed" size="sm" p="md">
            {q.isPending ? 'Loading…' : 'No rules yet. Mail is checked against the server’s blocklists only.'}
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={640}>
            <Table verticalSpacing="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>Sender</Table.Th>
                  <Table.Th>Note</Table.Th>
                  <Table.Th>Added</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rules.map((r) => (
                  <Table.Tr key={r.id}>
                    <Table.Td>
                      <Badge variant="light" color={r.action === 'block' ? 'red' : 'green'} tt="none">
                        {r.action === 'block' ? 'Block' : 'Allow'}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{r.value}</Text>
                      <Text size="xs" c="dimmed">
                        {kinds.find((k) => k.value === r.kind)?.label}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">
                        {r.note}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">{listDate(r.createdAt)}</Text>
                    </Table.Td>
                    <Table.Td>
                      <CloseButton aria-label={`Remove rule for ${r.value}`} onClick={() => del.mutate({ tenantId: tenant, id: r.id })} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
    </>
  )
}
