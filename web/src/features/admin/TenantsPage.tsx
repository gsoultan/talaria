// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Avatar, Badge, Button, Group, Modal, NumberInput, Paper, Stack, Switch, Table, Text, TextInput } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useForm } from '@tanstack/react-form'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { errorText } from '../../lib/errors'
import { avatarColor, bytes } from '../../lib/format'
import { navigate } from '../../lib/router'
import { Health, PageTitle } from './AdminShell'
import { ConfirmButton } from './confirm'
import { invalidate } from './DomainsPage'
import { type Tenant, useApiMutation, useApiQuery } from '../../lib/api'

const GB = 1024 ** 3

type Values = { name: string; displayName: string; seats: number | string; quotaGB: number | string; daily: number | string; suspended: boolean }

function TenantForm({ tenant, onClose }: { tenant?: Tenant; onClose: () => void }) {
  const qc = useQueryClient()
  const create = useApiMutation('admin.CreateTenant')
  const update = useApiMutation('admin.UpdateTenant')
  const del = useApiMutation('admin.DeleteTenant')
  const err = create.error ?? update.error
  const form = useForm({
    defaultValues: {
      name: tenant?.name ?? '',
      displayName: tenant?.displayName ?? '',
      seats: Number(tenant?.seatLimit ?? 25),
      quotaGB: Math.round(tenant?.quotaBytes ?? 50 * GB / GB),
      daily: Number(tenant?.dailySendLimit ?? 2000),
      suspended: tenant?.suspended ?? false,
    } as Values,
    onSubmit: async ({ value }) => {
      const t = {
        name: value.name.trim(),
        displayName: value.displayName.trim() || value.name.trim(),
        seatLimit: Number(value.seats || 0),
        quotaBytes: Math.round(Number(value.quotaGB || 0) * GB),
        dailySendLimit: Number(value.daily || 0),
      }
      try {
        if (tenant) {
          const { name: _, ...rest } = t
          await update.mutateAsync({ id: tenant.id, ...rest, suspended: value.suspended })
        }
        else await create.mutateAsync(t)
        invalidate(qc, 'ListTenants', 'GetStats')
        onClose()
      } catch {
        // Shown below.
      }
    },
  })
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        void form.handleSubmit()
      }}
    >
      <Stack>
        <form.Field name="displayName">{(f) => <TextInput label="Organization name" data-autofocus value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} />}</form.Field>
        <form.Field name="name" validators={{ onSubmit: ({ value }) => (/^[a-z0-9][a-z0-9-]*$/i.test(value.trim()) ? undefined : 'Letters, digits and dashes') }}>
          {(f) => <TextInput label="Short name" description="Used in the command line and logs" disabled={!!tenant} value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0]} />}
        </form.Field>
        <Group grow>
          <form.Field name="seats">{(f) => <NumberInput label="Seat limit" description="0 = no limit" min={0} value={f.state.value} onChange={f.handleChange} />}</form.Field>
          <form.Field name="quotaGB">{(f) => <NumberInput label="Storage quota (GB)" description="0 = no limit" min={0} value={f.state.value} onChange={f.handleChange} />}</form.Field>
        </Group>
        <form.Field name="daily">{(f) => <NumberInput label="Sending limit per day" description="Recipients outside the server; 0 = no limit" min={0} value={f.state.value} onChange={f.handleChange} thousandSeparator />}</form.Field>
        {tenant && <form.Field name="suspended">{(f) => <Switch label="Suspended" description="Nobody in this tenant can sign in." checked={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.checked)} />}</form.Field>}
        {err && (
          <Alert color="red" variant="light" p="xs">
            {errorText(err)}
          </Alert>
        )}
        <Group justify="space-between">
          {tenant ? (
            <ConfirmButton
              color="red"
              variant="subtle"
              label="Delete tenant"
              title={`Delete ${tenant.displayName}?`}
              body="Every domain, user and message in this tenant is deleted for good. This can’t be undone."
              confirm="Delete tenant"
              onConfirm={async () => {
                try {
                  await del.mutateAsync({ id: tenant.id })
                  invalidate(qc, 'ListTenants', 'GetStats')
                  onClose()
                } catch (e) {
                  notifications.show({ color: 'red', message: errorText(e) })
                }
              }}
            />
          ) : (
            <span />
          )}
          <Group>
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending || update.isPending}>
              {tenant ? 'Save' : 'Create tenant'}
            </Button>
          </Group>
        </Group>
        {!tenant && (
          <Text size="xs" c="dimmed">
            Next, open the tenant to add its first domain and admin.
          </Text>
        )}
      </Stack>
    </form>
  )
}

export function TenantsPage() {
  const q = useApiQuery('admin.ListTenants', {})
  const [edit, setEdit] = useState<Tenant | 'new' | null>(null)
  const list = q.data?.tenants ?? []
  return (
    <>
      <Health />
      <PageTitle title="Tenants" sub="Each tenant has its own domains, users, admins and quotas. Data never crosses tenants." right={<Button onClick={() => setEdit('new')}>New tenant</Button>} />
      <Paper className="t-pane" radius="lg">
        <Table.ScrollContainer minWidth={760}>
          <Table verticalSpacing="sm" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Tenant</Table.Th>
                <Table.Th>Domains</Table.Th>
                <Table.Th>Seats</Table.Th>
                <Table.Th>Storage</Table.Th>
                <Table.Th>Sending</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {list.map((t) => (
                <Table.Tr key={t.id.toString()}>
                  <Table.Td>
                    <Group gap="sm" wrap="nowrap">
                      <Avatar size={32} radius="md" color={avatarColor(t.name)}>
                        {t.displayName[0]?.toUpperCase()}
                      </Avatar>
                      <div>
                        <Text size="sm" fw={500}>
                          {t.displayName}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {t.name}
                        </Text>
                      </div>
                    </Group>
                  </Table.Td>
                  <Table.Td>{t.domains.toString()}</Table.Td>
                  <Table.Td>
                    {t.users.toString()}
                    {t.seatLimit > 0 ? ` of ${t.seatLimit}` : ''}
                  </Table.Td>
                  <Table.Td>
                    {bytes(t.usedBytes)}
                    {t.quotaBytes > 0 ? ` of ${bytes(t.quotaBytes)}` : ''}
                  </Table.Td>
                  <Table.Td>{t.dailySendLimit > 0 ? `${t.dailySendLimit.toLocaleString()} per day` : 'No limit'}</Table.Td>
                  <Table.Td>
                    <Badge color={t.suspended ? 'red' : 'green'} variant="light" tt="none">
                      {t.suspended ? 'Suspended' : 'Active'}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Group gap={4} justify="flex-end" wrap="nowrap">
                      <Button size="compact-sm" variant="default" onClick={() => navigate(`/admin/domains?tenant=${t.id}`)}>
                        Open as admin
                      </Button>
                      <Button size="compact-sm" variant="subtle" onClick={() => setEdit(t)}>
                        Edit
                      </Button>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>
      <Modal opened={!!edit} onClose={() => setEdit(null)} title={edit === 'new' ? 'New tenant' : 'Edit tenant'} centered>
        {edit && <TenantForm tenant={edit === 'new' ? undefined : edit} onClose={() => setEdit(null)} />}
      </Modal>
    </>
  )
}
