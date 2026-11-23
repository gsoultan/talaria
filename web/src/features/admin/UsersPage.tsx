// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Alert, Avatar, Badge, Button, CloseButton, Divider, Drawer, Group, Modal, NumberInput, Paper, PasswordInput, Select, Stack, Switch, Table, Text, TextInput } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useForm } from '@tanstack/react-form'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { errorText } from '../../lib/errors'
import { avatarColor, bytes, initials } from '../../lib/format'
import { isPlatformAdmin, Role, useMe } from '../auth/useMe'
import { PageTitle, useTenant } from './AdminShell'
import { ConfirmButton } from './confirm'
import { invalidate } from './DomainsPage'
import { useApiMutation, useApiQuery, type User } from '../../lib/api'

const GB = 1024 * 1024 * 1024

function roleLabel(r: string): string {
  return r === Role.PLATFORM_ADMIN ? 'Platform admin' : r === Role.TENANT_ADMIN ? 'Tenant admin' : 'User'
}

function roleOptions(platform: boolean) {
  return [
    { value: String(Role.USER), label: 'User' },
    { value: String(Role.TENANT_ADMIN), label: 'Tenant admin' },
    ...(platform ? [{ value: String(Role.PLATFORM_ADMIN), label: 'Platform admin' }] : []),
  ]
}

const toGB = (b: number) => b / GB
const fromGB = (g: number | string) => Math.round(Number(g || 0) * GB)

function AddUser({ tenant, onClose }: { tenant: number; onClose: () => void }) {
  const qc = useQueryClient()
  const me = useMe().data?.user
  const create = useApiMutation('admin.CreateUser')
  const form = useForm({
    defaultValues: { email: '', name: '', password: '', role: String(Role.USER), quota: 0 as number | string },
    onSubmit: async ({ value }) => {
      try {
        await create.mutateAsync({ tenantId: tenant, email: value.email.trim(), displayName: value.name.trim(), password: value.password, role: value.role, quotaBytes: fromGB(value.quota) })
        invalidate(qc, 'ListUsers', 'GetStats')
        notifications.show({ color: 'green', message: `${value.email} can sign in now.` })
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
        <form.Field name="email" validators={{ onSubmit: ({ value }) => (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value.trim()) ? undefined : 'Enter an address on one of your domains') }}>
          {(f) => <TextInput label="Email address" data-autofocus value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0]} />}
        </form.Field>
        <form.Field name="name">{(f) => <TextInput label="Display name" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} />}</form.Field>
        <form.Field name="password" validators={{ onSubmit: ({ value }) => (value.length >= 8 ? undefined : 'Use at least 8 characters') }}>
          {(f) => <PasswordInput label="Password" description="Share it with them safely; they can change it in Settings." autoComplete="new-password" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0]} />}
        </form.Field>
        <Group grow>
          <form.Field name="role">{(f) => <Select label="Role" data={roleOptions(isPlatformAdmin(me))} value={f.state.value} onChange={(v) => v && f.handleChange(v)} allowDeselect={false} />}</form.Field>
          <form.Field name="quota">{(f) => <NumberInput label="Quota in GB (0 = default)" min={0} value={f.state.value} onChange={f.handleChange} />}</form.Field>
        </Group>
        {create.error && (
          <Alert color="red" variant="light" p="xs">
            {errorText(create.error)}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={create.isPending}>
            Add user
          </Button>
        </Group>
      </Stack>
    </form>
  )
}

function Aliases({ tenant, user }: { tenant: number; user: User }) {
  const qc = useQueryClient()
  const list = useApiQuery('admin.ListAliases', { tenantId: tenant, userId: user.id }).data?.aliases ?? []
  const add = useApiMutation('admin.CreateAlias', { onSuccess: () => invalidate(qc, 'ListAliases') })
  const del = useApiMutation('admin.DeleteAlias', { onSuccess: () => invalidate(qc, 'ListAliases') })
  const [addr, setAddr] = useState('')
  return (
    <Stack gap="xs">
      <Text fw={600} size="sm">
        Aliases
      </Text>
      <Text size="xs" c="dimmed">
        Mail to these addresses lands in {user.email}’s Inbox, and they can send from them.
      </Text>
      {list.map((a) => (
        <Group key={a.id.toString()} justify="space-between" gap="xs">
          <Text size="sm">{a.address}</Text>
          <CloseButton size="sm" aria-label={`Remove ${a.address}`} onClick={() => del.mutate({ tenantId: tenant, id: a.id })} />
        </Group>
      ))}
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (!addr.trim()) return
          add.mutate({ tenantId: tenant, address: addr.trim(), userId: user.id }, { onSuccess: () => setAddr('') })
        }}
      >
        <Group gap="xs" align="flex-start">
          <TextInput size="xs" placeholder="sales@example.com" aria-label="New alias" value={addr} onChange={(e) => setAddr(e.currentTarget.value)} error={add.error ? errorText(add.error) : undefined} style={{ flex: 1 }} />
          <Button size="xs" type="submit" variant="default" loading={add.isPending}>
            Add alias
          </Button>
        </Group>
      </form>
    </Stack>
  )
}

function EditUser({ tenant, user, onClose }: { tenant: number; user: User; onClose: () => void }) {
  const qc = useQueryClient()
  const me = useMe().data?.user
  const update = useApiMutation('admin.UpdateUser')
  const setPw = useApiMutation('admin.SetUserPassword')
  const del = useApiMutation('admin.DeleteUser')
  const [pw, setPwValue] = useState('')
  const self = me?.id === user.id
  const form = useForm({
    defaultValues: { name: user.displayName, role: String(user.role), quota: toGB(user.quotaBytes) as number | string, suspended: user.suspended },
    onSubmit: async ({ value }) => {
      try {
        await update.mutateAsync({ id: user.id, displayName: value.name, role: value.role, quotaBytes: fromGB(value.quota), suspended: value.suspended })
        invalidate(qc, 'ListUsers')
        notifications.show({ color: 'green', message: 'Saved' })
      } catch {
        // Shown below.
      }
    },
  })
  return (
    <Stack>
      <Group>
        <Avatar color={avatarColor(user.email)} radius="xl">
          {initials(user.displayName, user.email)}
        </Avatar>
        <div>
          <Text fw={600}>{user.displayName || user.email}</Text>
          <Text size="sm" c="dimmed">
            {user.email} · {bytes(user.usedBytes)} used
          </Text>
        </div>
      </Group>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void form.handleSubmit()
        }}
      >
        <Stack gap="sm">
          <form.Field name="name">{(f) => <TextInput label="Display name" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} />}</form.Field>
          <Group grow>
            <form.Field name="role">{(f) => <Select label="Role" disabled={self} data={roleOptions(isPlatformAdmin(me))} value={f.state.value} onChange={(v) => v && f.handleChange(v)} allowDeselect={false} />}</form.Field>
            <form.Field name="quota">{(f) => <NumberInput label="Quota in GB (0 = default)" min={0} decimalScale={2} value={f.state.value} onChange={f.handleChange} />}</form.Field>
          </Group>
          <form.Field name="suspended">
            {(f) => <Switch label="Suspended" description="Blocks sign-in everywhere. Mail still arrives." disabled={self} checked={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.checked)} />}
          </form.Field>
          {update.error && (
            <Alert color="red" variant="light" p="xs">
              {errorText(update.error)}
            </Alert>
          )}
          <Button type="submit" loading={update.isPending} w="fit-content">
            Save
          </Button>
        </Stack>
      </form>
      <Divider />
      <Aliases tenant={tenant} user={user} />
      <Divider />
      <form
        onSubmit={(e) => {
          e.preventDefault()
          setPw.mutate(
            { id: user.id, password: pw },
            {
              onSuccess: () => {
                setPwValue('')
                notifications.show({ color: 'green', message: 'Password reset. Their other sessions are signed out.' })
              },
            },
          )
        }}
      >
        <Group gap="xs" align="flex-end">
          <PasswordInput label="Reset password" autoComplete="new-password" value={pw} onChange={(e) => setPwValue(e.currentTarget.value)} error={setPw.error ? errorText(setPw.error) : undefined} style={{ flex: 1 }} />
          <Button type="submit" variant="default" disabled={pw.length < 8} loading={setPw.isPending}>
            Reset
          </Button>
        </Group>
      </form>
      {!self && (
        <>
          <Divider />
          <ConfirmButton
            color="red"
            variant="light"
            label="Delete user"
            title={`Delete ${user.email}?`}
            body="Their mailboxes, mail and aliases are deleted for good. This can’t be undone."
            confirm="Delete user"
            onConfirm={async () => {
              try {
                await del.mutateAsync({ id: user.id })
                invalidate(qc, 'ListUsers', 'GetStats')
                onClose()
              } catch (e) {
                notifications.show({ color: 'red', message: errorText(e) })
              }
            }}
            w="fit-content"
          />
        </>
      )}
    </Stack>
  )
}

export function UsersPage() {
  const tenant = useTenant()
  const q = useApiQuery('admin.ListUsers', { tenantId: tenant })
  const stats = useApiQuery('admin.GetStats', { tenantId: tenant }).data
  const [adding, setAdding] = useState(false)
  const [edit, setEdit] = useState<number | null>(null)
  const users = q.data?.users ?? []
  const editing = users.find((u) => u.id === edit)
  const sub = stats ? `${stats.users}${stats.seatLimit > 0 ? ` of ${stats.seatLimit}` : ''} seats · ${bytes(stats.usedBytes)}${stats.quotaBytes > 0 ? ` of ${bytes(stats.quotaBytes)}` : ''} tenant storage` : undefined
  return (
    <>
      <PageTitle title="Users" sub={sub} right={<Button onClick={() => setAdding(true)}>Add user</Button>} />
      <Paper className="t-pane" radius="lg">
        <Table.ScrollContainer minWidth={640}>
          <Table verticalSpacing="sm" highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>User</Table.Th>
                <Table.Th>Role</Table.Th>
                <Table.Th>Storage</Table.Th>
                <Table.Th>Status</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {users.map((u) => (
                <Table.Tr key={u.id.toString()} onClick={() => setEdit(u.id)} style={{ cursor: 'pointer' }}>
                  <Table.Td>
                    <Group gap="sm" wrap="nowrap">
                      <Avatar size={32} radius="xl" color={avatarColor(u.email)}>
                        {initials(u.displayName, u.email)}
                      </Avatar>
                      <div style={{ minWidth: 0 }}>
                        <Text size="sm" fw={500} truncate>
                          {u.displayName || u.email}
                        </Text>
                        <Text size="xs" c="dimmed" truncate>
                          {u.email}
                        </Text>
                      </div>
                    </Group>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{roleLabel(u.role)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">
                      {bytes(u.usedBytes)}
                      {u.quotaBytes > 0 ? ` of ${bytes(u.quotaBytes)}` : ''}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    {u.suspended ? (
                      <Badge color="red" variant="light" tt="none">
                        Suspended
                      </Badge>
                    ) : (
                      <Badge color="green" variant="light" tt="none">
                        Active
                      </Badge>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>
      <Modal opened={adding} onClose={() => setAdding(false)} title="Add user" centered>
        <AddUser tenant={tenant} onClose={() => setAdding(false)} />
      </Modal>
      <Drawer opened={!!editing} onClose={() => setEdit(null)} position="right" size="md" title="User">
        {editing && <EditUser key={editing.id.toString()} tenant={tenant} user={editing} onClose={() => setEdit(null)} />}
      </Drawer>
    </>
  )
}
