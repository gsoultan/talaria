// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery } from '@connectrpc/connect-query'
import { Alert, Badge, Button, Code, CopyButton, Group, Paper, Stack, Table, Text, TextInput, Title, Tooltip } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useForm } from '@tanstack/react-form'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { AdminService, type Domain } from '../../gen/talaria/v1/admin_pb'
import { errorText } from '../../lib/errors'
import { Health, PageTitle, useTenant } from './AdminShell'
import { ConfirmButton } from './confirm'

function invalidate(qc: ReturnType<typeof useQueryClient>, ...methods: string[]) {
  void qc.invalidateQueries({ predicate: (q) => methods.includes((q.queryKey[1] as { methodName?: string })?.methodName ?? '') })
}
export { invalidate }

function DnsRecords({ tenant, domain }: { tenant: bigint; domain: Domain }) {
  const qc = useQueryClient()
  const [check, setCheck] = useState(false)
  const q = useQuery(AdminService.method.getDomainSetup, { tenantId: tenant, domainId: domain.id, check }, { staleTime: check ? 0 : 60_000 })
  const rotate = useMutation(AdminService.method.rotateDKIM, {
    onSuccess: () => {
      invalidate(qc, 'GetDomainSetup')
      notifications.show({ message: 'New DKIM key made. Publish its record, then mail is signed with it.' })
    },
    onError: (e) => notifications.show({ color: 'red', message: errorText(e) }),
  })
  const recs = q.data?.records ?? []
  const missing = check ? recs.filter((r) => !r.ok).length : 0
  return (
    <Paper className="t-pane" p="lg" radius="lg" mt="lg">
      <Group justify="space-between" align="flex-start" mb="sm">
        <div>
          <Title order={4}>DNS records for {domain.name}</Title>
          <Text size="sm" c="dimmed">
            Add these at your DNS provider. Changes can take a while to appear.
          </Text>
        </div>
        <Group gap="xs">
          <Button variant="default" size="xs" loading={q.isFetching && check} onClick={() => (check ? void q.refetch() : setCheck(true))}>
            Check records
          </Button>
          <ConfirmButton
            size="xs"
            variant="subtle"
            label="New DKIM key"
            title="Make a new DKIM key?"
            body="Mail is signed with the new key as soon as it exists. Publish its DNS record right away, or receivers can’t verify new mail. Keep the old record for a few days."
            confirm="Make new key"
            onConfirm={() => rotate.mutateAsync({ tenantId: tenant, domainId: domain.id })}
          />
        </Group>
      </Group>
      {check && q.isSuccess && (
        <Alert variant="light" color={missing ? 'orange' : 'green'} mb="sm" p="xs">
          {missing ? `${missing} record${missing > 1 ? 's' : ''} missing or different.` : 'All records found.'}
        </Alert>
      )}
      {q.error && (
        <Alert variant="light" color="red" mb="sm" p="xs">
          {errorText(q.error)}
        </Alert>
      )}
      <Table.ScrollContainer minWidth={720}>
        <Table verticalSpacing="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={70}>Type</Table.Th>
              <Table.Th>Name</Table.Th>
              <Table.Th>Value</Table.Th>
              <Table.Th w={110}>Status</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {recs.map((r, i) => (
              <Table.Tr key={i}>
                <Table.Td>
                  <Badge variant="light" radius="sm">
                    {r.type}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Code>{r.name}</Code>
                  <Text size="xs" c="dimmed">
                    {r.purpose}
                  </Text>
                </Table.Td>
                <Table.Td maw={460}>
                  <Group gap={6} wrap="nowrap" align="flex-start">
                    <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', flex: 1, fontSize: 12 }}>
                      {r.value}
                    </Code>
                    <CopyButton value={r.value}>
                      {({ copied, copy }) => (
                        <Button size="compact-xs" variant="subtle" onClick={copy}>
                          {copied ? 'Copied' : 'Copy'}
                        </Button>
                      )}
                    </CopyButton>
                  </Group>
                </Table.Td>
                <Table.Td>
                  {!check ? (
                    <Text size="xs" c="dimmed">
                      Not checked
                    </Text>
                  ) : r.ok ? (
                    <Badge color="green" variant="light" tt="none">
                      Found
                    </Badge>
                  ) : (
                    <Tooltip label={r.found ? `Found: ${r.found}` : 'Not found'} multiline w={300}>
                      <Badge color="orange" variant="light" tt="none">
                        {r.found ? 'Different' : 'Missing'}
                      </Badge>
                    </Tooltip>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Paper>
  )
}

function AddDomain({ tenant }: { tenant: bigint }) {
  const qc = useQueryClient()
  const create = useMutation(AdminService.method.createDomain)
  const form = useForm({
    defaultValues: { name: '' },
    onSubmit: async ({ value, formApi }) => {
      try {
        await create.mutateAsync({ tenantId: tenant, name: value.name.trim() })
        invalidate(qc, 'ListDomains', 'GetStats')
        formApi.reset()
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
      <Group gap="xs" align="flex-start">
        <form.Field name="name" validators={{ onSubmit: ({ value }) => (/^[^\s.]+(\.[^\s.]+)+$/.test(value.trim()) ? undefined : 'Enter a domain such as example.com') }}>
          {(f) => <TextInput aria-label="New domain" placeholder="example.com" value={f.state.value} onChange={(e) => f.handleChange(e.currentTarget.value)} error={f.state.meta.errors[0] ?? (create.error ? errorText(create.error) : undefined)} size="sm" />}
        </form.Field>
        <Button type="submit" size="sm" loading={create.isPending}>
          Add domain
        </Button>
      </Group>
    </form>
  )
}

export function DomainsPage() {
  const qc = useQueryClient()
  const tenant = useTenant()
  const q = useQuery(AdminService.method.listDomains, { tenantId: tenant })
  const del = useMutation(AdminService.method.deleteDomain, { onSuccess: () => invalidate(qc, 'ListDomains', 'GetStats', 'ListUsers') })
  const [sel, setSel] = useState<bigint | null>(null)
  const domains = q.data?.domains ?? []
  const open = domains.find((d) => d.id === sel) ?? domains[0]
  return (
    <>
      <Title order={2} mb="md">
        Server health
      </Title>
      <Health />
      <PageTitle title="Domains" right={<AddDomain tenant={tenant} />} />
      <Paper className="t-pane" radius="lg">
        <Table verticalSpacing="sm" highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Domain</Table.Th>
              <Table.Th w={200} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {domains.map((d) => (
              <Table.Tr key={d.id.toString()} bg={open?.id === d.id ? 'var(--t-selected)' : undefined}>
                <Table.Td>
                  <Text fw={500}>{d.name}</Text>
                </Table.Td>
                <Table.Td>
                  <Group gap="xs" justify="flex-end">
                    <Button size="compact-sm" variant="default" onClick={() => setSel(d.id)}>
                      DNS records
                    </Button>
                    <ConfirmButton
                      size="compact-sm"
                      variant="subtle"
                      color="red"
                      label="Delete"
                      title={`Delete ${d.name}?`}
                      body={`Every user and alias on ${d.name}, and all their mail, is deleted for good. This can’t be undone.`}
                      confirm="Delete domain"
                      onConfirm={() => del.mutateAsync({ tenantId: tenant, id: d.id }).catch((e) => notifications.show({ color: 'red', message: errorText(e) }))}
                    />
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {q.isSuccess && domains.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={2}>
                  <Text c="dimmed" size="sm" ta="center" py="md">
                    No domains yet. Add one to start receiving mail.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Paper>
      {open && <DnsRecords key={open.id.toString()} tenant={tenant} domain={open} />}
      <Stack />
    </>
  )
}
