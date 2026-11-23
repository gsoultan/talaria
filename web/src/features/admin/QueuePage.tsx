// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { useMutation, useQuery } from '@connectrpc/connect-query'
import { Alert, Badge, Button, Group, Paper, SegmentedControl, Table, Text, Tooltip } from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { AdminService, QueueStatus, type QueueItem } from '../../gen/talaria/v1/admin_pb'
import { errorText } from '../../lib/errors'
import { bytes, fullDate, listDate } from '../../lib/format'
import { PageTitle, useTenant } from './AdminShell'
import { invalidate } from './DomainsPage'

function StatusBadge({ s }: { s: QueueStatus }) {
  switch (s) {
    case QueueStatus.WAITING:
      return (
        <Badge color="orange" variant="light" tt="none">
          Retrying
        </Badge>
      )
    case QueueStatus.SENDING:
      return (
        <Badge color="blue" variant="light" tt="none">
          Sending
        </Badge>
      )
    case QueueStatus.SENT:
      return (
        <Badge color="green" variant="light" tt="none">
          Delivered
        </Badge>
      )
    case QueueStatus.BOUNCED:
      return (
        <Badge color="red" variant="light" tt="none">
          Bounced
        </Badge>
      )
  }
  return null
}

function next(i: QueueItem): string {
  if (i.status !== QueueStatus.WAITING) return ''
  const s = Number(i.nextAttempt) - Date.now() / 1000
  if (s <= 60) return 'now'
  if (s < 3600) return `in ${Math.round(s / 60)} min`
  return `in ${Math.round(s / 3600)} h`
}

export function QueuePage() {
  const qc = useQueryClient()
  const tenant = useTenant()
  const [filter, setFilter] = useState(String(QueueStatus.UNSPECIFIED))
  const q = useQuery(AdminService.method.listQueue, { tenantId: tenant, status: Number(filter) as QueueStatus, limit: 200 }, { refetchInterval: 15_000 })
  const done = { onSuccess: () => invalidate(qc, 'ListQueue', 'GetStats'), onError: (e: unknown) => notifications.show({ color: 'red', message: errorText(e) }) }
  const retry = useMutation(AdminService.method.retryQueue, done)
  const cancel = useMutation(AdminService.method.cancelQueue, done)
  const d = q.data
  const noRelay = d?.route.startsWith('not configured')
  return (
    <>
      <PageTitle
        title="Outbound queue"
        sub={d ? `${d.waiting} waiting · ${d.sentToday.toLocaleString()} delivered today · ${d.bouncedToday} bounced` : undefined}
        right={
          <Button variant="default" disabled={!d || d.waiting === 0n} loading={retry.isPending} onClick={() => retry.mutate({ tenantId: tenant, id: 0n })}>
            Retry all now
          </Button>
        }
      />
      {d && (
        <Alert variant="light" color={noRelay ? 'orange' : 'gray'} mb="md">
          {noRelay ? (
            <Text size="sm">
              No outbound relay is set up yet, so mail to other servers waits here. Most providers block port 25, so set <b>outbound.relay</b> in talaria.toml and restart; waiting mail then goes out.
            </Text>
          ) : (
            <Text size="sm">
              Mail to other servers leaves via <b>{d.route}</b>. Change it in talaria.toml under [outbound].
            </Text>
          )}
        </Alert>
      )}
      <SegmentedControl
        mb="sm"
        size="xs"
        value={filter}
        onChange={setFilter}
        data={[
          { value: String(QueueStatus.UNSPECIFIED), label: 'All' },
          { value: String(QueueStatus.WAITING), label: 'Waiting' },
          { value: String(QueueStatus.BOUNCED), label: 'Bounced' },
          { value: String(QueueStatus.SENT), label: 'Delivered' },
        ]}
      />
      <Paper className="t-pane" radius="lg">
        <Table.ScrollContainer minWidth={820}>
          <Table verticalSpacing="sm">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Recipient</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Last error</Table.Th>
                <Table.Th>Next try</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {(d?.items ?? []).map((i) => (
                <Table.Tr key={i.id.toString()}>
                  <Table.Td>
                    <Text size="sm">{i.to}</Text>
                    <Text size="xs" c="dimmed">
                      {bytes(i.size)} · {i.attempts} {i.attempts === 1 ? 'try' : 'tries'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{i.from || '(bounce)'}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Tooltip label={`Updated ${fullDate(i.updatedAt)}`}>
                      <span>
                        <StatusBadge s={i.status} />
                      </span>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td maw={320}>
                    <Text size="xs" c="dimmed" lineClamp={2} title={i.lastError}>
                      {i.lastError || '—'}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{next(i) || listDate(i.updatedAt)}</Text>
                  </Table.Td>
                  <Table.Td>
                    {i.status === QueueStatus.WAITING && (
                      <Group gap={4} wrap="nowrap">
                        <Button size="compact-xs" variant="default" onClick={() => retry.mutate({ tenantId: tenant, id: i.id })}>
                          Retry
                        </Button>
                        <Button size="compact-xs" variant="subtle" color="red" onClick={() => cancel.mutate({ tenantId: tenant, id: i.id })}>
                          Cancel
                        </Button>
                      </Group>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
              {q.isSuccess && d?.items.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={6}>
                    <Text c="dimmed" size="sm" ta="center" py="md">
                      Nothing here.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Paper>
    </>
  )
}
