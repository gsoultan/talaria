// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Badge, Button, Group, Paper, Table, Text, Tooltip } from '@mantine/core'
import type { ReactNode } from 'react'
import { type HeldMessage } from '../../lib/api'
import { bytes, fullDate, listDate } from '../../lib/format'

export function ReasonBadge({ m }: { m: HeldMessage }) {
  return m.reason === 'malware' ? (
    <Badge color="red" variant="light" tt="none">
      Dangerous attachment
    </Badge>
  ) : (
    <Badge color="orange" variant="light" tt="none">
      Likely spam · {m.spamScore.toFixed(1)}
    </Badge>
  )
}

/** Held mail with the actions the caller may take on each message. */
export function HeldTable({
  rows,
  loaded,
  showRecipient,
  onOpen,
  onRelease,
  actions,
}: {
  rows: HeldMessage[]
  loaded: boolean
  showRecipient?: boolean
  onOpen?: (m: HeldMessage) => void
  onRelease: (m: HeldMessage) => void
  actions?: (m: HeldMessage) => ReactNode
}) {
  const cols = showRecipient ? 5 : 4
  return (
    <Paper className="t-pane" radius="lg">
      <Table.ScrollContainer minWidth={720}>
        <Table verticalSpacing="sm" highlightOnHover={!!onOpen}>
          <Table.Thead>
            <Table.Tr>
              {showRecipient && <Table.Th>Recipient</Table.Th>}
              <Table.Th>From and subject</Table.Th>
              <Table.Th>Reason</Table.Th>
              <Table.Th>Held</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((m) => (
              <Table.Tr key={m.id.toString()} style={onOpen ? { cursor: 'pointer' } : undefined} onClick={onOpen ? () => onOpen(m) : undefined}>
                {showRecipient && (
                  <Table.Td>
                    <Text size="sm">{m.recipient}</Text>
                  </Table.Td>
                )}
                <Table.Td maw={380}>
                  <Text size="sm" fw={600} truncate title={m.fromAddr}>
                    {m.fromName || m.fromAddr || m.envFrom || '(no sender)'}
                  </Text>
                  <Text size="sm" truncate title={m.subject}>
                    {m.subject || '(no subject)'}
                  </Text>
                  {m.envFrom && m.envFrom.toLowerCase() !== m.fromAddr.toLowerCase() && (
                    <Text size="xs" c="dimmed" truncate>
                      Sent by {m.envFrom}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td maw={260}>
                  <ReasonBadge m={m} />
                  <Text size="xs" c="dimmed" lineClamp={2} title={m.detail} mt={4}>
                    {m.detail}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Tooltip label={fullDate(m.createdAt)}>
                    <Text size="sm">{listDate(m.createdAt)}</Text>
                  </Tooltip>
                  <Text size="xs" c="dimmed">
                    {bytes(m.size)}
                  </Text>
                </Table.Td>
                <Table.Td onClick={(e) => e.stopPropagation()}>
                  <Group gap={4} wrap="nowrap" justify="flex-end">
                    {m.canRelease ? (
                      <Button size="compact-xs" variant="default" onClick={() => onRelease(m)}>
                        Release
                      </Button>
                    ) : (
                      <Tooltip label="An admin must review mail with dangerous attachments">
                        <Text size="xs" c="dimmed">
                          Admin review
                        </Text>
                      </Tooltip>
                    )}
                    {actions?.(m)}
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {loaded && rows.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={cols}>
                  <Text c="dimmed" size="sm" ta="center" py="md">
                    Nothing is held.
                  </Text>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Paper>
  )
}
