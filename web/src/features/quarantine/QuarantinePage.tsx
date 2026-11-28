// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { Anchor, Box, Button, Group, Text, TextInput, Title } from '@mantine/core'
import { useDebouncedValue, useMediaQuery } from '@mantine/hooks'
import { notifications } from '@mantine/notifications'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { ofOps, useApiMutation, useApiQuery } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { Link } from '../../lib/router'
import { HeldTable } from './HeldTable'

/** The signed-in user's held mail. */
export function QuarantinePage() {
  const qc = useQueryClient()
  const narrow = useMediaQuery('(max-width: 62em)', false)
  const [q, setQ] = useState('')
  const [dq] = useDebouncedValue(q, 250)
  const list = useApiQuery('mail.ListQuarantine', { q: dq })
  const done = (message: string) => ({
    onSuccess: () => {
      notifications.show({ color: 'green', message })
      void qc.invalidateQueries({ predicate: ofOps('mail.ListQuarantine', 'mail.ListMailboxes') })
    },
    onError: (e: unknown) => notifications.show({ color: 'red', message: errorText(e) }),
  })
  const release = useApiMutation('mail.ReleaseQuarantined', done('Released to your Inbox.'))
  const del = useApiMutation('mail.DeleteQuarantined', done('Deleted.'))
  const days = list.data?.keepDays ?? 30
  return (
    <Box style={{ flex: 1, minWidth: 0, overflow: 'auto' }} p={narrow ? 'sm' : 0}>
      <Box maw={1100}>
        <Anchor component={Link} to="/mail/inbox" size="sm">
          ← Back to mail
        </Anchor>
        <Group justify="space-between" align="flex-end" mt="sm" mb="md" wrap="wrap">
          <div>
            <Title order={2}>Quarantine</Title>
            <Text size="sm" c="dimmed">
              Mail held back because it looks like spam or carries a dangerous attachment. It is deleted after {days} days.
            </Text>
          </div>
          <TextInput placeholder="Search sender or subject" value={q} onChange={(e) => setQ(e.currentTarget.value)} w={260} aria-label="Search held mail" />
        </Group>
        <HeldTable
          rows={list.data?.messages ?? []}
          loaded={list.isSuccess}
          onRelease={(m) => release.mutate({ id: m.id })}
          actions={(m) => (
            <Button size="compact-xs" variant="subtle" color="red" onClick={() => del.mutate({ id: m.id })}>
              Delete
            </Button>
          )}
        />
      </Box>
    </Box>
  )
}
