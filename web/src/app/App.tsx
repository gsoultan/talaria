// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { AppShell, Button, Container, Group, Notification, Stack, Title } from '@mantine/core'
import { useEffect, useState } from 'react'
import { registerServiceWorker } from '../lib/registerSW'
import { ServerInfo } from './ServerInfo'

export function App() {
  const [update, setUpdate] = useState<(() => void) | null>(null)
  useEffect(() => registerServiceWorker((fn) => setUpdate(() => fn)), [])

  return (
    <AppShell header={{ height: 56 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md">
          <Title order={3}>Talaria</Title>
        </Group>
      </AppShell.Header>
      <AppShell.Main>
        <Container size="sm">
          <Stack>
            <ServerInfo />
            {update && (
              <Notification title="Update available" onClose={() => setUpdate(null)} withCloseButton>
                <Button size="xs" mt="xs" onClick={update}>
                  Reload
                </Button>
              </Notification>
            )}
          </Stack>
        </Container>
      </AppShell.Main>
    </AppShell>
  )
}
