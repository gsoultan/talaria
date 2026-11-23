// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import '@fontsource-variable/inter'
import '@mantine/core/styles.css'
import '@mantine/notifications/styles.css'
import './app/app.css'
import { TransportProvider } from '@connectrpc/connect-query'
import { MantineProvider } from '@mantine/core'
import { PersistQueryClientProvider } from '@tanstack/react-query-persist-client'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './app/App'
import { theme } from './app/theme'
import { persister, queryClient, shouldPersist } from './lib/queryClient'
import { RouterProvider } from './lib/router'
import { transport } from './lib/transport'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TransportProvider transport={transport}>
      <PersistQueryClientProvider
        client={queryClient}
        persistOptions={{ persister, maxAge: 7 * 24 * 60 * 60_000, buster: 'v1', dehydrateOptions: { shouldDehydrateQuery: shouldPersist } }}
      >
        <MantineProvider theme={theme} defaultColorScheme="auto">
          <RouterProvider>
            <App />
          </RouterProvider>
        </MantineProvider>
      </PersistQueryClientProvider>
    </TransportProvider>
  </StrictMode>,
)
