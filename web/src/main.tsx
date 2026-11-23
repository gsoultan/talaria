// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import '@mantine/core/styles.css'
import { TransportProvider } from '@connectrpc/connect-query'
import { MantineProvider, createTheme } from '@mantine/core'
import { QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './app/App'
import { queryClient } from './lib/queryClient'
import { transport } from './lib/transport'

const theme = createTheme({ primaryColor: 'blue', defaultRadius: 'md' })

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TransportProvider transport={transport}>
      <QueryClientProvider client={queryClient}>
        <MantineProvider theme={theme} defaultColorScheme="auto">
          <App />
        </MantineProvider>
      </QueryClientProvider>
    </TransportProvider>
  </StrictMode>,
)
