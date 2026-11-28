// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createTheme } from '@mantine/core'

export const theme = createTheme({
  primaryColor: 'blue',
  primaryShade: { light: 8, dark: 6 },
  defaultRadius: 'md',
  fontFamily: '"Inter Variable", Inter, system-ui, -apple-system, "Segoe UI", sans-serif',
  headings: { fontFamily: '"Inter Variable", Inter, system-ui, sans-serif', fontWeight: '700' },
  cursorType: 'pointer',
})
