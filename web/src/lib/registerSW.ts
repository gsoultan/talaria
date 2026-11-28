// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { registerSW } from 'virtual:pwa-register'

// Registered after first paint so it never competes with the initial render.
export function registerServiceWorker(onNeedRefresh: (update: () => void) => void) {
  if (!('serviceWorker' in navigator) || import.meta.env.DEV) return
  const run = () => {
    const update = registerSW({
      onNeedRefresh: () => onNeedRefresh(() => void update(true)),
    })
  }
  if ('requestIdleCallback' in window) window.requestIdleCallback(run)
  else setTimeout(run, 1000)
}
