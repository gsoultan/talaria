// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createAsyncStoragePersister } from '@tanstack/query-async-storage-persister'
import { MutationCache, QueryCache, QueryClient, type Query } from '@tanstack/react-query'
import { createStore, del, get, set } from 'idb-keyval'
import { opOf } from './api'
import { isUnauthenticated } from './errors'

// A signed-out session shows up as 401 on any call; re-asking Me then
// switches the app to the sign-in page.
const isMe = (q: Query) => opOf(q) === 'account.Me'

function onError(err: unknown, q?: Query) {
  if (q && isMe(q)) return
  if (isUnauthenticated(err)) void queryClient.refetchQueries({ predicate: isMe })
}

export const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({ onError: (err, q) => onError(err, q as Query) }),
  mutationCache: new MutationCache({ onError: (err) => onError(err) }),
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      // Kept a day so mail read once is still there offline.
      gcTime: 24 * 60 * 60_000,
      refetchOnWindowFocus: false,
      retry: 1,
      networkMode: 'offlineFirst',
    },
    mutations: { networkMode: 'always' },
  },
})

const store = createStore('talaria', 'cache')

export const persister = createAsyncStoragePersister({
  storage: { getItem: (k) => get<string>(k, store).then((v) => v ?? null), setItem: (k, v) => set(k, v, store), removeItem: (k) => del(k, store) },
  throttleTime: 2000,
})

// Only mail the person has looked at is kept for offline use.
const offline = new Set(['mail.ListMailboxes', 'mail.ListMessages', 'mail.GetMessage', 'mail.GetThread', 'account.Me', 'mail.ListIdentities'])

export function shouldPersist(q: Query): boolean {
  return q.state.status === 'success' && offline.has(opOf(q) ?? '')
}

/** Forget everything cached, on sign-out. */
export async function clearCache() {
  queryClient.clear()
  await persister.removeClient()
}
