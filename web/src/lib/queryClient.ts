// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { createAsyncStoragePersister } from '@tanstack/query-async-storage-persister'
import { Code, ConnectError } from '@connectrpc/connect'
import { MutationCache, QueryCache, QueryClient, type Query } from '@tanstack/react-query'
import { createStore, del, get, set } from 'idb-keyval'

// A signed-out session shows up as Unauthenticated on any call; re-asking
// Me then switches the app to the sign-in page.
const isMe = (q: Query) => (q.queryKey[1] as { methodName?: string } | undefined)?.methodName === 'Me'

function onError(err: unknown, q?: Query) {
  if (q && isMe(q)) return
  if (err instanceof ConnectError && err.code === Code.Unauthenticated) void queryClient.refetchQueries({ predicate: isMe })
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

// int64 fields are bigints, which JSON cannot hold.
function replacer(_k: string, v: unknown) {
  return typeof v === 'bigint' ? { $big: v.toString() } : v
}
function reviver(_k: string, v: unknown) {
  if (v && typeof v === 'object' && '$big' in v && Object.keys(v).length === 1) return BigInt((v as { $big: string }).$big)
  return v
}

export const persister = createAsyncStoragePersister({
  storage: { getItem: (k) => get<string>(k, store).then((v) => v ?? null), setItem: (k, v) => set(k, v, store), removeItem: (k) => del(k, store) },
  serialize: (c) => JSON.stringify(c, replacer),
  deserialize: (s) => JSON.parse(s, reviver),
  throttleTime: 2000,
})

// Only mail the person has looked at is kept for offline use.
const offline = new Set(['ListMailboxes', 'ListMessages', 'GetMessage', 'GetThread', 'Me', 'ListIdentities'])

export function shouldPersist(q: Query): boolean {
  if (q.state.status !== 'success') return false
  const k = q.queryKey[1] as { methodName?: string } | undefined
  return !!k?.methodName && offline.has(k.methodName)
}

/** Forget everything cached, on sign-out. */
export async function clearCache() {
  queryClient.clear()
  await persister.removeClient()
}
