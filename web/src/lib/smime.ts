// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Talks to the S/MIME worker, which holds the private keys.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import type { IdentityInfo, SignatureInfo, SmimeRequest, SmimeResponse, SmimeResult } from '../workers/smime.worker'

export type { IdentityInfo, SignatureInfo }

let worker: Worker | undefined
let nextId = 1
const pending = new Map<number, { resolve: (r: SmimeResult) => void; reject: (e: Error) => void }>()

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('../workers/smime.worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (e: MessageEvent<SmimeResponse>) => {
      const p = pending.get(e.data.id)
      if (!p) return
      pending.delete(e.data.id)
      if (e.data.ok) p.resolve(e.data.result)
      else p.reject(new Error(e.data.error))
    }
  }
  return worker
}

type Without<T> = T extends unknown ? Omit<T, 'id'> : never

function call(req: Without<SmimeRequest>, transfer: Transferable[] = []): Promise<SmimeResult> {
  const id = nextId++
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    getWorker().postMessage({ ...req, id } as SmimeRequest, transfer)
  })
}

function expect<K extends SmimeResult['kind']>(r: SmimeResult, kind: K): Extract<SmimeResult, { kind: K }> {
  if (r.kind !== kind) throw new Error('unexpected answer from the S/MIME worker')
  return r as Extract<SmimeResult, { kind: K }>
}

export async function listIdentities(): Promise<IdentityInfo[]> {
  return expect(await call({ kind: 'list' }), 'list').identities
}

export async function importIdentity(file: File, password: string): Promise<IdentityInfo> {
  const p12 = await file.arrayBuffer()
  return expect(await call({ kind: 'import', p12, password }, [p12]), 'identity').identity
}

export async function removeIdentity(id: string): Promise<void> {
  await call({ kind: 'remove', identity: id })
}

export async function signEntity(email: string, entity: string): Promise<string> {
  return expect(await call({ kind: 'sign', email, entity }), 'entity').entity
}

export async function encryptEntity(email: string, entity: string, certs: string[]): Promise<string> {
  return expect(await call({ kind: 'encrypt', email, entity, certs }), 'entity').entity
}

export async function decryptMessage(raw: ArrayBuffer): Promise<{ entity: string; signature?: SignatureInfo }> {
  const r = expect(await call({ kind: 'decrypt', raw }, [raw]), 'decrypted')
  return { entity: r.entity, signature: r.signature }
}

const key = ['smime', 'identities']

/** The identities in this browser. */
export function useIdentities() {
  return useQuery({ queryKey: key, queryFn: listIdentities, staleTime: Infinity })
}

export function useRefreshIdentities() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: key })
}

/** The identity to sign as for an address, if this browser has one. */
export function identityFor(ids: IdentityInfo[] | undefined, email: string): IdentityInfo | undefined {
  const e = email.toLowerCase()
  return ids?.filter((i) => i.emails.includes(e) && i.notAfter > Date.now()).sort((a, b) => b.notAfter - a.notAfter)[0]
}
