// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Identities (certificate and private key) kept in this browser only. The
// private key is stored encrypted with an AES-GCM key that cannot be
// exported, which IndexedDB keeps as a CryptoKey object.

import type { Bytes } from './der'

export type Identity = {
  id: string // certificate SHA-256, hex
  emails: string[]
  subject: string
  issuer: string
  notAfter: number // ms
  chain: Bytes[] // DER, own certificate first
  wrapped: Bytes
  iv: Bytes
}

const DB = 'talaria-smime'

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => {
      req.result.createObjectStore('identities', { keyPath: 'id' })
      req.result.createObjectStore('meta')
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function run<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return open().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(store, mode)
        const req = fn(tx.objectStore(store))
        tx.oncomplete = () => {
          db.close()
          resolve(req.result)
        }
        tx.onerror = tx.onabort = () => {
          db.close()
          reject(tx.error)
        }
      }),
  )
}

async function wrappingKey(): Promise<CryptoKey> {
  const k = await run<CryptoKey | undefined>('meta', 'readonly', (s) => s.get('wrap'))
  if (k) return k
  const nk = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  await run('meta', 'readwrite', (s) => s.put(nk, 'wrap'))
  return nk
}

export async function seal(pkcs8: Bytes): Promise<{ wrapped: Bytes; iv: Bytes }> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await wrappingKey(), pkcs8))
  return { wrapped, iv }
}

export async function unseal(id: Identity): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: id.iv }, await wrappingKey(), id.wrapped))
}

export const list = () => run<Identity[]>('identities', 'readonly', (s) => s.getAll() as IDBRequest<Identity[]>)
export const put = (id: Identity) => run('identities', 'readwrite', (s) => s.put(id))
export const remove = (id: string) => run('identities', 'readwrite', (s) => s.delete(id))
