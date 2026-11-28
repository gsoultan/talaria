// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The webmail's client for the kakarot API. Operations are called by name
// ("mail.ListMessages") with one input object; ops (generated from the
// OpenAPI document) says which fields go in the path and query, and the rest
// is the JSON body. Queries are cached under ['api', name, input].

import {
  type Query,
  type UseMutationOptions,
  type UseQueryOptions,
  queryOptions,
  useMutation,
  useQuery,
} from '@tanstack/react-query'
import { type OpName, type Ops, ops } from '../gen/api'

export type * from '../gen/api'
export type Input<O extends OpName> = Ops[O]['input']
export type Output<O extends OpName> = Ops[O]['output']

/** An error the API answered with: {"error":{"code","message","fields"}}. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly fields: Record<string, string> = {},
  ) {
    super(message)
  }
}

/** The URL of an operation, with path and query fields filled in. */
export function urlOf<O extends OpName>(name: O, input: Input<O>): string {
  const spec = ops[name]
  const values = input as Record<string, unknown>
  let path: string = spec.path
  for (const p of spec.pathParams) path = path.replace(`{${p}}`, encodeURIComponent(String(values[p])))
  const q = new URLSearchParams()
  for (const p of spec.query) {
    const v = values[p]
    if (v !== undefined && v !== '' && v !== 0 && v !== false && v !== null) q.set(p, String(v))
  }
  const qs = q.toString()
  return qs ? `${path}?${qs}` : path
}

function bodyOf<O extends OpName>(name: O, input: Input<O>): string | undefined {
  const spec = ops[name]
  if (!spec.body) return undefined
  const skip = new Set<string>([...spec.pathParams, ...spec.query])
  const rest = Object.fromEntries(Object.entries(input as Record<string, unknown>).filter(([k]) => !skip.has(k)))
  return JSON.stringify(rest)
}

/** Reads an error response into an ApiError. */
export async function errorFrom(res: Response): Promise<ApiError> {
  const body = (await res.json().catch(() => null)) as { error?: { code?: string; message?: string; fields?: Record<string, string> } } | null
  const e = body?.error
  return new ApiError(res.status, e?.code ?? 'internal', e?.message || res.statusText || 'request failed', e?.fields ?? {})
}

/** Calls an operation. */
export async function call<O extends OpName>(name: O, input: Input<O>, signal?: AbortSignal): Promise<Output<O>> {
  const spec = ops[name]
  const body = bodyOf(name, input)
  const res = await fetch(urlOf(name, input), {
    method: spec.method,
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body,
    credentials: 'same-origin',
    signal,
  })
  if (!res.ok) throw await errorFrom(res)
  return (await res.json()) as Output<O>
}

/** The cache key of a query. */
export const keyOf = <O extends OpName>(name: O, input: Input<O>) => ['api', name, input] as const

/** The operation a cached query belongs to. */
export const opOf = (q: Query): string | undefined => (q.queryKey[0] === 'api' ? (q.queryKey[1] as string) : undefined)

/** Query options for an operation, for useQuery, prefetching and cache reads. */
export function apiQuery<O extends OpName>(name: O, input: Input<O>) {
  return queryOptions({ queryKey: keyOf(name, input), queryFn: ({ signal }) => call(name, input, signal) })
}

type QueryOpts<O extends OpName> = Omit<UseQueryOptions<Output<O>, Error, Output<O>, ReturnType<typeof keyOf<O>>>, 'queryKey' | 'queryFn'>

/** useQuery for an operation. */
export function useApiQuery<O extends OpName>(name: O, input: Input<O>, opts?: QueryOpts<O>) {
  return useQuery({ ...apiQuery(name, input), ...opts })
}

/** useMutation for an operation. */
export function useApiMutation<O extends OpName, C = unknown>(name: O, opts?: Omit<UseMutationOptions<Output<O>, Error, Input<O>, C>, 'mutationFn'>) {
  return useMutation({ mutationFn: (input: Input<O>) => call(name, input), ...opts })
}

/** A predicate matching every cached query of the named operations. */
export const ofOps =
  (...names: OpName[]) =>
  (q: Query) =>
    names.includes(opOf(q) as OpName)

/** A file sent ahead of a message; Compose refers to it by id. */
export type Uploaded = { id: string; filename: string; contentType: string; size: number }

/**
 * Uploads one attachment. The file is the body, so it skips the API's JSON
 * size limit; the server keeps it for a day or until the message is sent.
 */
export async function upload(file: Blob, filename: string, signal?: AbortSignal): Promise<Uploaded> {
  const res = await fetch('/api/v1/uploads', {
    method: 'POST',
    headers: { 'Content-Type': file.type || 'application/octet-stream', 'X-Filename': encodeURIComponent(filename) },
    body: file,
    credentials: 'same-origin',
    signal,
  })
  if (!res.ok) throw await errorFrom(res)
  return (await res.json()) as Uploaded
}
