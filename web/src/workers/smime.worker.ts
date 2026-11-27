// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT
/// <reference lib="webworker" />

// S/MIME in the browser: private keys never leave this worker and the
// browser's storage. The server only ever sees certificates (public), the
// signed or encrypted message, and the plain text it composed itself.

import { type Bytes, b64, b64Lines, unb64 } from './smime/der'
import { decrypt, encrypt, sign, verify } from './smime/cms'
import * as keys from './smime/keystore'
import { readPKCS12 } from './smime/pkcs12'
import { rsaFromPKCS8 } from './smime/rsa'
import { type Cert, parseCert, sameBytes } from './smime/x509'

export type IdentityInfo = { id: string; emails: string[]; subject: string; issuer: string; notAfter: number; chain: string[] }

export type SignatureInfo = { valid: boolean; problem?: string; signer?: string; chain: string[]; signedAt?: number }

export type SmimeRequest =
  | { id: number; kind: 'list' }
  | { id: number; kind: 'import'; p12: ArrayBuffer; password: string }
  | { id: number; kind: 'remove'; identity: string }
  | { id: number; kind: 'sign'; email: string; entity: string }
  | { id: number; kind: 'encrypt'; email: string; entity: string; certs: string[] }
  | { id: number; kind: 'decrypt'; raw: ArrayBuffer }

export type SmimeResult =
  | { kind: 'list'; identities: IdentityInfo[] }
  | { kind: 'identity'; identity: IdentityInfo }
  | { kind: 'entity'; entity: string }
  | { kind: 'decrypted'; entity: string; signature?: SignatureInfo }
  | { kind: 'done' }

export type SmimeResponse = { id: number; ok: true; result: SmimeResult } | { id: number; ok: false; error: string }

declare const self: DedicatedWorkerGlobalScope

const hex = (b: Bytes) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const latin1 = (b: Bytes) => {
  let s = ''
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return s
}
const bytesOf = (s: string): Bytes => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff)

function info(i: keys.Identity): IdentityInfo {
  return { id: i.id, emails: i.emails, subject: i.subject, issuer: i.issuer, notAfter: i.notAfter, chain: i.chain.map(b64) }
}

async function importP12(file: Bytes, password: string): Promise<IdentityInfo> {
  const bundle = await readPKCS12(file, password)
  const certs = bundle.certs.map(parseCert)
  // The certificate that goes with the key: the one whose modulus matches.
  for (const pkcs8 of bundle.keys) {
    const rsa = rsaFromPKCS8(pkcs8)
    const mine = certs.find((c) => c.n === rsa.n)
    if (!mine) continue
    if (mine.emails.length === 0) throw new Error('the certificate names no email address')
    const chain = [mine, ...certs.filter((c) => c !== mine)]
    const id = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', mine.der)))
    const { wrapped, iv } = await keys.seal(pkcs8)
    const rec: keys.Identity = { id, emails: mine.emails, subject: mine.subject, issuer: mine.issuer, notAfter: mine.notAfter.getTime(), chain: chain.map((c) => c.der), wrapped, iv }
    await keys.put(rec)
    return info(rec)
  }
  throw new Error('the private key does not match any certificate in the file')
}

async function identityFor(email: string): Promise<keys.Identity> {
  const now = Date.now()
  const all = (await keys.list()).filter((i) => i.emails.includes(email.toLowerCase()) && i.notAfter > now)
  all.sort((a, b) => b.notAfter - a.notAfter)
  if (!all[0]) throw new Error(`no certificate for ${email} in this browser`)
  return all[0]
}

const boundary = () => `----=_smime_${hex(crypto.getRandomValues(new Uint8Array(12)))}`

async function signEntity(email: string, entity: string): Promise<string> {
  const id = await identityFor(email)
  const chain = id.chain.map(parseCert)
  const key = await crypto.subtle.importKey('pkcs8', await keys.unseal(id), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'])
  const content = new TextEncoder().encode(entity)
  const sig = await sign(content, key, chain[0]!, chain)
  const b = boundary()
  return (
    `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;\r\n boundary="${b}"\r\n\r\n` +
    `This is a cryptographically signed message in MIME format.\r\n\r\n--${b}\r\n${entity}\r\n--${b}\r\n` +
    `Content-Type: application/pkcs7-signature; name="smime.p7s"\r\nContent-Transfer-Encoding: base64\r\n` +
    `Content-Disposition: attachment; filename="smime.p7s"\r\nContent-Description: S/MIME Cryptographic Signature\r\n\r\n` +
    b64Lines(sig) +
    `\r\n--${b}--\r\n`
  )
}

async function encryptEntity(email: string, entity: string, certs: string[]): Promise<string> {
  const self = await identityFor(email)
  const to: Cert[] = certs.map((c) => parseCert(unb64(c)))
  // Also to the sender, so the copy in Sent can be read.
  const mine = parseCert(self.chain[0]!)
  if (!to.some((c) => sameBytes(c.der, mine.der))) to.push(mine)
  const p7 = await encrypt(new TextEncoder().encode(entity), to)
  return (
    `Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"\r\nContent-Transfer-Encoding: base64\r\n` +
    `Content-Disposition: attachment; filename="smime.p7m"\r\nContent-Description: S/MIME Encrypted Message\r\n\r\n` +
    b64Lines(p7)
  )
}

// --- reading MIME, as latin1 strings so bytes stay as they were ---

function splitEntity(s: string): { head: string; body: string } {
  const m = /\r?\n\r?\n/.exec(s)
  if (!m) return { head: s, body: '' }
  return { head: s.slice(0, m.index), body: s.slice(m.index + m[0].length) }
}

function header(head: string, name: string): string {
  const unfolded = head.replace(/\r?\n[ \t]+/g, ' ')
  for (const line of unfolded.split(/\r?\n/)) {
    const i = line.indexOf(':')
    if (i > 0 && line.slice(0, i).trim().toLowerCase() === name.toLowerCase()) return line.slice(i + 1).trim()
  }
  return ''
}

function param(value: string, name: string): string {
  const re = new RegExp(`;\\s*${name}\\s*=\\s*(?:"([^"]*)"|([^;\\s]+))`, 'i')
  const m = re.exec(value)
  return m ? (m[1] ?? m[2] ?? '') : ''
}

function decodeBody(head: string, body: string): Bytes {
  const cte = header(head, 'Content-Transfer-Encoding').toLowerCase()
  if (cte === 'base64') return unb64(body)
  return bytesOf(body)
}

/** The two parts of a multipart/signed body, the first exactly as signed. */
function splitSigned(body: string, b: string): [string, string] | null {
  const delim = `--${b}`
  const lines = body.split(/(?<=\n)/)
  const parts: string[] = []
  let cur: string[] | null = null
  for (const line of lines) {
    const t = line.replace(/[ \t\r\n]+$/, '')
    if (t === delim || t === `${delim}--`) {
      if (cur) {
        let p = cur.join('')
        p = p.replace(/\r?\n$/, '')
        parts.push(p)
      }
      if (t.endsWith('--') && t !== delim) break
      cur = []
      continue
    }
    cur?.push(line)
  }
  if (parts.length !== 2) return null
  let first = parts[0]!
  if (!first.includes('\r\n')) first = first.replace(/\n/g, '\r\n')
  return [first, parts[1]!]
}

async function checkSigned(entity: string): Promise<{ entity: string; signature?: SignatureInfo }> {
  const { head, body } = splitEntity(entity)
  const ct = header(head, 'Content-Type')
  const mt = ct.split(';')[0]!.trim().toLowerCase()
  let res: Awaited<ReturnType<typeof verify>> | undefined
  let shown = entity
  if (mt === 'multipart/signed') {
    const parts = splitSigned(body, param(ct, 'boundary'))
    if (!parts) return { entity }
    const sig = splitEntity(parts[1])
    res = await verify(decodeBody(sig.head, sig.body), bytesOf(parts[0]))
    shown = parts[0]
  } else if ((mt === 'application/pkcs7-mime' || mt === 'application/x-pkcs7-mime') && param(ct, 'smime-type').toLowerCase() === 'signed-data') {
    res = await verify(decodeBody(head, body))
    shown = res.content ? latin1(res.content) : entity
  } else {
    return { entity }
  }
  return {
    entity: shown,
    signature: { valid: res.valid, problem: res.problem, signer: res.signer?.emails[0], chain: res.chain.map((c) => b64(c.der)), signedAt: res.signedAt?.getTime() },
  }
}

async function decryptMessage(raw: Bytes): Promise<{ entity: string; signature?: SignatureInfo }> {
  const { head, body } = splitEntity(latin1(raw))
  const p7 = decodeBody(head, body)
  const mine = (await keys.list()).map((id) => ({
    cert: parseCert(id.chain[0]!),
    key: async () => {
      const pkcs8 = await keys.unseal(id)
      return { rsa: rsaFromPKCS8(pkcs8), pkcs8 }
    },
  }))
  if (mine.length === 0) throw new Error('there is no S/MIME certificate in this browser; import yours in Settings')
  const inner = latin1(await decrypt(p7, mine))
  return checkSigned(inner)
}

async function handle(req: SmimeRequest): Promise<SmimeResult> {
  switch (req.kind) {
    case 'list':
      return { kind: 'list', identities: (await keys.list()).map(info) }
    case 'import':
      return { kind: 'identity', identity: await importP12(new Uint8Array(req.p12), req.password) }
    case 'remove':
      await keys.remove(req.identity)
      return { kind: 'done' }
    case 'sign':
      return { kind: 'entity', entity: await signEntity(req.email, req.entity) }
    case 'encrypt':
      return { kind: 'entity', entity: await encryptEntity(req.email, req.entity, req.certs) }
    case 'decrypt': {
      const r = await decryptMessage(new Uint8Array(req.raw))
      return { kind: 'decrypted', ...r }
    }
  }
}

self.onmessage = (e: MessageEvent<SmimeRequest>) => {
  const req = e.data
  handle(req).then(
    (result) => self.postMessage({ id: req.id, ok: true, result } satisfies SmimeResponse),
    (err: unknown) => self.postMessage({ id: req.id, ok: false, error: err instanceof Error ? err.message : String(err) } satisfies SmimeResponse),
  )
}
