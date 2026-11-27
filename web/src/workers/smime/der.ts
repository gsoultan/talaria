// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// A small ASN.1 reader (DER and the BER that mail apps and Windows write:
// indefinite lengths, constructed strings) and a DER writer.

/** Bytes backed by a plain ArrayBuffer, as WebCrypto takes them. */
export type Bytes = Uint8Array<ArrayBuffer>

export type Node = {
  /** The identifier octet: class, constructed bit and tag number. */
  tag: number
  /** The whole element, header included. */
  raw: Bytes
  /** The contents (for an indefinite length, without the end marker). */
  body: Bytes
  children: Node[]
}

export class ASN1Error extends Error {}

export const Tag = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8: 0x0c,
  PRINTABLE: 0x13,
  IA5: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  BMP: 0x1e,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const

const constructed = (tag: number) => (tag & 0x20) !== 0

function readNode(buf: Bytes, start: number, depth: number): Node {
  if (depth > 40) throw new ASN1Error('nested too deeply')
  let i = start
  if (i >= buf.length) throw new ASN1Error('truncated')
  const tag = buf[i++]!
  if ((tag & 0x1f) === 0x1f) throw new ASN1Error('high tag numbers are not supported')
  if (i >= buf.length) throw new ASN1Error('truncated')
  let len = buf[i++]!
  let indefinite = false
  if (len === 0x80) {
    indefinite = true
  } else if (len & 0x80) {
    const n = len & 0x7f
    if (n > 4 || i + n > buf.length) throw new ASN1Error('bad length')
    len = 0
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++]!
  }
  const bodyStart = i
  const children: Node[] = []
  if (indefinite) {
    if (!constructed(tag)) throw new ASN1Error('indefinite length on a primitive')
    let p = bodyStart
    for (;;) {
      if (p + 1 >= buf.length) throw new ASN1Error('truncated')
      if (buf[p] === 0 && buf[p + 1] === 0) break
      const c = readNode(buf, p, depth + 1)
      children.push(c)
      p += c.raw.length
    }
    return { tag, raw: buf.subarray(start, p + 2), body: buf.subarray(bodyStart, p), children }
  }
  const end = bodyStart + len
  if (end > buf.length) throw new ASN1Error('truncated')
  const body = buf.subarray(bodyStart, end)
  if (constructed(tag)) {
    let p = bodyStart
    while (p < end) {
      const c = readNode(buf, p, depth + 1)
      children.push(c)
      p += c.raw.length
    }
  }
  return { tag, raw: buf.subarray(start, end), body, children }
}

/** Parses one element; trailing bytes are ignored. */
export function parse(buf: Bytes): Node {
  return readNode(buf, 0, 0)
}

export function child(n: Node, i: number, tag?: number): Node {
  const c = n.children[i]
  if (!c) throw new ASN1Error('missing element')
  if (tag !== undefined && c.tag !== tag) throw new ASN1Error(`expected tag ${tag.toString(16)}, got ${c.tag.toString(16)}`)
  return c
}

/** The children with a context tag [n], explicit or implicit. */
export function tagged(n: Node, num: number): Node | undefined {
  return n.children.find((c) => (c.tag & 0xc0) === 0x80 && (c.tag & 0x1f) === num)
}

/** The bytes of an OCTET STRING, joining the pieces of a BER constructed one. */
export function octets(n: Node): Bytes {
  if (!constructed(n.tag)) return n.body
  return concat(...n.children.map(octets))
}

export function oid(n: Node): string {
  if ((n.tag & 0x1f) !== Tag.OID) throw new ASN1Error('expected an OID')
  const b = n.body
  const out: number[] = []
  let v = 0
  for (let i = 0; i < b.length; i++) {
    v = v * 128 + (b[i]! & 0x7f)
    if (!(b[i]! & 0x80)) {
      if (out.length === 0) {
        const first = Math.min(2, Math.floor(v / 40))
        out.push(first, v - first * 40)
      } else out.push(v)
      v = 0
    }
  }
  return out.join('.')
}

export function int(n: Node): bigint {
  let v = 0n
  for (const b of n.body) v = (v << 8n) | BigInt(b)
  if (n.body.length && n.body[0]! & 0x80) v -= 1n << BigInt(n.body.length * 8)
  return v
}

export function smallInt(n: Node): number {
  return Number(int(n))
}

export function text(n: Node): string {
  const t = n.tag & 0x1f
  if (t === Tag.BMP) {
    let s = ''
    for (let i = 0; i + 1 < n.body.length; i += 2) s += String.fromCharCode((n.body[i]! << 8) | n.body[i + 1]!)
    return s
  }
  return new TextDecoder().decode(octets(n))
}

export function time(n: Node): Date {
  const s = text(n)
  const m = (n.tag & 0x1f) === Tag.UTC_TIME ? /^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/.exec(s) : /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?(?:\.\d+)?Z$/.exec(s)
  if (!m) throw new ASN1Error('bad time')
  let y = Number(m[1])
  if (m[1]!.length === 2) y += y < 50 ? 2000 : 1900
  return new Date(Date.UTC(y, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? 0)))
}

// --- writing ---

export function concat(...parts: Bytes[]): Bytes {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function lengthBytes(n: number): Bytes {
  if (n < 0x80) return Uint8Array.of(n)
  const b: number[] = []
  while (n > 0) {
    b.unshift(n & 0xff)
    n = Math.floor(n / 256)
  }
  return Uint8Array.of(0x80 | b.length, ...b)
}

export function tlv(tag: number, ...body: Bytes[]): Bytes {
  const b = concat(...body)
  return concat(Uint8Array.of(tag), lengthBytes(b.length), b)
}

export const seq = (...items: Bytes[]) => tlv(Tag.SEQUENCE, ...items)

/** A DER SET OF: its elements sorted by their encoding. */
export function setOf(...items: Bytes[]): Bytes {
  const sorted = [...items].sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!
    return a.length - b.length
  })
  return tlv(Tag.SET, ...sorted)
}

export const octetString = (b: Bytes) => tlv(Tag.OCTET_STRING, b)
export const nullValue = () => Uint8Array.of(Tag.NULL, 0)
/** An explicit (constructed) context tag [n]. */
export const explicit = (n: number, ...body: Bytes[]) => tlv(0xa0 | n, ...body)
/** An implicit primitive context tag [n]. */
export const implicitPrim = (n: number, body: Bytes) => tlv(0x80 | n, body)

export function encodeOid(s: string): Bytes {
  const parts = s.split('.').map(Number)
  const vals = [parts[0]! * 40 + parts[1]!, ...parts.slice(2)]
  const out: number[] = []
  for (const v of vals) {
    const b: number[] = [v & 0x7f]
    let x = Math.floor(v / 128)
    while (x > 0) {
      b.unshift((x & 0x7f) | 0x80)
      x = Math.floor(x / 128)
    }
    out.push(...b)
  }
  return tlv(Tag.OID, Uint8Array.from(out))
}

export function encodeInt(v: bigint | number): Bytes {
  let x = BigInt(v)
  if (x < 0n) throw new ASN1Error('negative integers are not written')
  const b: number[] = []
  do {
    b.unshift(Number(x & 0xffn))
    x >>= 8n
  } while (x > 0n)
  if (b[0]! & 0x80) b.unshift(0)
  return tlv(Tag.INTEGER, Uint8Array.from(b))
}

export function utcTime(d: Date): Bytes {
  const p = (n: number) => String(n).padStart(2, '0')
  const s = `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`
  return tlv(Tag.UTC_TIME, new TextEncoder().encode(s))
}

export const algId = (o: string, params?: Bytes) => seq(encodeOid(o), ...(params ? [params] : []))

export const OID = {
  data: '1.2.840.113549.1.7.1',
  signedData: '1.2.840.113549.1.7.2',
  envelopedData: '1.2.840.113549.1.7.3',
  encryptedData: '1.2.840.113549.1.7.6',
  rsaEncryption: '1.2.840.113549.1.1.1',
  rsaOAEP: '1.2.840.113549.1.1.7',
  sha1WithRSA: '1.2.840.113549.1.1.5',
  sha256WithRSA: '1.2.840.113549.1.1.11',
  sha384WithRSA: '1.2.840.113549.1.1.12',
  sha512WithRSA: '1.2.840.113549.1.1.13',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
  aes128CBC: '2.16.840.1.101.3.4.1.2',
  aes192CBC: '2.16.840.1.101.3.4.1.22',
  aes256CBC: '2.16.840.1.101.3.4.1.42',
  desEDE3CBC: '1.2.840.113549.3.7',
  rc2CBC: '1.2.840.113549.3.2',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  signingTime: '1.2.840.113549.1.9.5',
  emailAddress: '1.2.840.113549.1.9.1',
  subjectAltName: '2.5.29.17',
  subjectKeyId: '2.5.29.14',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  hmacSHA1: '1.2.840.113549.2.7',
  hmacSHA256: '1.2.840.113549.2.9',
  hmacSHA384: '1.2.840.113549.2.10',
  hmacSHA512: '1.2.840.113549.2.11',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  shroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  certBag: '1.2.840.113549.1.12.10.1.3',
  x509Certificate: '1.2.840.113549.1.9.22.1',
} as const

export function b64(b: Bytes): string {
  let s = ''
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return btoa(s)
}

export function unb64(s: string): Bytes {
  const bin = atob(s.replace(/[^A-Za-z0-9+/=]/g, ''))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Base64 in 76-character lines, CRLF ended, for MIME. */
export function b64Lines(b: Bytes): string {
  return (b64(b).match(/.{1,76}/g) ?? []).join('\r\n') + '\r\n'
}
