// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Reads a .p12 / .pfx file: the private key and certificates. Takes what
// current and older exporters write: PBES2 (PBKDF2 with AES, 3DES, DES or
// RC2) and the PKCS #12 password-based schemes (3DES, RC2, RC4), with the
// file's MAC checked first so a wrong password is reported as such.

import { BadPadding, type Block, aes, cbcDecrypt, des, des3, rc2, rc4 } from './ciphers'
import { type Bytes, type Node, ASN1Error, OID, Tag, child, concat, int, octets, oid, parse, smallInt, tagged } from './der'

export type Bundle = { keys: Bytes[]; certs: Bytes[] }

export class WrongPassword extends Error {}

const hmacHash: Record<string, string> = {
  [OID.hmacSHA1]: 'SHA-1',
  [OID.hmacSHA256]: 'SHA-256',
  [OID.hmacSHA384]: 'SHA-384',
  [OID.hmacSHA512]: 'SHA-512',
}

const digestHash: Record<string, { name: string; u: number; v: number }> = {
  [OID.sha1]: { name: 'SHA-1', u: 20, v: 64 },
  [OID.sha256]: { name: 'SHA-256', u: 32, v: 64 },
  [OID.sha384]: { name: 'SHA-384', u: 48, v: 128 },
  [OID.sha512]: { name: 'SHA-512', u: 64, v: 128 },
}

const MAX_ITERATIONS = 10_000_000

/** The password as PKCS #12 wants it: UTF-16BE ending in two zero bytes. */
function bmp(password: string): Bytes {
  const out = new Uint8Array(password.length * 2 + 2)
  for (let i = 0; i < password.length; i++) {
    out[2 * i] = password.charCodeAt(i) >> 8
    out[2 * i + 1] = password.charCodeAt(i) & 0xff
  }
  return out
}

/** The PKCS #12 key derivation (RFC 7292 appendix B). id 1 key, 2 IV, 3 MAC. */
async function kdf12(hash: { name: string; u: number; v: number }, pass: Bytes, salt: Bytes, id: number, iterations: number, n: number): Promise<Bytes> {
  if (iterations > MAX_ITERATIONS) throw new ASN1Error('too many iterations')
  const { v, u } = hash
  const fill = (src: Bytes) => {
    const len = src.length === 0 ? 0 : v * Math.ceil(src.length / v)
    const out = new Uint8Array(len)
    for (let i = 0; i < len; i++) out[i] = src[i % src.length]!
    return out
  }
  const D = new Uint8Array(v).fill(id)
  const I = concat(fill(salt), fill(pass))
  const out = new Uint8Array(n)
  for (let done = 0; done < n; done += u) {
    let a = concat(D, I)
    for (let r = 0; r < iterations; r++) a = new Uint8Array(await crypto.subtle.digest(hash.name, a))
    out.set(a.subarray(0, Math.min(u, n - done)), done)
    if (done + u >= n) break
    const b = new Uint8Array(v)
    for (let i = 0; i < v; i++) b[i] = a[i % u]!
    for (let j = 0; j < I.length; j += v) {
      let carry = 1
      for (let k = v - 1; k >= 0; k--) {
        const x = I[j + k]! + b[k]! + carry
        I[j + k] = x & 0xff
        carry = x >> 8
      }
    }
  }
  return out
}

const sha1 = digestHash[OID.sha1]!

type Secret = { utf8: Bytes; bmp: Bytes }

/** Decrypts with a key from the PKCS #12 scheme (SHA-1 based). */
async function legacy(id: string, params: Node, pw: Secret, data: Bytes): Promise<Bytes> {
  const salt = octets(child(params, 0, Tag.OCTET_STRING))
  const iterations = smallInt(child(params, 1, Tag.INTEGER))
  const key = (n: number) => kdf12(sha1, pw.bmp, salt, 1, iterations, n)
  const iv = () => kdf12(sha1, pw.bmp, salt, 2, iterations, 8)
  switch (id) {
    case OID.pbeSHA3DES:
      return cbcDecrypt(des3(await key(24)), await iv(), data)
    case OID.pbeSHA2DES:
      return cbcDecrypt(des3(await key(16)), await iv(), data)
    case OID.pbeSHA128RC2:
      return cbcDecrypt(rc2(await key(16), 128), await iv(), data)
    case OID.pbeSHA40RC2:
      return cbcDecrypt(rc2(await key(5), 40), await iv(), data)
    case OID.pbeSHA128RC4:
      return rc4(await key(16), data)
    case OID.pbeSHA40RC4:
      return rc4(await key(5), data)
  }
  // PBES1 (PKCS #5 v1.5) with SHA-1: PBKDF1, the key and IV from one hash.
  let dk = concat(pw.utf8, salt)
  if (iterations > MAX_ITERATIONS) throw new ASN1Error('too many iterations')
  for (let i = 0; i < iterations; i++) dk = new Uint8Array(await crypto.subtle.digest('SHA-1', dk))
  if (id === OID.pbeSHA1DES) return cbcDecrypt(des(dk.subarray(0, 8)), dk.subarray(8, 16), data)
  return cbcDecrypt(rc2(dk.subarray(0, 8), 64), dk.subarray(8, 16), data)
}

/** RC2 parameters: the effective key bits from the version number. */
function rc2Params(n: Node): { bits: number; iv: Bytes } {
  if (n.tag === Tag.OCTET_STRING) return { bits: 32, iv: octets(n) }
  const version = n.children[0]?.tag === Tag.INTEGER ? Number(int(n.children[0])) : 32
  const iv = octets(n.children[n.children.length - 1]!)
  const bits = version === 160 ? 40 : version === 120 ? 64 : version === 58 ? 128 : version >= 256 ? version : 32
  return { bits, iv }
}

/** Decrypts PBES2-protected bytes (PBKDF2, then a block cipher in CBC mode). */
async function pbes2(params: Node, pw: Secret, data: Bytes): Promise<Bytes> {
  const kdf = child(params, 0)
  const enc = child(params, 1)
  if (oid(child(kdf, 0)) !== OID.pbkdf2) throw new ASN1Error('unsupported key derivation')
  const kp = child(kdf, 1)
  const salt = octets(child(kp, 0, Tag.OCTET_STRING))
  const iterations = smallInt(child(kp, 1, Tag.INTEGER))
  if (iterations > MAX_ITERATIONS) throw new ASN1Error('too many iterations')
  let keyLength = 0
  let hash = 'SHA-1'
  for (const c of kp.children.slice(2)) {
    if (c.tag === Tag.INTEGER) keyLength = smallInt(c)
    if (c.tag === Tag.SEQUENCE) hash = hmacHash[oid(child(c, 0))] ?? ''
  }
  if (!hash) throw new ASN1Error('unsupported key derivation hash')
  const encId = oid(child(enc, 0))
  const encParams = child(enc, 1)
  let make: (k: Bytes) => Block
  let iv: Bytes
  let len: number
  switch (encId) {
    case OID.aes128CBC:
    case OID.aes192CBC:
    case OID.aes256CBC:
      len = encId === OID.aes128CBC ? 16 : encId === OID.aes192CBC ? 24 : 32
      make = aes
      iv = octets(encParams)
      break
    case OID.desEDE3CBC:
      len = 24
      make = des3
      iv = octets(encParams)
      break
    case OID.desCBC:
      len = 8
      make = des
      iv = octets(encParams)
      break
    case OID.rc2CBC: {
      const p = rc2Params(encParams)
      len = keyLength || 16
      make = (k) => rc2(k, p.bits)
      iv = p.iv
      break
    }
    default:
      throw new ASN1Error('the file uses an unknown cipher')
  }
  const base = await crypto.subtle.importKey('raw', pw.utf8, 'PBKDF2', false, ['deriveBits'])
  const key = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash }, base, len * 8))
  try {
    return cbcDecrypt(make(key), iv, data)
  } finally {
    key.fill(0)
  }
}

async function decryptWith(alg: Node, pw: Secret, data: Bytes): Promise<Bytes> {
  const id = oid(child(alg, 0))
  try {
    if (id === OID.pbes2) return await pbes2(child(alg, 1), pw, data)
    return await legacy(id, child(alg, 1), pw, data)
  } catch (e) {
    if (e instanceof BadPadding) throw new WrongPassword('wrong password')
    if (e instanceof ASN1Error && e.message === 'bad 3DES key') throw e
    throw e instanceof ASN1Error ? e : new ASN1Error('the file uses an unknown encryption')
  }
}

const known = new Set<string>([OID.pbes2, OID.pbeSHA3DES, OID.pbeSHA2DES, OID.pbeSHA128RC2, OID.pbeSHA40RC2, OID.pbeSHA128RC4, OID.pbeSHA40RC4, OID.pbeSHA1DES, OID.pbeSHA1RC2])

async function bags(contents: Node, pw: Secret, out: Bundle) {
  for (const bag of contents.children) {
    const id = oid(child(bag, 0))
    const value = child(tagged(bag, 0) ?? child(bag, 1), 0)
    if (id === OID.keyBag) out.keys.push(value.raw)
    else if (id === OID.shroudedKeyBag) {
      const alg = child(value, 0)
      if (!known.has(oid(child(alg, 0)))) throw new ASN1Error('the key in this file uses an unknown encryption')
      out.keys.push(await decryptWith(alg, pw, octets(child(value, 1))))
    } else if (id === OID.certBag && oid(child(value, 0)) === OID.x509Certificate) {
      out.certs.push(octets(child(tagged(value, 0)!, 0)))
    }
  }
}

async function hmac(hash: string, key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash }, false, ['sign'])
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data))
}

/** Checks the file's MAC with the password; false when it does not match. */
async function macMatches(macData: Node, pw: Secret, content: Bytes): Promise<boolean> {
  const digestInfo = child(macData, 0)
  const alg = child(digestInfo, 0)
  const want = octets(child(digestInfo, 1, Tag.OCTET_STRING))
  const algId = oid(child(alg, 0))
  let got: Bytes
  if (algId === OID.pbmac1) {
    // PBMAC1 (RFC 9579): PBKDF2 makes the HMAC key.
    const params = child(alg, 1)
    const kdf = child(params, 0)
    const kp = child(kdf, 1)
    const salt = octets(child(kp, 0, Tag.OCTET_STRING))
    const iterations = smallInt(child(kp, 1, Tag.INTEGER))
    if (iterations > MAX_ITERATIONS) throw new ASN1Error('too many iterations')
    let keyLength = 32
    let prf = 'SHA-1'
    for (const c of kp.children.slice(2)) {
      if (c.tag === Tag.INTEGER) keyLength = smallInt(c)
      if (c.tag === Tag.SEQUENCE) prf = hmacHash[oid(child(c, 0))] ?? ''
    }
    const scheme = hmacHash[oid(child(child(params, 1), 0))]
    if (!prf || !scheme) throw new ASN1Error('the file uses an unknown integrity check')
    const base = await crypto.subtle.importKey('raw', pw.utf8, 'PBKDF2', false, ['deriveBits'])
    const key = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash: prf }, base, keyLength * 8))
    got = await hmac(scheme, key, content)
  } else {
    const hash = digestHash[algId]
    if (!hash) throw new ASN1Error('the file uses an unknown integrity check')
    const salt = octets(child(macData, 1, Tag.OCTET_STRING))
    const iterations = macData.children[2] ? smallInt(macData.children[2]) : 1
    got = await hmac(hash.name, await kdf12(hash, pw.bmp, salt, 3, iterations, hash.u), content)
  }
  if (got.length !== want.length) return false
  let d = 0
  for (let i = 0; i < got.length; i++) d |= got[i]! ^ want[i]!
  return d === 0
}

export async function readPKCS12(file: Bytes, password: string): Promise<Bundle> {
  let pfx: Node
  try {
    pfx = parse(file)
  } catch {
    throw new ASN1Error('not a .p12 or .pfx file')
  }
  const authSafe = child(pfx, 1)
  if (oid(child(authSafe, 0)) !== OID.data) throw new ASN1Error('public-key protected .p12 files are not supported')
  const content = octets(child(tagged(authSafe, 0)!, 0))
  const utf8 = new TextEncoder().encode(password)
  let pw: Secret = { utf8, bmp: bmp(password) }
  const macData = pfx.children[2]
  if (macData) {
    if (!(await macMatches(macData, pw, content))) {
      // Some exporters write an empty password as no bytes at all.
      const alt: Secret = { utf8, bmp: new Uint8Array(0) }
      if (password !== '' || !(await macMatches(macData, alt, content))) throw new WrongPassword('wrong password')
      pw = alt
    }
  }
  const safes = parse(content)
  const out: Bundle = { keys: [], certs: [] }
  for (const ci of safes.children) {
    const type = oid(child(ci, 0))
    const body = child(tagged(ci, 0)!, 0)
    if (type === OID.data) {
      await bags(parse(octets(body)), pw, out)
    } else if (type === OID.encryptedData) {
      const eci = child(body, 1)
      const enc = tagged(eci, 0)
      if (!enc) continue
      const alg = child(eci, 1)
      if (!known.has(oid(child(alg, 0)))) throw new ASN1Error('the certificates in this file use an unknown encryption')
      await bags(parse(await decryptWith(alg, pw, octets(enc))), pw, out)
    }
  }
  if (out.keys.length === 0) throw new ASN1Error('the file has no private key')
  if (out.certs.length === 0) throw new ASN1Error('the file has no certificate')
  return out
}
