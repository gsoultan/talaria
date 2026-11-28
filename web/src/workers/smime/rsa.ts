// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// RSA with PKCS #1 v1.5 key transport, which most mail apps still use for
// encrypted mail and which WebCrypto does not offer.

import { type Bytes, ASN1Error, OID, Tag, child, int, octets, oid, parse } from './der'

export type RSAPrivate = { n: bigint; e: bigint; d: bigint; p: bigint; q: bigint; dp: bigint; dq: bigint; qi: bigint }

/** Reads the RSA key from a PKCS #8 PrivateKeyInfo. */
export function rsaFromPKCS8(pkcs8: Bytes): RSAPrivate {
  const pki = parse(pkcs8)
  if (oid(child(child(pki, 1), 0)) !== OID.rsaEncryption) throw new ASN1Error('only RSA keys are supported for now')
  const k = parse(octets(child(pki, 2, Tag.OCTET_STRING)))
  const v = (i: number) => int(child(k, i, Tag.INTEGER))
  return { n: v(1), e: v(2), d: v(3), p: v(4), q: v(5), dp: v(6), dq: v(7), qi: v(8) }
}

export function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n
  b %= m
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m
    e >>= 1n
    b = (b * b) % m
  }
  return r
}

export const byteLen = (n: bigint) => Math.ceil(n.toString(16).length / 2)

export function toBig(b: Bytes): bigint {
  let v = 0n
  for (const x of b) v = (v << 8n) | BigInt(x)
  return v
}

export function fromBig(v: bigint, len: number): Bytes {
  const out = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** The private operation, with the Chinese remainder theorem and blinding. */
function privateOp(k: RSAPrivate, c: bigint): bigint {
  // Blinding keeps the timing from depending on the ciphertext.
  const r = toBig(crypto.getRandomValues(new Uint8Array(byteLen(k.n)))) % k.n || 2n
  const cb = (c * modPow(r, k.e, k.n)) % k.n
  const m1 = modPow(cb % k.p, k.dp, k.p)
  const m2 = modPow(cb % k.q, k.dq, k.q)
  let h = ((m1 - m2) * k.qi) % k.p
  if (h < 0n) h += k.p
  const mb = m2 + h * k.q
  return (mb * modInverse(r, k.n)) % k.n
}

function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [a % m, m]
  let [oldS, s] = [1n, 0n]
  while (r !== 0n) {
    const q = oldR / r
    ;[oldR, r] = [r, oldR - q * r]
    ;[oldS, s] = [s, oldS - q * s]
  }
  return ((oldS % m) + m) % m
}

/**
 * Decrypts a PKCS #1 v1.5 key transport block. A malformed block gives a
 * random key of the expected length instead of an error, so the failure
 * shows only later, as content that does not decrypt (RFC 3218).
 */
export function decryptV15(k: RSAPrivate, block: Bytes, keyLen: number): Bytes {
  const len = byteLen(k.n)
  const em = fromBig(privateOp(k, toBig(block)), len)
  let sep = -1
  for (let i = 2; i < em.length; i++)
    if (em[i] === 0) {
      sep = i
      break
    }
  const ok = em[0] === 0 && em[1] === 2 && sep >= 10 && em.length - sep - 1 === keyLen
  return ok ? em.slice(sep + 1) : crypto.getRandomValues(new Uint8Array(keyLen))
}

/** Encrypts a content key to a public key with PKCS #1 v1.5. */
export function encryptV15(n: bigint, e: bigint, msg: Bytes): Bytes {
  const len = byteLen(n)
  if (msg.length > len - 11) throw new ASN1Error('key too small')
  const ps = new Uint8Array(len - 3 - msg.length)
  for (let i = 0; i < ps.length; i++) {
    let b = 0
    while (b === 0) b = crypto.getRandomValues(new Uint8Array(1))[0]!
    ps[i] = b
  }
  const em = new Uint8Array(len)
  em[1] = 2
  em.set(ps, 2)
  em.set(msg, 3 + ps.length)
  return fromBig(modPow(toBig(em), e, n), len)
}
