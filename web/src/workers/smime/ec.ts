// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Elliptic curve keys for S/MIME: ECDSA signatures (RFC 5753 section 2)
// and ECDH key agreement with the ANSI X9.63 key derivation (RFC 5753
// section 3), on the NIST curves WebCrypto has.

import { type Bytes, type Node, ASN1Error, OID, Tag, child, concat, explicit, nullValue, octetString, oid, parse, seq, algId } from './der'

export type Curve = 'P-256' | 'P-384' | 'P-521'

export const curves: Record<string, Curve> = { [OID.p256]: 'P-256', [OID.p384]: 'P-384', [OID.p521]: 'P-521' }
export const curveOid: Record<Curve, string> = { 'P-256': OID.p256, 'P-384': OID.p384, 'P-521': OID.p521 }

/** Bytes in a field element (and in r and s of a signature). */
export const fieldSize: Record<Curve, number> = { 'P-256': 32, 'P-384': 48, 'P-521': 66 }

/** The hash that goes with a curve's strength. */
export const curveHash: Record<Curve, string> = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' }

/** The curve named by an AlgorithmIdentifier's parameters, if any. */
export function curveOfParams(params: Node | undefined): Curve | undefined {
  if (!params || params.tag !== Tag.OID) return undefined
  return curves[oid(params)]
}

/** What kind of key a PKCS #8 PrivateKeyInfo holds. */
export function keyKind(pkcs8: Bytes): { kind: 'rsa' } | { kind: 'ec'; curve: Curve } {
  const pki = parse(pkcs8)
  const alg = child(pki, 1)
  const id = oid(child(alg, 0))
  if (id === OID.rsaEncryption) return { kind: 'rsa' }
  if (id !== OID.ecPublicKey) throw new ASN1Error('the key type is not supported')
  let curve = curveOfParams(alg.children[1])
  if (!curve) {
    // The curve may be inside the ECPrivateKey instead, as [0].
    const ecpk = parse(child(pki, 2, Tag.OCTET_STRING).body)
    const p = ecpk.children.find((c) => c.tag === 0xa0)
    curve = curveOfParams(p?.children[0])
  }
  if (!curve) throw new ASN1Error('the key uses an elliptic curve that is not supported (use P-256, P-384 or P-521)')
  return { kind: 'ec', curve }
}

const fromB64url = (s: string): Bytes => {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(b, (c) => c.charCodeAt(0))
}

/** The public point (uncompressed) of an EC private key. */
export async function publicPoint(pkcs8: Bytes, curve: Curve): Promise<Bytes> {
  const k = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: curve }, true, ['deriveBits'])
  const jwk = await crypto.subtle.exportKey('jwk', k)
  return concat(Uint8Array.of(4), fromB64url(jwk.x!), fromB64url(jwk.y!))
}

/** Whether two encodings name the same point (compressed or not). */
export function samePoint(a: Bytes, b: Bytes, size: number): boolean {
  const x = (p: Bytes) => p.subarray(1, 1 + size)
  if (a.length === 0 || b.length === 0) return false
  for (let i = 0; i < size; i++) if (x(a)[i] !== x(b)[i]) return false
  const odd = (p: Bytes) => (p[0] === 4 ? p[p.length - 1]! & 1 : p[0] === 3 ? 1 : 0)
  return odd(a) === odd(b)
}

function unsignedInt(b: Bytes): Bytes {
  let i = 0
  while (i < b.length - 1 && b[i] === 0) i++
  const v = b.subarray(i)
  return v[0]! & 0x80 ? concat(Uint8Array.of(0), v) : v
}

/** WebCrypto's r||s signature as the DER SEQUENCE CMS carries. */
export function sigToDER(raw: Bytes): Bytes {
  const n = raw.length / 2
  return seq(tlvInt(raw.subarray(0, n)), tlvInt(raw.subarray(n)))
}

const tlvInt = (b: Bytes) => concat(Uint8Array.of(Tag.INTEGER, unsignedInt(b).length), unsignedInt(b))

/** A DER ECDSA signature as WebCrypto's r||s; undefined if malformed. */
export function sigFromDER(der: Bytes, size: number): Bytes | undefined {
  try {
    const s = parse(der)
    const out = new Uint8Array(2 * size)
    for (let i = 0; i < 2; i++) {
      let v = child(s, i, Tag.INTEGER).body
      while (v.length > size && v[0] === 0) v = v.subarray(1)
      if (v.length > size) return undefined
      out.set(v, (i + 1) * size - v.length)
    }
    return out
  } catch {
    return undefined
  }
}

/** The key-agreement algorithms: the hash for the X9.63 derivation. */
export const kdfHash: Record<string, string> = {
  [OID.ecdhSHA1]: 'SHA-1',
  [OID.ecdhSHA256]: 'SHA-256',
  [OID.ecdhSHA384]: 'SHA-384',
  [OID.ecdhSHA512]: 'SHA-512',
  // With cofactor 1, as on the NIST curves, cofactor DH is the same.
  [OID.ecdhCofactorSHA1]: 'SHA-1',
  [OID.ecdhCofactorSHA256]: 'SHA-256',
  [OID.ecdhCofactorSHA384]: 'SHA-384',
  [OID.ecdhCofactorSHA512]: 'SHA-512',
}

export const agreeFor: Record<Curve, string> = { 'P-256': OID.ecdhSHA256, 'P-384': OID.ecdhSHA384, 'P-521': OID.ecdhSHA512 }

export const wrapLen: Record<string, number> = { [OID.aes128Wrap]: 16, [OID.aes192Wrap]: 24, [OID.aes256Wrap]: 32, [OID.des3Wrap]: 24 }

/** ECC-CMS-SharedInfo: the wrap algorithm, the UKM, the key size in bits. */
export function sharedInfo(wrapOid: string, ukm: Bytes | undefined, keyBytes: number): Bytes {
  const bits = new Uint8Array(4)
  new DataView(bits.buffer).setUint32(0, keyBytes * 8)
  // The 3DES wrap names NULL parameters; the AES wraps none.
  return seq(algId(wrapOid, wrapOid === OID.des3Wrap ? nullValue() : undefined), ...(ukm ? [explicit(0, octetString(ukm))] : []), explicit(2, octetString(bits)))
}

/** The ANSI X9.63 key derivation. */
export async function x963(hash: string, z: Bytes, info: Bytes, len: number): Promise<Bytes> {
  const out = new Uint8Array(len)
  for (let counter = 1, done = 0; done < len; counter++) {
    const c = new Uint8Array(4)
    new DataView(c.buffer).setUint32(0, counter)
    const h = new Uint8Array(await crypto.subtle.digest(hash, concat(z, c, info)))
    out.set(h.subarray(0, Math.min(h.length, len - done)), done)
    done += h.length
  }
  return out
}

/** ECDH: the shared secret of a private key and a public point. */
export async function agree(priv: CryptoKey, point: Bytes, curve: Curve): Promise<Bytes> {
  const pub = await crypto.subtle.importKey('raw', point, { name: 'ECDH', namedCurve: curve }, false, [])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, fieldSize[curve] * 8))
}


