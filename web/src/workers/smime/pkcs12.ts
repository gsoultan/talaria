// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Reads a .p12 / .pfx file: the private key and certificates, protected
// with PBES2 (PBKDF2 and AES), which current Windows, macOS and OpenSSL
// write by default.

import { type Bytes, type Node, ASN1Error, OID, Tag, child, octets, oid, parse, smallInt, tagged } from './der'

export type Bundle = { keys: Bytes[]; certs: Bytes[] }

const prfHash: Record<string, string> = {
  [OID.hmacSHA1]: 'SHA-1',
  [OID.hmacSHA256]: 'SHA-256',
  [OID.hmacSHA384]: 'SHA-384',
  [OID.hmacSHA512]: 'SHA-512',
}

const aesLen: Record<string, number> = { [OID.aes128CBC]: 16, [OID.aes192CBC]: 24, [OID.aes256CBC]: 32 }

export class WrongPassword extends Error {}

/** Decrypts PBES2-protected bytes. alg is the AlgorithmIdentifier. */
async function pbes2(alg: Node, password: string, data: Bytes): Promise<Bytes> {
  const id = oid(child(alg, 0))
  if (id !== OID.pbes2) {
    throw new ASN1Error('this file uses old encryption (3DES or RC2). Export it again with AES, for example: openssl pkcs12 -export -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256')
  }
  const params = child(alg, 1)
  const kdf = child(params, 0)
  const enc = child(params, 1)
  if (oid(child(kdf, 0)) !== OID.pbkdf2) throw new ASN1Error('unsupported key derivation')
  const kp = child(kdf, 1)
  const salt = octets(child(kp, 0, Tag.OCTET_STRING))
  const iterations = smallInt(child(kp, 1, Tag.INTEGER))
  let hash = 'SHA-1'
  for (const c of kp.children.slice(2)) if (c.tag === Tag.SEQUENCE) hash = prfHash[oid(child(c, 0))] ?? ''
  if (!hash) throw new ASN1Error('unsupported key derivation hash')
  const encId = oid(child(enc, 0))
  const len = aesLen[encId]
  if (!len) throw new ASN1Error('this file uses a cipher other than AES-CBC')
  if (iterations > 10_000_000) throw new ASN1Error('too many iterations')
  const iv = octets(child(enc, 1, Tag.OCTET_STRING))
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash }, base, { name: 'AES-CBC', length: len * 8 }, false, ['decrypt'])
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, data))
  } catch {
    throw new WrongPassword('wrong password')
  }
}

async function bags(contents: Node, password: string, out: Bundle) {
  for (const bag of contents.children) {
    const id = oid(child(bag, 0))
    const value = child(tagged(bag, 0) ?? child(bag, 1), 0)
    if (id === OID.keyBag) out.keys.push(value.raw)
    else if (id === OID.shroudedKeyBag) out.keys.push(await pbes2(child(value, 0), password, octets(child(value, 1))))
    else if (id === OID.certBag && oid(child(value, 0)) === OID.x509Certificate) {
      out.certs.push(octets(child(tagged(value, 0)!, 0)))
    }
  }
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
  const safes = parse(octets(child(tagged(authSafe, 0)!, 0)))
  const out: Bundle = { keys: [], certs: [] }
  for (const ci of safes.children) {
    const type = oid(child(ci, 0))
    const content = child(tagged(ci, 0)!, 0)
    if (type === OID.data) {
      await bags(parse(octets(content)), password, out)
    } else if (type === OID.encryptedData) {
      const eci = child(content, 1)
      const enc = tagged(eci, 0)
      if (!enc) continue
      await bags(parse(await pbes2(child(eci, 1), password, octets(enc))), password, out)
    }
  }
  if (out.keys.length === 0) throw new ASN1Error('the file has no private key')
  if (out.certs.length === 0) throw new ASN1Error('the file has no certificate')
  return out
}
