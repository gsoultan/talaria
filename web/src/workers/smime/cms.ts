// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// CMS (RFC 5652) for S/MIME: detached signatures and enveloped data.

import { type Bytes,
  type Node,
  ASN1Error,
  OID,
  Tag,
  algId,
  child,
  concat,
  encodeInt,
  encodeOid,
  explicit,
  implicitPrim,
  nullValue,
  octetString,
  octets,
  oid,
  parse,
  seq,
  setOf,
  tagged,
  time,
  tlv,
} from './der'
import { type RSAPrivate, decryptV15, encryptV15 } from './rsa'
import { type Cert, assertRSA, parseCert, sameBytes } from './x509'

const digestName: Record<string, string> = {
  [OID.sha1]: 'SHA-1',
  [OID.sha256]: 'SHA-256',
  [OID.sha384]: 'SHA-384',
  [OID.sha512]: 'SHA-512',
}

const sigHash: Record<string, string> = {
  [OID.sha1WithRSA]: 'SHA-1',
  [OID.sha256WithRSA]: 'SHA-256',
  [OID.sha384WithRSA]: 'SHA-384',
  [OID.sha512WithRSA]: 'SHA-512',
}

const attr = (type: string, value: Bytes) => seq(encodeOid(type), setOf(value))

const issuerAndSerial = (c: Cert) => seq(c.issuerRaw, c.serialRaw)

/** Signs content detached, with SHA-256. key signs RSASSA-PKCS1-v1_5. */
export async function sign(content: Bytes, key: CryptoKey, cert: Cert, chain: Cert[], when = new Date()): Promise<Bytes> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', content))
  const attrs = [
    attr(OID.contentType, encodeOid(OID.data)),
    attr(OID.signingTime, tlv(Tag.UTC_TIME, new TextEncoder().encode(utc(when)))),
    attr(OID.messageDigest, octetString(digest)),
  ]
  const signedAttrs = setOf(...attrs) // SET OF, as signed
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, signedAttrs))
  const signerInfo = seq(
    encodeInt(1),
    issuerAndSerial(cert),
    algId(OID.sha256),
    concat(Uint8Array.of(0xa0), signedAttrs.subarray(1)), // [0] IMPLICIT
    algId(OID.rsaEncryption, nullValue()),
    octetString(sig),
  )
  const certs = [cert, ...chain.filter((c) => !sameBytes(c.der, cert.der))].map((c) => c.der)
  const signedData = seq(encodeInt(1), setOf(algId(OID.sha256)), seq(encodeOid(OID.data)), tlv(0xa0, ...certs), setOf(signerInfo))
  return seq(encodeOid(OID.signedData), explicit(0, signedData))
}

function utc(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getUTCFullYear() % 100)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`
}

export type Verified = {
  /** The signature matches the content and the signer's key. */
  valid: boolean
  problem?: string
  signer?: Cert
  /** The signer's certificate first, then the others the message carried. */
  chain: Cert[]
  signedAt?: Date
}

/** Checks a detached signature (or an embedded one when content is absent). */
export async function verify(p7: Bytes, content?: Bytes): Promise<Verified & { content?: Bytes }> {
  const ci = parse(p7)
  if (oid(child(ci, 0)) !== OID.signedData) throw new ASN1Error('not a signature')
  const sd = child(tagged(ci, 0)!, 0)
  const encap = child(sd, 2)
  const embedded = tagged(encap, 0)
  if (!content && embedded) content = octets(child(embedded, 0))
  if (!content) throw new ASN1Error('the signed content is missing')
  const certsNode = sd.children.find((c) => c.tag === 0xa0)
  const certs: Cert[] = []
  for (const c of certsNode?.children ?? []) {
    try {
      if (c.tag === Tag.SEQUENCE) certs.push(parseCert(c.raw))
    } catch {
      /* skip what is not a certificate */
    }
  }
  const infos = sd.children[sd.children.length - 1]!
  if (infos.tag !== Tag.SET || infos.children.length !== 1) return { valid: false, problem: 'the signature does not name exactly one signer', chain: certs, content }
  const si = infos.children[0]!
  const sid = child(si, 1)
  const signer = certs.find((c) =>
    sid.tag === Tag.SEQUENCE ? sameBytes(c.issuerRaw, child(sid, 0).raw) && sameBytes(c.serialRaw, child(sid, 1).raw) : c.subjectKeyId && sameBytes(c.subjectKeyId, sid.body),
  )
  if (!signer) return { valid: false, problem: 'the signer’s certificate is not in the message', chain: certs, content }
  const chain = [signer, ...certs.filter((c) => c !== signer)]
  const hash = digestName[oid(child(child(si, 2), 0))]
  if (!hash) return { valid: false, problem: 'the signature uses an unknown hash', chain, content }
  let i = 3
  const signedAttrs = si.children[i]?.tag === 0xa0 ? si.children[i++] : undefined
  const sigAlg = oid(child(child(si, i++), 0))
  const signature = octets(child(si, i, Tag.OCTET_STRING))
  const digest = new Uint8Array(await crypto.subtle.digest(hash, content))
  let signedBytes = content
  let signedAt: Date | undefined
  if (signedAttrs) {
    let md: Bytes | undefined
    for (const a of signedAttrs.children) {
      const t = oid(child(a, 0))
      if (t === OID.messageDigest) md = octets(child(child(a, 1), 0))
      if (t === OID.signingTime) signedAt = time(child(child(a, 1), 0))
    }
    if (!md || !sameBytes(md, digest)) return { valid: false, problem: 'the message was changed after it was signed', chain, content, signer }
    signedBytes = concat(Uint8Array.of(Tag.SET), signedAttrs.raw.subarray(1))
  }
  if (sigAlg !== OID.rsaEncryption && !sigHash[sigAlg]) return { valid: false, problem: 'only RSA signatures can be checked for now', chain, content, signer }
  const key = await crypto.subtle.importKey('spki', signer.spki, { name: 'RSASSA-PKCS1-v1_5', hash: sigHash[sigAlg] ?? hash }, false, ['verify'])
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signedBytes)
  return ok ? { valid: true, chain, content, signer, signedAt } : { valid: false, problem: 'the signature is not valid', chain, content, signer }
}

/** Encrypts content to each certificate with AES-256-CBC. */
export async function encrypt(content: Bytes, recipients: Cert[]): Promise<Bytes> {
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', cek, 'AES-CBC', false, ['encrypt'])
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, content))
  const ris = recipients.map((r) => {
    assertRSA(r)
    return seq(encodeInt(0), issuerAndSerial(r), algId(OID.rsaEncryption, nullValue()), octetString(encryptV15(r.n, r.e, cek)))
  })
  cek.fill(0)
  const eci = seq(encodeOid(OID.data), algId(OID.aes256CBC, octetString(iv)), implicitPrim(0, ct))
  return seq(encodeOid(OID.envelopedData), explicit(0, seq(encodeInt(0), setOf(...ris), eci)))
}

const contentCiphers: Record<string, number> = { [OID.aes128CBC]: 16, [OID.aes192CBC]: 24, [OID.aes256CBC]: 32 }

/** Decrypts enveloped data with one of the identities' keys. */
export async function decrypt(p7: Bytes, mine: { cert: Cert; key: () => Promise<{ rsa: RSAPrivate; pkcs8: Bytes }> }[]): Promise<Bytes> {
  const ci = parse(p7)
  if (oid(child(ci, 0)) !== OID.envelopedData) throw new ASN1Error('not an encrypted message')
  const ed = child(tagged(ci, 0)!, 0)
  let i = 1
  if (ed.children[i]?.tag === 0xa0) i++ // originatorInfo
  const ris = child(ed, i++, Tag.SET)
  const eci = child(ed, i)
  const algNode = child(eci, 1)
  const alg = oid(child(algNode, 0))
  const keyLen = contentCiphers[alg]
  if (!keyLen) throw new ASN1Error(alg === OID.desEDE3CBC ? 'the message uses 3DES, which this browser cannot decrypt' : 'the message uses an unsupported cipher')
  if (keyLen === 24) throw new ASN1Error('the message uses AES-192, which browsers cannot decrypt')
  const iv = octets(child(algNode, 1, Tag.OCTET_STRING))
  const encNode = tagged(eci, 0)
  if (!encNode) throw new ASN1Error('the encrypted content is missing')
  const ct = octets(encNode)
  for (const ri of ris.children) {
    if (ri.tag !== Tag.SEQUENCE) continue // only key transport recipients
    const rid = child(ri, 1)
    const me = mine.find(({ cert }) =>
      rid.tag === Tag.SEQUENCE ? sameBytes(cert.issuerRaw, child(rid, 0).raw) && sameBytes(cert.serialRaw, child(rid, 1).raw) : cert.subjectKeyId && sameBytes(cert.subjectKeyId, rid.body),
    )
    if (!me) continue
    const kea = child(ri, 2)
    const encKey = octets(child(ri, 3, Tag.OCTET_STRING))
    const { rsa, pkcs8 } = await me.key()
    let cek: Bytes
    const keaOid = oid(child(kea, 0))
    if (keaOid === OID.rsaEncryption) cek = decryptV15(rsa, encKey, keyLen)
    else if (keaOid === OID.rsaOAEP) cek = await oaep(kea, pkcs8, encKey)
    else throw new ASN1Error('the message uses an unsupported key transport')
    try {
      const k = await crypto.subtle.importKey('raw', cek, 'AES-CBC', false, ['decrypt'])
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, k, ct))
    } catch {
      throw new ASN1Error('the message could not be decrypted with your key')
    } finally {
      cek.fill(0)
    }
  }
  throw new ASN1Error('the message is not encrypted to any of your certificates')
}

async function oaep(kea: Node, pkcs8: Bytes, encKey: Bytes): Promise<Bytes> {
  let hash = 'SHA-1'
  const params = kea.children[1]
  const h = params && tagged(params, 0)
  if (h) hash = digestName[oid(child(child(h, 0), 0))] ?? ''
  if (!hash) throw new ASN1Error('unsupported OAEP hash')
  const k = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash }, false, ['decrypt'])
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, k, encKey))
}
