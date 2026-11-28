// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// CMS (RFC 5652) for S/MIME: detached signatures, enveloped data (RFC 5652)
// and authenticated enveloped data (RFC 5083), with RSA and EC keys.

import { BadPadding, aes, aesUnwrap, aesWrap, cbcDecrypt, des, des3, des3Unwrap, rc2 } from './ciphers'
import {
  type Bytes,
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
  int,
  nullValue,
  octetString,
  octets,
  oid,
  parse,
  seq,
  setOf,
  smallInt,
  tagged,
  time,
  tlv,
} from './der'
import { agree, agreeFor, curveHash, curveOfParams, fieldSize, kdfHash, keyKind, sharedInfo, sigFromDER, sigToDER, wrapLen, x963 } from './ec'
import { decryptV15, encryptV15, rsaFromPKCS8 } from './rsa'
import { type Cert, assertUsable, parseCert, sameBytes } from './x509'

const digestName: Record<string, string> = {
  [OID.sha1]: 'SHA-1',
  [OID.sha256]: 'SHA-256',
  [OID.sha384]: 'SHA-384',
  [OID.sha512]: 'SHA-512',
}
const digestOid: Record<string, string> = { 'SHA-1': OID.sha1, 'SHA-256': OID.sha256, 'SHA-384': OID.sha384, 'SHA-512': OID.sha512 }

const rsaSigHash: Record<string, string> = {
  [OID.sha1WithRSA]: 'SHA-1',
  [OID.sha256WithRSA]: 'SHA-256',
  [OID.sha384WithRSA]: 'SHA-384',
  [OID.sha512WithRSA]: 'SHA-512',
}

const ecdsaHash: Record<string, string> = {
  [OID.ecdsaSHA1]: 'SHA-1',
  [OID.ecdsaSHA256]: 'SHA-256',
  [OID.ecdsaSHA384]: 'SHA-384',
  [OID.ecdsaSHA512]: 'SHA-512',
}
const ecdsaOid: Record<string, string> = { 'SHA-256': OID.ecdsaSHA256, 'SHA-384': OID.ecdsaSHA384, 'SHA-512': OID.ecdsaSHA512 }

/** The micalg name of a hash, for multipart/signed. */
export const micalg: Record<string, string> = { 'SHA-1': 'sha-1', 'SHA-256': 'sha-256', 'SHA-384': 'sha-384', 'SHA-512': 'sha-512' }

const attr = (type: string, value: Bytes) => seq(encodeOid(type), setOf(value))

const issuerAndSerial = (c: Cert) => seq(c.issuerRaw, c.serialRaw)

/** The hash a signature with this certificate's key uses. */
export const signHash = (c: Cert) => (c.curve ? curveHash[c.curve] : 'SHA-256')

/** Imports a PKCS #8 key for signing with the certificate's key type. */
export function signingKey(pkcs8: Bytes, c: Cert): Promise<CryptoKey> {
  const hash = signHash(c)
  if (c.curve) return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: c.curve }, false, ['sign'])
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign'])
}

/** Signs content detached. key comes from signingKey for cert. */
export async function sign(content: Bytes, key: CryptoKey, cert: Cert, chain: Cert[], when = new Date()): Promise<Bytes> {
  const hash = signHash(cert)
  const digest = new Uint8Array(await crypto.subtle.digest(hash, content))
  const attrs = [
    attr(OID.contentType, encodeOid(OID.data)),
    attr(OID.signingTime, tlv(Tag.UTC_TIME, new TextEncoder().encode(utc(when)))),
    attr(OID.messageDigest, octetString(digest)),
  ]
  const signedAttrs = setOf(...attrs) // SET OF, as signed
  let sig: Bytes
  let sigAlg: Bytes
  if (cert.curve) {
    sig = sigToDER(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash }, key, signedAttrs)))
    sigAlg = algId(ecdsaOid[hash]!)
  } else {
    sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, signedAttrs))
    sigAlg = algId(OID.rsaEncryption, nullValue())
  }
  const signerInfo = seq(
    encodeInt(1),
    issuerAndSerial(cert),
    algId(digestOid[hash]!),
    concat(Uint8Array.of(0xa0), signedAttrs.subarray(1)), // [0] IMPLICIT
    sigAlg,
    octetString(sig),
  )
  const certs = [cert, ...chain.filter((c) => !sameBytes(c.der, cert.der))].map((c) => c.der)
  const signedData = seq(encodeInt(1), setOf(algId(digestOid[hash]!)), seq(encodeOid(OID.data)), tlv(0xa0, ...certs), setOf(signerInfo))
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

/** RSASSA-PSS parameters: the hash and the salt length. */
function pssParams(params: Node | undefined): { hash: string; saltLength: number } {
  let hash = 'SHA-1'
  let saltLength = 20
  for (const c of params?.children ?? []) {
    if (c.tag === 0xa0) hash = digestName[oid(child(child(c, 0), 0))] ?? ''
    if (c.tag === 0xa2) saltLength = smallInt(child(c, 0))
  }
  return { hash, saltLength }
}

/** Checks the signature value over signed with the signer's key. */
async function checkSignature(signer: Cert, alg: Node, digestHash: string, signature: Bytes, signed: Bytes): Promise<boolean | string> {
  const id = oid(child(alg, 0))
  if (signer.curve) {
    const hash = ecdsaHash[id] ?? (id === OID.ecPublicKey ? digestHash : '')
    if (!hash) return 'the signature uses an unknown algorithm'
    const raw = sigFromDER(signature, fieldSize[signer.curve])
    if (!raw) return false
    const key = await crypto.subtle.importKey('spki', signer.spki, { name: 'ECDSA', namedCurve: signer.curve }, false, ['verify'])
    return crypto.subtle.verify({ name: 'ECDSA', hash }, key, raw, signed)
  }
  if (signer.n === undefined) return 'the signer’s key type is not supported'
  if (id === OID.rsaPSS) {
    const { hash, saltLength } = pssParams(alg.children[1])
    if (!hash) return 'the signature uses an unknown hash'
    const spki = rsaSpki(signer)
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSA-PSS', hash }, false, ['verify'])
    return crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, key, signature, signed)
  }
  if (id !== OID.rsaEncryption && !rsaSigHash[id]) return 'the signature uses an unknown algorithm'
  const key = await crypto.subtle.importKey('spki', rsaSpki(signer), { name: 'RSASSA-PKCS1-v1_5', hash: rsaSigHash[id] ?? digestHash }, false, ['verify'])
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signed)
}

/** The certificate's RSA key as a plain rsaEncryption SPKI (PSS certificates name another algorithm). */
function rsaSpki(c: Cert): Bytes {
  if (oid(child(child(parse(c.spki), 0), 0)) === OID.rsaEncryption) return c.spki
  const key = child(parse(c.spki), 1).raw
  return seq(algId(OID.rsaEncryption, nullValue()), key)
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
  const sigAlg = child(si, i++)
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
  let ok: boolean | string
  try {
    ok = await checkSignature(signer, sigAlg, hash, signature, signedBytes)
  } catch {
    ok = false
  }
  if (typeof ok === 'string') return { valid: false, problem: ok, chain, content, signer }
  return ok ? { valid: true, chain, content, signer, signedAt } : { valid: false, problem: 'the signature is not valid', chain, content, signer }
}

// --- encryption ---

/** The recipient info for one certificate: RSA key transport or ECDH key agreement. */
async function recipientInfo(r: Cert, cek: Bytes): Promise<Bytes> {
  assertUsable(r)
  if (r.n !== undefined && r.e !== undefined) {
    return seq(encodeInt(0), issuerAndSerial(r), algId(OID.rsaEncryption, nullValue()), octetString(encryptV15(r.n, r.e, cek)))
  }
  const curve = r.curve!
  const eph = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits'])) as CryptoKeyPair
  const ephPoint = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey))
  const z = await agree(eph.privateKey, r.point!, curve)
  const agreeOid = agreeFor[curve]
  const hash = kdfHash[agreeOid]!
  const kek = await x963(hash, z, sharedInfo(OID.aes256Wrap, undefined, 32), 32)
  const wrapped = aesWrap(kek, cek)
  z.fill(0)
  kek.fill(0)
  const originator = explicit(0, concat(Uint8Array.of(0xa1), seq(algId(OID.ecPublicKey), tlv(Tag.BIT_STRING, Uint8Array.of(0), ephPoint)).subarray(1)))
  const body = seq(encodeInt(3), originator, algId(agreeOid, algId(OID.aes256Wrap)), seq(seq(issuerAndSerial(r), octetString(wrapped))))
  return concat(Uint8Array.of(0xa1), body.subarray(1)) // [1] IMPLICIT KeyAgreeRecipientInfo
}

/** Encrypts content to each certificate with AES-256-CBC. */
export async function encrypt(content: Bytes, recipients: Cert[]): Promise<Bytes> {
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const key = await crypto.subtle.importKey('raw', cek, 'AES-CBC', false, ['encrypt'])
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, content))
  const ris: Bytes[] = []
  for (const r of recipients) ris.push(await recipientInfo(r, cek))
  cek.fill(0)
  // Version 2 when any recipient uses key agreement (RFC 5652, 6.1).
  const version = recipients.some((r) => r.curve) ? 2 : 0
  const eci = seq(encodeOid(OID.data), algId(OID.aes256CBC, octetString(iv)), implicitPrim(0, ct))
  return seq(encodeOid(OID.envelopedData), explicit(0, seq(encodeInt(version), setOf(...ris), eci)))
}

// --- decryption ---

export type Mine = { cert: Cert; key: () => Promise<Bytes> }

/** How long the content key is for a content cipher, and how to use it. */
type Content = { keyLen: number; open: (cek: Bytes) => Promise<Bytes> }

function contentCipher(alg: Node, ct: Bytes, auth?: { mac: Bytes; aad: Bytes }): Content {
  const id = oid(child(alg, 0))
  const params = alg.children[1]
  const cbc = (keyLen: number, block: (k: Bytes) => ReturnType<typeof aes>, iv: Bytes): Content => ({ keyLen, open: async (cek) => cbcDecrypt(block(cek), iv, ct) })
  switch (id) {
    case OID.aes128CBC:
    case OID.aes256CBC: {
      const iv = octets(child(alg, 1, Tag.OCTET_STRING))
      return {
        keyLen: id === OID.aes128CBC ? 16 : 32,
        open: async (cek) => {
          const k = await crypto.subtle.importKey('raw', cek, 'AES-CBC', false, ['decrypt'])
          return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, k, ct))
        },
      }
    }
    case OID.aes192CBC:
      return cbc(24, aes, octets(child(alg, 1, Tag.OCTET_STRING)))
    case OID.desEDE3CBC:
      return cbc(24, des3, octets(child(alg, 1, Tag.OCTET_STRING)))
    case OID.desCBC:
      return cbc(8, des, octets(child(alg, 1, Tag.OCTET_STRING)))
    case OID.rc2CBC: {
      // RC2CBCParameter: the version encodes the effective key bits.
      let bits = 32
      let iv: Bytes
      if (params?.tag === Tag.OCTET_STRING) iv = octets(params)
      else {
        const v = params!.children[0]?.tag === Tag.INTEGER ? Number(int(params!.children[0])) : 32
        bits = v === 160 ? 40 : v === 120 ? 64 : v === 58 ? 128 : v >= 256 ? v : 32
        iv = octets(params!.children[params!.children.length - 1]!)
      }
      return cbc(Math.ceil(bits / 8), (k) => rc2(k, bits), iv)
    }
    case OID.aes128GCM:
    case OID.aes256GCM: {
      if (!auth) throw new ASN1Error('AES-GCM needs authenticated enveloped data')
      const nonce = octets(child(params!, 0, Tag.OCTET_STRING))
      const tagLen = params!.children[1] ? smallInt(params!.children[1]) : 12
      return {
        keyLen: id === OID.aes128GCM ? 16 : 32,
        open: async (cek) => {
          if (auth.mac.length !== tagLen) throw new BadPadding('bad tag')
          const k = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt'])
          return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: auth.aad, tagLength: tagLen * 8 }, k, concat(ct, auth.mac)))
        },
      }
    }
    case OID.aes192GCM:
      throw new ASN1Error('the message uses AES-192-GCM, which browsers cannot decrypt')
  }
  throw new ASN1Error('the message uses an unknown cipher')
}

const ridMatches = (cert: Cert, rid: Node) =>
  rid.tag === Tag.SEQUENCE ? sameBytes(cert.issuerRaw, child(rid, 0).raw) && sameBytes(cert.serialRaw, child(rid, 1).raw) : !!cert.subjectKeyId && sameBytes(cert.subjectKeyId, rid.body)

/** Gets the content key from a key transport (RSA) recipient info. */
async function transportKey(ri: Node, mine: Mine[], keyLen: number): Promise<Bytes | undefined> {
  const me = mine.find(({ cert }) => ridMatches(cert, child(ri, 1)))
  if (!me) return undefined
  const kea = child(ri, 2)
  const encKey = octets(child(ri, 3, Tag.OCTET_STRING))
  const pkcs8 = await me.key()
  const keaOid = oid(child(kea, 0))
  if (keaOid === OID.rsaEncryption) return decryptV15(rsaFromPKCS8(pkcs8), encKey, keyLen)
  if (keaOid === OID.rsaOAEP) return oaep(kea, pkcs8, encKey)
  throw new ASN1Error('the message uses an unsupported key transport')
}

/** Gets the content key from a key agreement (ECDH) recipient info. */
async function agreedKey(kari: Node, mine: Mine[]): Promise<Bytes | undefined> {
  const keys = kari.children[kari.children.length - 1]!
  let me: Mine | undefined
  let wrapped: Bytes | undefined
  for (const rek of keys.children) {
    const rid = child(rek, 0)
    // rKeyId [0] holds the subject key identifier first.
    const m = mine.find(({ cert }) => (rid.tag === 0xa0 ? !!cert.subjectKeyId && sameBytes(cert.subjectKeyId, child(rid, 0).body) : ridMatches(cert, rid)))
    if (m?.cert.curve) {
      me = m
      wrapped = octets(child(rek, 1, Tag.OCTET_STRING))
      break
    }
  }
  if (!me || !wrapped) return undefined
  const curve = me.cert.curve!
  const originator = child(child(kari, 1), 0)
  if (originator.tag !== 0xa1) throw new ASN1Error('the message uses a kind of key agreement that is not supported')
  const point = child(originator, 1, Tag.BIT_STRING).body.subarray(1)
  const oc = curveOfParams(child(originator, 0).children[1])
  if (oc && oc !== curve) throw new ASN1Error('the sender used a different curve')
  let i = 2
  const ukmNode = kari.children[i]?.tag === 0xa1 ? kari.children[i++] : undefined
  const ukm = ukmNode ? octets(child(ukmNode, 0)) : undefined
  const kea = child(kari, i)
  const hash = kdfHash[oid(child(kea, 0))]
  if (!hash) throw new ASN1Error('the message uses an unknown key agreement')
  const wrapAlg = oid(child(child(kea, 1), 0))
  const kekLen = wrapLen[wrapAlg]
  if (!kekLen) throw new ASN1Error('the message uses an unknown key wrap')
  const priv = await crypto.subtle.importKey('pkcs8', await me.key(), { name: 'ECDH', namedCurve: curve }, false, ['deriveBits'])
  const z = await agree(priv, point, curve)
  const kek = await x963(hash, z, sharedInfo(wrapAlg, ukm, kekLen), kekLen)
  z.fill(0)
  try {
    return wrapAlg === OID.des3Wrap ? await des3Unwrap(kek, wrapped) : aesUnwrap(kek, wrapped)
  } finally {
    kek.fill(0)
  }
}

/** Decrypts enveloped or authenticated enveloped data with one of the identities' keys. */
export async function decrypt(p7: Bytes, mine: Mine[]): Promise<Bytes> {
  const ci = parse(p7)
  const type = oid(child(ci, 0))
  if (type !== OID.envelopedData && type !== OID.authEnvelopedData) throw new ASN1Error('not an encrypted message')
  const ed = child(tagged(ci, 0)!, 0)
  let i = 1
  if (ed.children[i]?.tag === 0xa0) i++ // originatorInfo
  const ris = child(ed, i++, Tag.SET)
  const eci = child(ed, i++)
  const encNode = tagged(eci, 0)
  if (!encNode) throw new ASN1Error('the encrypted content is missing')
  const ct = octets(encNode)
  let auth: { mac: Bytes; aad: Bytes } | undefined
  if (type === OID.authEnvelopedData) {
    const authAttrs = ed.children[i]?.tag === 0xa1 ? ed.children[i++] : undefined
    const mac = octets(child(ed, i, Tag.OCTET_STRING))
    auth = { mac, aad: authAttrs ? concat(Uint8Array.of(Tag.SET), authAttrs.raw.subarray(1)) : new Uint8Array(0) }
  }
  const content = contentCipher(child(eci, 1), ct, auth)
  let found = false
  for (const ri of ris.children) {
    let cek: Bytes | undefined
    if (ri.tag === Tag.SEQUENCE) cek = await transportKey(ri, mine, content.keyLen)
    else if (ri.tag === 0xa1) cek = await agreedKey(ri, mine)
    else continue
    if (!cek) continue
    found = true
    try {
      return await content.open(cek)
    } catch {
      /* a wrong key for this recipient; try the next */
    } finally {
      cek.fill(0)
    }
  }
  throw new ASN1Error(found ? 'the message could not be decrypted with your key' : 'the message is not encrypted to any of your certificates')
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

export { keyKind }
