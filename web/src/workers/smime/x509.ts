// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// The parts of an X.509 certificate S/MIME needs.

import { type Bytes, type Node, ASN1Error, OID, Tag, child, int, oid, parse, tagged, text, time } from './der'
import { type Curve, curveOfParams } from './ec'

export type Cert = {
  der: Bytes
  /** The issuer Name as encoded, for IssuerAndSerialNumber. */
  issuerRaw: Bytes
  serialRaw: Bytes
  serial: bigint
  subject: string
  issuer: string
  notBefore: Date
  notAfter: Date
  /** SubjectPublicKeyInfo as encoded. */
  spki: Bytes
  keyAlg: string
  /** RSA modulus and exponent, for RSA keys. */
  n?: bigint
  e?: bigint
  /** Curve and public point, for EC keys. */
  curve?: Curve
  point?: Bytes
  emails: string[]
  subjectKeyId?: Bytes
}

const names: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  [OID.emailAddress]: 'E',
}

function nameText(n: Node): string {
  const parts: string[] = []
  for (const rdn of n.children) {
    for (const atv of rdn.children) {
      const k = names[oid(child(atv, 0))] ?? oid(child(atv, 0))
      try {
        parts.push(`${k}=${text(child(atv, 1))}`)
      } catch {
        /* skip values that are not text */
      }
    }
  }
  return parts.join(', ')
}

export function parseCert(der: Bytes): Cert {
  const c = parse(der)
  const tbs = child(c, 0, Tag.SEQUENCE)
  // [0] version is optional.
  let i = tbs.children[0]?.tag === 0xa0 ? 1 : 0
  const serialN = child(tbs, i++, Tag.INTEGER)
  i++ // signature algorithm
  const issuer = child(tbs, i++, Tag.SEQUENCE)
  const validity = child(tbs, i++, Tag.SEQUENCE)
  const subject = child(tbs, i++, Tag.SEQUENCE)
  const spki = child(tbs, i++, Tag.SEQUENCE)
  const cert: Cert = {
    der: c.raw,
    issuerRaw: issuer.raw,
    serialRaw: serialN.raw,
    serial: int(serialN),
    subject: nameText(subject),
    issuer: nameText(issuer),
    notBefore: time(child(validity, 0)),
    notAfter: time(child(validity, 1)),
    spki: spki.raw,
    keyAlg: oid(child(child(spki, 0), 0)),
    emails: [],
  }
  if (cert.keyAlg === OID.rsaEncryption) {
    const bits = child(spki, 1, Tag.BIT_STRING).body.subarray(1)
    const k = parse(bits)
    cert.n = int(child(k, 0, Tag.INTEGER))
    cert.e = int(child(k, 1, Tag.INTEGER))
  }
  if (cert.keyAlg === OID.ecPublicKey) {
    cert.curve = curveOfParams(child(spki, 0).children[1])
    cert.point = child(spki, 1, Tag.BIT_STRING).body.subarray(1)
  }
  const add = (e: string) => {
    e = e.trim().toLowerCase()
    if (e && !cert.emails.includes(e)) cert.emails.push(e)
  }
  const ext = tagged(tbs, 3)
  if (ext?.children[0]) {
    for (const x of ext.children[0].children) {
      const id = oid(child(x, 0))
      const value = x.children[x.children.length - 1]!
      if (id === OID.subjectAltName) {
        for (const g of parse(value.body).children) if (g.tag === 0x81) add(new TextDecoder().decode(g.body))
      } else if (id === OID.subjectKeyId) {
        cert.subjectKeyId = parse(value.body).body
      }
    }
  }
  for (const rdn of subject.children)
    for (const atv of rdn.children)
      if (oid(child(atv, 0)) === OID.emailAddress) {
        try {
          add(text(child(atv, 1)))
        } catch {
          /* ignore */
        }
      }
  return cert
}

export function sameBytes(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!
  return d === 0
}

/** Throws unless the certificate's key can be used here: RSA, or EC on a NIST curve. */
export function assertUsable(c: Cert) {
  if (c.n !== undefined && c.e !== undefined) return
  if (c.curve && c.point) return
  throw new ASN1Error(`the certificate for ${c.emails[0] ?? c.subject} uses a key type that is not supported`)
}
