// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Interoperability with OpenSSL: the .p12 files it exports with every
// common encryption, RSA and EC keys, the signatures and encrypted messages
// it reads and writes. Skipped without openssl.

import { beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { decrypt, encrypt, sign, signingKey, verify } from './cms'
import { type Bytes, b64Lines } from './der'
import { fieldSize, keyKind, publicPoint, samePoint } from './ec'
import { readPKCS12, WrongPassword } from './pkcs12'
import { rsaFromPKCS8 } from './rsa'
import { type Cert, parseCert } from './x509'

const hasOpenSSL = Bun.spawnSync(['openssl', 'version']).exitCode === 0
const dir = mkdtempSync(join(tmpdir(), 'smime-'))
const sh = (...args: string[]) => {
  const r = Bun.spawnSync(['openssl', ...args], { cwd: dir })
  if (r.exitCode !== 0) throw new Error(`openssl ${args.join(' ')}: ${r.stderr.toString()}`)
  return r.stdout
}
const file = (name: string): Bytes => new Uint8Array(readFileSync(join(dir, name)))
const enc = (s: string) => new TextEncoder().encode(s)
const dec = (b: Bytes) => new TextDecoder().decode(b)

/** Keys: RSA and the three NIST curves, each with a certificate from the CA. */
const KINDS = {
  rsa: ['-newkey', 'rsa:2048'],
  p256: ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256'],
  p384: ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-384'],
  p521: ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-521'],
} as const
type Kind = keyof typeof KINDS

async function certFor(pkcs8: Bytes, certs: Cert[]): Promise<Cert | undefined> {
  const k = keyKind(pkcs8)
  if (k.kind === 'rsa') {
    const rsa = rsaFromPKCS8(pkcs8)
    return certs.find((c) => c.n === rsa.n)
  }
  const pt = await publicPoint(pkcs8, k.curve)
  return certs.find((c) => c.curve === k.curve && c.point && samePoint(c.point, pt, fieldSize[k.curve]))
}

async function identity(kind: Kind, p12 = `${kind}.p12`, password = 's3cret pass') {
  const b = await readPKCS12(file(p12), password)
  const certs = b.certs.map(parseCert)
  const pkcs8 = b.keys[0]!
  const cert = (await certFor(pkcs8, certs))!
  return { certs, cert, pkcs8 }
}

describe.skipIf(!hasOpenSSL)('S/MIME with OpenSSL', () => {
  beforeAll(() => {
    writeFileSync(join(dir, 'ext.cnf'), 'subjectAltName=email:ana@x.example\nextendedKeyUsage=emailProtection\nkeyUsage=digitalSignature,keyEncipherment,keyAgreement\n')
    sh('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test CA')
    for (const [kind, args] of Object.entries(KINDS)) {
      sh('req', ...args, '-nodes', '-keyout', `${kind}.key`, '-out', `${kind}.csr`, '-subj', '/CN=Ana/emailAddress=ana@x.example')
      sh('x509', '-req', '-in', `${kind}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${kind}.pem`, '-days', '2', '-extfile', 'ext.cnf')
      sh('pkcs12', '-export', '-inkey', `${kind}.key`, '-in', `${kind}.pem`, '-certfile', 'ca.pem', '-out', `${kind}.p12`, '-passout', 'pass:s3cret pass')
    }
    writeFileSync(join(dir, 'plain.txt'), 'Content-Type: text/plain\r\n\r\nFrom OpenSSL, encrypted\r\n')
  })

  test('reads .p12 files with every common encryption', async () => {
    const legacy = ['-provider', 'legacy', '-provider', 'default']
    const variants: [string, string[]][] = [
      ['aes', ['-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'sha256']],
      ['aes128-sha512', ['-keypbe', 'AES-128-CBC', '-certpbe', 'AES-128-CBC', '-macalg', 'sha512']],
      ['3des', ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1']],
      ['rc2-40', [...legacy, '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-RC2-40', '-macalg', 'sha1']],
      ['rc2-128', [...legacy, '-keypbe', 'PBE-SHA1-RC2-128', '-certpbe', 'PBE-SHA1-RC2-128']],
      ['2des', [...legacy, '-keypbe', 'PBE-SHA1-2DES', '-certpbe', 'PBE-SHA1-3DES']],
      ['rc4', [...legacy, '-keypbe', 'PBE-SHA1-RC4-128', '-certpbe', 'PBE-SHA1-RC4-40']],
      ['pbes2-3des', ['-keypbe', 'DES-EDE3-CBC', '-certpbe', 'DES-EDE3-CBC']],
      ['pbes2-aes192', ['-keypbe', 'AES-192-CBC', '-certpbe', 'AES-192-CBC']],
      ['certs-plain', ['-keypbe', 'AES-256-CBC', '-certpbe', 'NONE']],
      ['no-mac', ['-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-nomac']],
    ]
    for (const [name, args] of variants) {
      sh('pkcs12', '-export', '-inkey', 'rsa.key', '-in', 'rsa.pem', '-certfile', 'ca.pem', '-out', `v-${name}.p12`, '-passout', 'pass:pässword', ...args)
      const { cert, certs } = await identity('rsa', `v-${name}.p12`, 'pässword')
      expect(cert?.emails, name).toEqual(['ana@x.example'])
      expect(certs.length, name).toBe(2)
      expect(readPKCS12(file(`v-${name}.p12`), 'wrong'), name).rejects.toBeInstanceOf(WrongPassword)
    }
    // An empty password.
    sh('pkcs12', '-export', '-inkey', 'rsa.key', '-in', 'rsa.pem', '-out', 'empty.p12', '-passout', 'pass:', '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES')
    expect((await identity('rsa', 'empty.p12', '')).cert.emails).toEqual(['ana@x.example'])
  })

  for (const kind of Object.keys(KINDS) as Kind[]) {
    describe(kind, () => {
      test('reads the .p12 and finds the certificate for the key', async () => {
        const { cert, certs } = await identity(kind)
        expect(certs.length).toBe(2)
        expect(cert.emails).toEqual(['ana@x.example'])
        expect(cert.subject).toContain('CN=Ana')
        expect(readPKCS12(file(`${kind}.p12`), 'wrong')).rejects.toBeInstanceOf(WrongPassword)
      })

      test('OpenSSL verifies our signature, and we notice changes', async () => {
        const { cert, certs, pkcs8 } = await identity(kind)
        const content = enc('Content-Type: text/plain\r\n\r\nPay by Friday.\r\n')
        const sig = await sign(content, await signingKey(pkcs8, cert), cert, certs)
        writeFileSync(join(dir, `${kind}-content.txt`), content)
        writeFileSync(join(dir, `${kind}-sig.der`), sig)
        sh('cms', '-verify', '-binary', '-inform', 'DER', '-in', `${kind}-sig.der`, '-content', `${kind}-content.txt`, '-CAfile', 'ca.pem', '-purpose', 'smimesign', '-out', '/dev/null')
        expect((await verify(sig, content)).valid).toBe(true)
        const changed = await verify(sig, enc('Content-Type: text/plain\r\n\r\nPay by Monday.\r\n'))
        expect(changed.valid).toBe(false)
        expect(changed.problem).toBe('the message was changed after it was signed')
      })

      test('we verify OpenSSL signatures', async () => {
        writeFileSync(join(dir, 'msg.txt'), 'Content-Type: text/plain\r\n\r\nHello from OpenSSL\r\n')
        const mds = kind === 'rsa' ? ['sha256', 'sha512', 'sha1'] : ['sha256', 'sha384', 'sha512']
        for (const md of mds) {
          sh('cms', '-sign', '-nodetach', '-binary', '-in', 'msg.txt', '-signer', `${kind}.pem`, '-inkey', `${kind}.key`, '-certfile', 'ca.pem', '-outform', 'DER', '-out', 'os.der', '-md', md)
          const r = await verify(file('os.der'))
          expect(r.valid, md).toBe(true)
          expect(r.signer?.emails).toEqual(['ana@x.example'])
          expect(dec(r.content!)).toContain('Hello from OpenSSL')
          expect(r.chain.length).toBe(2)
        }
        if (kind === 'rsa') {
          sh('cms', '-sign', '-nodetach', '-binary', '-in', 'msg.txt', '-signer', 'rsa.pem', '-inkey', 'rsa.key', '-outform', 'DER', '-out', 'pss.der', '-md', 'sha256', '-keyopt', 'rsa_padding_mode:pss')
          expect((await verify(file('pss.der'))).valid).toBe(true)
        }
      })

      test('OpenSSL decrypts what we encrypt', async () => {
        const { cert } = await identity(kind)
        const p7 = await encrypt(enc('Content-Type: text/plain\r\n\r\nSecret plans\r\n'), [cert])
        writeFileSync(join(dir, `${kind}-enc.der`), p7)
        const out = sh('cms', '-decrypt', '-binary', '-inform', 'DER', '-in', `${kind}-enc.der`, '-recip', `${kind}.pem`, '-inkey', `${kind}.key`).toString()
        expect(out).toContain('Secret plans')
        // And so do we.
        const { pkcs8 } = await identity(kind)
        expect(dec(await decrypt(p7, [{ cert, key: async () => pkcs8 }]))).toContain('Secret plans')
      })

      test('we decrypt what OpenSSL encrypts, with every common cipher', async () => {
        const { cert, pkcs8 } = await identity(kind)
        const mine = [{ cert, key: async () => pkcs8 }]
        const ciphers: [string, string[]][] = [
          ['aes256', ['-aes256']],
          ['aes192', ['-aes192']],
          ['aes128', ['-aes128']],
          ['3des', ['-des3']],
          ['aes256-gcm', ['-aes-256-gcm']],
          ['aes128-gcm', ['-aes-128-gcm']],
        ]
        if (kind === 'rsa') ciphers.push(['oaep', ['-aes256', '-recip', 'rsa.pem', '-keyopt', 'rsa_padding_mode:oaep']])
        else ciphers.push(['ecdh-sha1', ['-aes256', '-recip', `${kind}.pem`, '-keyopt', 'ecdh_kdf_md:sha1']], ['ecdh-sha512', ['-aes128', '-recip', `${kind}.pem`, '-keyopt', 'ecdh_kdf_md:sha512']])
        for (const [name, extra] of ciphers) {
          const args = extra.includes('-recip') ? extra : [...extra, `${kind}.pem`]
          sh('cms', '-encrypt', '-binary', '-in', 'plain.txt', '-outform', 'DER', '-out', `${kind}-${name}.der`, ...args)
          const out = dec(await decrypt(file(`${kind}-${name}.der`), mine))
          expect(out, name).toContain('From OpenSSL, encrypted')
        }
        // OpenSSL cannot wrap an 8-byte DES key for EC recipients.
        const old: [string, string[]][] = kind === 'rsa' ? [['rc2', ['-rc2']], ['rc2-40', ['-rc2-40']], ['des', ['-des']]] : [['rc2', ['-rc2']]]
        for (const [name, extra] of old) {
          sh('cms', '-encrypt', '-binary', '-provider', 'legacy', '-provider', 'default', '-in', 'plain.txt', '-outform', 'DER', '-out', `${kind}-${name}.der`, ...extra, `${kind}.pem`)
          expect(dec(await decrypt(file(`${kind}-${name}.der`), mine)), name).toContain('From OpenSSL, encrypted')
        }
      })
    })
  }

  test('one message to RSA and EC recipients at once', async () => {
    const rsa = await identity('rsa')
    const ec = await identity('p384')
    const p7 = await encrypt(enc('Content-Type: text/plain\r\n\r\nTo both\r\n'), [rsa.cert, ec.cert])
    writeFileSync(join(dir, 'both.der'), p7)
    for (const k of ['rsa', 'p384']) expect(sh('cms', '-decrypt', '-binary', '-inform', 'DER', '-in', 'both.der', '-recip', `${k}.pem`, '-inkey', `${k}.key`).toString()).toContain('To both')
    expect(dec(await decrypt(p7, [{ cert: ec.cert, key: async () => ec.pkcs8 }]))).toContain('To both')
  })

  test('base64 lines', () => {
    expect(b64Lines(new Uint8Array(100)).split('\r\n')[0]!.length).toBe(76)
  })
})
