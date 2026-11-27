// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Interoperability with OpenSSL: the .p12 it exports, the signatures and
// encrypted messages it reads and writes. Skipped without openssl.

import { beforeAll, describe, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { decrypt, encrypt, sign, verify } from './cms'
import { b64Lines } from './der'
import { readPKCS12, WrongPassword } from './pkcs12'
import { rsaFromPKCS8 } from './rsa'
import { parseCert } from './x509'

const hasOpenSSL = Bun.spawnSync(['openssl', 'version']).exitCode === 0
const dir = mkdtempSync(join(tmpdir(), 'smime-'))
const sh = (...args: string[]) => {
  const r = Bun.spawnSync(['openssl', ...args], { cwd: dir })
  if (r.exitCode !== 0) throw new Error(`openssl ${args.join(' ')}: ${r.stderr.toString()}`)
  return r.stdout
}

describe.skipIf(!hasOpenSSL)('S/MIME with OpenSSL', () => {
  beforeAll(() => {
    writeFileSync(join(dir, 'ext.cnf'), 'subjectAltName=email:ana@x.example\nextendedKeyUsage=emailProtection\nkeyUsage=digitalSignature,keyEncipherment\n')
    sh('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test CA')
    sh('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ana.key', '-out', 'ana.csr', '-subj', '/CN=Ana/emailAddress=ana@x.example')
    sh('x509', '-req', '-in', 'ana.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'ana.pem', '-days', '2', '-extfile', 'ext.cnf')
    sh('pkcs12', '-export', '-inkey', 'ana.key', '-in', 'ana.pem', '-certfile', 'ca.pem', '-out', 'ana.p12', '-passout', 'pass:s3cret pass', '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'sha256')
  })

  async function identity() {
    const b = await readPKCS12(new Uint8Array(readFileSync(join(dir, 'ana.p12'))), 's3cret pass')
    const certs = b.certs.map(parseCert)
    const pkcs8 = b.keys[0]!
    const rsa = rsaFromPKCS8(pkcs8)
    const cert = certs.find((c) => c.n === rsa.n)!
    return { certs, cert, pkcs8, rsa }
  }

  test('reads the .p12 and its certificate', async () => {
    const { cert, certs } = await identity()
    expect(certs.length).toBe(2)
    expect(cert.emails).toEqual(['ana@x.example'])
    expect(cert.subject).toContain('CN=Ana')
    expect(readPKCS12(new Uint8Array(readFileSync(join(dir, 'ana.p12'))), 'wrong')).rejects.toBeInstanceOf(WrongPassword)
  })

  test('OpenSSL verifies our signature', async () => {
    const { cert, certs, pkcs8 } = await identity()
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'])
    const content = new TextEncoder().encode('Content-Type: text/plain\r\n\r\nPay by Friday.\r\n')
    const sig = await sign(content, key, cert, certs)
    writeFileSync(join(dir, 'content.txt'), content)
    writeFileSync(join(dir, 'sig.der'), sig)
    sh('cms', '-verify', '-binary', '-inform', 'DER', '-in', 'sig.der', '-content', 'content.txt', '-CAfile', 'ca.pem', '-purpose', 'smimesign', '-out', '/dev/null')
    // And we verify it ourselves, and notice a change.
    expect((await verify(sig, content)).valid).toBe(true)
    const changed = await verify(sig, new TextEncoder().encode('Content-Type: text/plain\r\n\r\nPay by Monday.\r\n'))
    expect(changed.valid).toBe(false)
    expect(changed.problem).toBe('the message was changed after it was signed')
  })

  test('we verify an OpenSSL signature', async () => {
    writeFileSync(join(dir, 'msg.txt'), 'Content-Type: text/plain\r\n\r\nHello from OpenSSL\r\n')
    sh('cms', '-sign', '-nodetach', '-binary', '-in', 'msg.txt', '-signer', 'ana.pem', '-inkey', 'ana.key', '-certfile', 'ca.pem', '-outform', 'DER', '-out', 'os.der', '-md', 'sha256')
    const r = await verify(new Uint8Array(readFileSync(join(dir, 'os.der'))))
    expect(r.valid).toBe(true)
    expect(r.signer?.emails).toEqual(['ana@x.example'])
    expect(new TextDecoder().decode(r.content)).toContain('Hello from OpenSSL')
    expect(r.chain.length).toBe(2)
  })

  test('OpenSSL decrypts what we encrypt', async () => {
    const { cert } = await identity()
    const p7 = await encrypt(new TextEncoder().encode('Content-Type: text/plain\r\n\r\nSecret plans\r\n'), [cert])
    writeFileSync(join(dir, 'enc.der'), p7)
    const out = sh('cms', '-decrypt', '-binary', '-inform', 'DER', '-in', 'enc.der', '-recip', 'ana.pem', '-inkey', 'ana.key').toString()
    expect(out).toContain('Secret plans')
  })

  test('we decrypt what OpenSSL encrypts, PKCS #1 v1.5 and OAEP', async () => {
    const { cert, rsa, pkcs8 } = await identity()
    const mine = [{ cert, key: async () => ({ rsa, pkcs8 }) }]
    writeFileSync(join(dir, 'plain.txt'), 'Content-Type: text/plain\r\n\r\nFrom OpenSSL, encrypted\r\n')
    for (const [name, extra] of [
      ['aes256', ['-aes256', '-recip', 'ana.pem']],
      ['aes128', ['-aes128', '-recip', 'ana.pem']],
      ['oaep', ['-aes256', '-recip', 'ana.pem', '-keyopt', 'rsa_padding_mode:oaep']],
    ] as const) {
      sh('cms', '-encrypt', '-binary', '-in', 'plain.txt', '-outform', 'DER', '-out', `${name}.der`, ...extra)
      const out = new TextDecoder().decode(await decrypt(new Uint8Array(readFileSync(join(dir, `${name}.der`))), mine))
      expect(out).toContain('From OpenSSL, encrypted')
    }
    sh('cms', '-encrypt', '-binary', '-in', 'plain.txt', '-outform', 'DER', '-out', 'des.der', '-des3', 'ana.pem')
    expect(decrypt(new Uint8Array(readFileSync(join(dir, 'des.der'))), mine)).rejects.toThrow('3DES')
  })

  test('base64 lines', () => {
    expect(b64Lines(new Uint8Array(100)).split('\r\n')[0]!.length).toBe(76)
  })
})
