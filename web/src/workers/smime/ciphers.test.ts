// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

import { describe, expect, test } from 'bun:test'
import { aes, aesUnwrap, aesWrap, cbcDecrypt, cbcEncrypt, des, des3, rc2, rc4 } from './ciphers'

const h = (s: string) => Uint8Array.from(s.match(/../g)!.map((x) => parseInt(x, 16)))
const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
const hasOpenSSL = Bun.spawnSync(['openssl', 'version']).exitCode === 0

function openssl(cipher: string, key: string, iv: string, data: Uint8Array, legacy = false): Uint8Array<ArrayBuffer> {
  const r = Bun.spawnSync(['openssl', 'enc', `-${cipher}`, '-K', key, '-iv', iv, ...(legacy ? ['-provider', 'legacy', '-provider', 'default'] : [])], { stdin: data })
  if (r.exitCode !== 0) throw new Error(r.stderr.toString())
  return new Uint8Array(r.stdout)
}

describe('block ciphers', () => {
  test('AES known answers (FIPS 197)', () => {
    const pt = h('00112233445566778899aabbccddeeff')
    for (const [key, ct] of [
      ['000102030405060708090a0b0c0d0e0f', '69c4e0d86a7b0430d8cdb78070b4c55a'],
      ['000102030405060708090a0b0c0d0e0f1011121314151617', 'dda97ca4864cdfe06eaf70a0ec0d7191'],
      ['000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', '8ea2b7ca516745bfeafc49904b496089'],
    ] as const) {
      const c = aes(h(key))
      expect(hx(c.encrypt(pt))).toBe(ct)
      expect(hx(c.decrypt(h(ct)))).toBe(hx(pt))
    }
  })

  test('DES known answer', () => {
    // FIPS 81 / the classic "Now is the time for all " example.
    const c = des(h('0123456789abcdef'))
    expect(hx(c.encrypt(h('4e6f772069732074')))).toBe('3fa40e8a984d4815')
    expect(hx(c.decrypt(h('3fa40e8a984d4815')))).toBe('4e6f772069732074')
  })

  test('RC2 known answers (RFC 2268)', () => {
    expect(hx(rc2(h('0000000000000000'), 63).encrypt(h('0000000000000000')))).toBe('ebb773f993278eff')
    expect(hx(rc2(h('ffffffffffffffff'), 64).encrypt(h('ffffffffffffffff')))).toBe('278b27e42e2f0d49')
    expect(hx(rc2(h('88bca90e90875a7f0f79c384627bafb2'), 128).encrypt(h('0000000000000000')))).toBe('2269552ab0f85ca6')
    const c = rc2(h('88bca90e90875a7f0f79c384627bafb2'), 128)
    expect(hx(c.decrypt(h('2269552ab0f85ca6')))).toBe('0000000000000000')
  })

  test('RC4 known answer', () => {
    expect(hx(rc4(new TextEncoder().encode('Key'), new TextEncoder().encode('Plaintext')))).toBe('bbf316e8d940af0ad3')
  })

  test('AES key wrap (RFC 3394)', () => {
    const kek = h('000102030405060708090a0b0c0d0e0f')
    const key = h('00112233445566778899aabbccddeeff')
    const w = aesWrap(kek, key)
    expect(hx(w)).toBe('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5')
    expect(hx(aesUnwrap(kek, w))).toBe(hx(key))
    const k256 = h('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
    expect(hx(aesWrap(k256, key))).toBe('64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7')
    w[3]! ^= 1
    expect(() => aesUnwrap(kek, w)).toThrow()
  })

  test.skipIf(!hasOpenSSL)('CBC matches OpenSSL', () => {
    const data = new TextEncoder().encode('Some text that is longer than one block, to check chaining.')
    const iv8 = '0102030405060708'
    const iv16 = '0102030405060708090a0b0c0d0e0f10'
    const k24 = '00112233445566778899aabbccddeeff0011223344556677'
    for (const [name, block, iv, legacy] of [
      ['des-ede3-cbc', des3(h(k24)), iv8, false],
      ['aes-192-cbc', aes(h(k24)), iv16, false],
      ['rc2-cbc', rc2(h('00112233445566778899aabbccddeeff'), 128), iv8, true],
      ['des-cbc', des(h('0011223344556677')), iv8, true],
    ] as const) {
      const key = name === 'rc2-cbc' ? '00112233445566778899aabbccddeeff' : name === 'des-cbc' ? '0011223344556677' : k24
      const ct = openssl(name, key, iv, data, legacy)
      expect(hx(cbcEncrypt(block, h(iv), data))).toBe(hx(ct))
      expect(new TextDecoder().decode(cbcDecrypt(block, h(iv), ct))).toBe(new TextDecoder().decode(data))
    }
  })
})
