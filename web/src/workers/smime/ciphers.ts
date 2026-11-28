// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Block ciphers WebCrypto does not have, for older .p12 files and
// messages: DES and 3DES (FIPS 46-3), RC2 (RFC 2268), RC4, AES with 192-bit
// keys, and AES key wrap (RFC 3394) for every key size.

import { type Bytes, ASN1Error } from './der'

export interface Block {
  size: number
  encrypt(b: Bytes): Bytes
  decrypt(b: Bytes): Bytes
}

// --- DES: the standard's tables, bits numbered from 1 at the left ---

const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
const S = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

const ROT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

/** Applies a permutation table to n input bits held in a bigint-free pair. */
function permute(get: (bit: number) => number, table: number[]): number[] {
  return table.map((b) => get(b))
}

const bitsOf = (b: Bytes) => (k: number) => (b[(k - 1) >> 3]! >> (7 - ((k - 1) & 7))) & 1

function pack32(bits: number[], from: number): number {
  let v = 0
  for (let i = 0; i < 32; i++) v = (v << 1) | bits[from + i]!
  return v >>> 0
}

// S-boxes joined with P: SP[j][x] is P(S_j(x) in its place).
const SP: Uint32Array[] = S.map((box, j) => {
  const t = new Uint32Array(64)
  for (let x = 0; x < 64; x++) {
    const out = box[(((x >> 4) & 2) | (x & 1)) * 16 + ((x >> 1) & 15)]!
    const pre = new Array<number>(32).fill(0)
    for (let k = 0; k < 4; k++) pre[4 * j + k] = (out >> (3 - k)) & 1
    t[x] = pack32(
      P.map((p) => pre[p - 1]!),
      0,
    )
  }
  return t
})

const [SP0, SP1, SP2, SP3, SP4, SP5, SP6, SP7] = SP as [Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array, Uint32Array]

/** A 64-bit permutation as lookup tables: for each input byte and value, the output halves. */
function permTable(table: number[]): Uint32Array {
  const t = new Uint32Array(8 * 256 * 2)
  table.forEach((src, out) => {
    const byte = (src - 1) >> 3
    const bit = 7 - ((src - 1) & 7)
    for (let v = 0; v < 256; v++) {
      if (!((v >> bit) & 1)) continue
      const idx = 2 * (256 * byte + v) + (out < 32 ? 0 : 1)
      t[idx] = (t[idx]! | (1 << (31 - (out & 31)))) >>> 0
    }
  })
  return t
}

const IPT = permTable(IP)
const FPT = permTable(FP)

class DES implements Block {
  size = 8
  // 16 rounds of 8 six-bit chunks, in encryption and decryption order.
  private ek = new Uint8Array(128)
  private dk = new Uint8Array(128)

  constructor(key: Bytes) {
    const k = permute(bitsOf(key), PC1)
    let c = k.slice(0, 28)
    let d = k.slice(28)
    for (let r = 0; r < 16; r++) {
      const n = ROT[r]!
      c = [...c.slice(n), ...c.slice(0, n)]
      d = [...d.slice(n), ...d.slice(0, n)]
      const cd = [...c, ...d]
      const sub = PC2.map((p) => cd[p - 1]!)
      const chunks: number[] = []
      for (let j = 0; j < 8; j++) {
        let v = 0
        for (let i = 0; i < 6; i++) v = (v << 1) | sub[6 * j + i]!
        chunks.push(v)
      }
      this.ek.set(chunks, 8 * r)
      this.dk.set(chunks, 8 * (15 - r))
    }
  }

  private run(b: Bytes, keys: Uint8Array): Bytes {
    let l = 0
    let r = 0
    for (let i = 0; i < 8; i++) {
      l |= IPT[2 * (256 * i + b[i]!)]!
      r |= IPT[2 * (256 * i + b[i]!) + 1]!
    }
    l >>>= 0
    r >>>= 0
    for (let n = 0; n < 128; n += 8) {
      const f =
        SP0[(((r >>> 27) | (r << 5)) & 0x3f) ^ keys[n]!]! |
        SP1[((r >>> 23) & 0x3f) ^ keys[n + 1]!]! |
        SP2[((r >>> 19) & 0x3f) ^ keys[n + 2]!]! |
        SP3[((r >>> 15) & 0x3f) ^ keys[n + 3]!]! |
        SP4[((r >>> 11) & 0x3f) ^ keys[n + 4]!]! |
        SP5[((r >>> 7) & 0x3f) ^ keys[n + 5]!]! |
        SP6[((r >>> 3) & 0x3f) ^ keys[n + 6]!]! |
        SP7[(((r << 1) | (r >>> 31)) & 0x3f) ^ keys[n + 7]!]!
      const t = r
      r = (l ^ f) >>> 0
      l = t
    }
    // The halves swap before the final permutation.
    const pre = [r >>> 24, (r >>> 16) & 0xff, (r >>> 8) & 0xff, r & 0xff, l >>> 24, (l >>> 16) & 0xff, (l >>> 8) & 0xff, l & 0xff]
    let hi = 0
    let lo = 0
    for (let i = 0; i < 8; i++) {
      hi |= FPT[2 * (256 * i + pre[i]!)]!
      lo |= FPT[2 * (256 * i + pre[i]!) + 1]!
    }
    return Uint8Array.of(hi >>> 24, (hi >>> 16) & 0xff, (hi >>> 8) & 0xff, hi & 0xff, lo >>> 24, (lo >>> 16) & 0xff, (lo >>> 8) & 0xff, lo & 0xff)
  }

  encrypt(b: Bytes): Bytes {
    return this.run(b, this.ek)
  }

  decrypt(b: Bytes): Bytes {
    return this.run(b, this.dk)
  }
}

/** 3DES (EDE) with a 24-byte key, or a 16-byte two-key one. */
class TripleDES implements Block {
  size = 8
  private k1: DES
  private k2: DES
  private k3: DES
  constructor(key: Bytes) {
    if (key.length !== 16 && key.length !== 24) throw new ASN1Error('bad 3DES key')
    this.k1 = new DES(key.subarray(0, 8))
    this.k2 = new DES(key.subarray(8, 16))
    this.k3 = new DES(key.length === 24 ? key.subarray(16, 24) : key.subarray(0, 8))
  }
  encrypt(b: Bytes): Bytes {
    return this.k3.encrypt(this.k2.decrypt(this.k1.encrypt(b)))
  }
  decrypt(b: Bytes): Bytes {
    return this.k1.decrypt(this.k2.encrypt(this.k3.decrypt(b)))
  }
}

// --- RC2 ---

const PI = Uint8Array.from([0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32, 0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26, 0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a, 0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31, 0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e, 0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad])

class RC2 implements Block {
  size = 8
  private k = new Uint16Array(64)

  /** bits is the effective key length in bits. */
  constructor(key: Bytes, bits: number) {
    const l = new Uint8Array(128)
    l.set(key)
    const t = key.length
    for (let i = t; i < 128; i++) l[i] = PI[(l[i - 1]! + l[i - t]!) & 0xff]!
    const t8 = (bits + 7) >> 3
    const tm = 0xff >> (8 * t8 - bits)
    l[128 - t8] = PI[l[128 - t8]! & tm]!
    for (let i = 127 - t8; i >= 0; i--) l[i] = PI[l[i + 1]! ^ l[i + t8]!]!
    for (let i = 0; i < 64; i++) this.k[i] = l[2 * i]! | (l[2 * i + 1]! << 8)
  }

  encrypt(b: Bytes): Bytes {
    const r = [b[0]! | (b[1]! << 8), b[2]! | (b[3]! << 8), b[4]! | (b[5]! << 8), b[6]! | (b[7]! << 8)]
    const s = [1, 2, 3, 5]
    let j = 0
    const mix = () => {
      for (let i = 0; i < 4; i++) {
        const v = (r[i]! + this.k[j++]! + (r[(i + 3) & 3]! & r[(i + 2) & 3]!) + (~r[(i + 3) & 3]! & r[(i + 1) & 3]!)) & 0xffff
        r[i] = ((v << s[i]!) | (v >>> (16 - s[i]!))) & 0xffff
      }
    }
    const mash = () => {
      for (let i = 0; i < 4; i++) r[i] = (r[i]! + this.k[r[(i + 3) & 3]! & 63]!) & 0xffff
    }
    for (let n = 0; n < 5; n++) mix()
    mash()
    for (let n = 0; n < 6; n++) mix()
    mash()
    for (let n = 0; n < 5; n++) mix()
    return Uint8Array.from(r.flatMap((v) => [v & 0xff, v >>> 8]))
  }

  decrypt(b: Bytes): Bytes {
    const r = [b[0]! | (b[1]! << 8), b[2]! | (b[3]! << 8), b[4]! | (b[5]! << 8), b[6]! | (b[7]! << 8)]
    const s = [1, 2, 3, 5]
    let j = 63
    const rmix = () => {
      for (let i = 3; i >= 0; i--) {
        const v = r[i]!
        r[i] = ((v >>> s[i]!) | (v << (16 - s[i]!))) & 0xffff
        r[i] = (r[i]! - this.k[j--]! - (r[(i + 3) & 3]! & r[(i + 2) & 3]!) - (~r[(i + 3) & 3]! & r[(i + 1) & 3]!)) & 0xffff
      }
    }
    const rmash = () => {
      for (let i = 3; i >= 0; i--) r[i] = (r[i]! - this.k[r[(i + 3) & 3]! & 63]!) & 0xffff
    }
    for (let n = 0; n < 5; n++) rmix()
    rmash()
    for (let n = 0; n < 6; n++) rmix()
    rmash()
    for (let n = 0; n < 5; n++) rmix()
    return Uint8Array.from(r.flatMap((v) => [v & 0xff, v >>> 8]))
  }
}

// --- AES (FIPS 197), tables computed at start ---

const SBOX = new Uint8Array(256)
const INV = new Uint8Array(256)
{
  let p = 1
  let q = 1
  do {
    p = (p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0)) & 0xff
    q ^= q << 1
    q ^= q << 2
    q ^= q << 4
    q &= 0xff
    if (q & 0x80) q ^= 0x09
    const x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
    SBOX[p] = (x ^ 0x63) & 0xff
  } while (p !== 1)
  SBOX[0] = 0x63
  for (let i = 0; i < 256; i++) INV[SBOX[i]!] = i
}

const xt = (a: number) => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff
function mul(a: number, b: number): number {
  let r = 0
  while (b) {
    if (b & 1) r ^= a
    a = xt(a)
    b >>= 1
  }
  return r
}

const ror8 = (v: number) => ((v >>> 8) | (v << 24)) >>> 0
const TE = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)]
const TD = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)]
for (let x = 0; x < 256; x++) {
  const s = SBOX[x]!
  const i = INV[x]!
  let e = ((mul(s, 2) << 24) | (s << 16) | (s << 8) | mul(s, 3)) >>> 0
  let d = ((mul(i, 14) << 24) | (mul(i, 9) << 16) | (mul(i, 13) << 8) | mul(i, 11)) >>> 0
  for (let k = 0; k < 4; k++) {
    TE[k]![x] = e
    TD[k]![x] = d
    e = ror8(e)
    d = ror8(d)
  }
}
const [TE0, TE1, TE2, TE3] = TE as [Uint32Array, Uint32Array, Uint32Array, Uint32Array]
const [TD0, TD1, TD2, TD3] = TD as [Uint32Array, Uint32Array, Uint32Array, Uint32Array]

const word = (b: Bytes, i: number) => ((b[i]! << 24) | (b[i + 1]! << 16) | (b[i + 2]! << 8) | b[i + 3]!) >>> 0

class AES implements Block {
  size = 16
  private ek: Uint32Array
  private dk: Uint32Array
  private rounds: number

  constructor(key: Bytes) {
    const nk = key.length / 4
    if (![4, 6, 8].includes(nk)) throw new ASN1Error('bad AES key')
    const nr = nk + 6
    this.rounds = nr
    const w = new Uint32Array(4 * (nr + 1))
    for (let i = 0; i < nk; i++) w[i] = word(key, 4 * i)
    let rcon = 1
    for (let i = nk; i < w.length; i++) {
      let t = w[i - 1]!
      if (i % nk === 0) {
        t = ((SBOX[(t >>> 16) & 0xff]! << 24) | (SBOX[(t >>> 8) & 0xff]! << 16) | (SBOX[t & 0xff]! << 8) | SBOX[t >>> 24]!) ^ (rcon << 24)
        rcon = xt(rcon)
      } else if (nk > 6 && i % nk === 4) {
        t = (SBOX[t >>> 24]! << 24) | (SBOX[(t >>> 16) & 0xff]! << 16) | (SBOX[(t >>> 8) & 0xff]! << 8) | SBOX[t & 0xff]!
      }
      w[i] = (w[i - nk]! ^ t) >>> 0
    }
    this.ek = w
    // The equivalent inverse cipher's keys: reversed, with InvMixColumns inside.
    const dk = new Uint32Array(w.length)
    for (let r = 0; r <= nr; r++) {
      for (let c = 0; c < 4; c++) {
        const v = w[4 * (nr - r) + c]!
        dk[4 * r + c] =
          r === 0 || r === nr ? v : (TD0[SBOX[v >>> 24]!]! ^ TD1[SBOX[(v >>> 16) & 0xff]!]! ^ TD2[SBOX[(v >>> 8) & 0xff]!]! ^ TD3[SBOX[v & 0xff]!]!) >>> 0
      }
    }
    this.dk = dk
  }

  encrypt(b: Bytes): Bytes {
    const k = this.ek
    let s0 = word(b, 0) ^ k[0]!
    let s1 = word(b, 4) ^ k[1]!
    let s2 = word(b, 8) ^ k[2]!
    let s3 = word(b, 12) ^ k[3]!
    for (let r = 1; r < this.rounds; r++) {
      const o = 4 * r
      const t0 = TE0[s0 >>> 24]! ^ TE1[(s1 >>> 16) & 0xff]! ^ TE2[(s2 >>> 8) & 0xff]! ^ TE3[s3 & 0xff]! ^ k[o]!
      const t1 = TE0[s1 >>> 24]! ^ TE1[(s2 >>> 16) & 0xff]! ^ TE2[(s3 >>> 8) & 0xff]! ^ TE3[s0 & 0xff]! ^ k[o + 1]!
      const t2 = TE0[s2 >>> 24]! ^ TE1[(s3 >>> 16) & 0xff]! ^ TE2[(s0 >>> 8) & 0xff]! ^ TE3[s1 & 0xff]! ^ k[o + 2]!
      const t3 = TE0[s3 >>> 24]! ^ TE1[(s0 >>> 16) & 0xff]! ^ TE2[(s1 >>> 8) & 0xff]! ^ TE3[s2 & 0xff]! ^ k[o + 3]!
      s0 = t0
      s1 = t1
      s2 = t2
      s3 = t3
    }
    const o = 4 * this.rounds
    const out = new Uint8Array(16)
    const st = [s0, s1, s2, s3]
    for (let c = 0; c < 4; c++) {
      const v =
        ((SBOX[st[c]! >>> 24]! << 24) | (SBOX[(st[(c + 1) & 3]! >>> 16) & 0xff]! << 16) | (SBOX[(st[(c + 2) & 3]! >>> 8) & 0xff]! << 8) | SBOX[st[(c + 3) & 3]! & 0xff]!) ^ k[o + c]!
      out[4 * c] = v >>> 24
      out[4 * c + 1] = (v >>> 16) & 0xff
      out[4 * c + 2] = (v >>> 8) & 0xff
      out[4 * c + 3] = v & 0xff
    }
    return out
  }

  decrypt(b: Bytes): Bytes {
    const k = this.dk
    let s0 = word(b, 0) ^ k[0]!
    let s1 = word(b, 4) ^ k[1]!
    let s2 = word(b, 8) ^ k[2]!
    let s3 = word(b, 12) ^ k[3]!
    for (let r = 1; r < this.rounds; r++) {
      const o = 4 * r
      const t0 = TD0[s0 >>> 24]! ^ TD1[(s3 >>> 16) & 0xff]! ^ TD2[(s2 >>> 8) & 0xff]! ^ TD3[s1 & 0xff]! ^ k[o]!
      const t1 = TD0[s1 >>> 24]! ^ TD1[(s0 >>> 16) & 0xff]! ^ TD2[(s3 >>> 8) & 0xff]! ^ TD3[s2 & 0xff]! ^ k[o + 1]!
      const t2 = TD0[s2 >>> 24]! ^ TD1[(s1 >>> 16) & 0xff]! ^ TD2[(s0 >>> 8) & 0xff]! ^ TD3[s3 & 0xff]! ^ k[o + 2]!
      const t3 = TD0[s3 >>> 24]! ^ TD1[(s2 >>> 16) & 0xff]! ^ TD2[(s1 >>> 8) & 0xff]! ^ TD3[s0 & 0xff]! ^ k[o + 3]!
      s0 = t0
      s1 = t1
      s2 = t2
      s3 = t3
    }
    const o = 4 * this.rounds
    const out = new Uint8Array(16)
    const st = [s0, s1, s2, s3]
    for (let c = 0; c < 4; c++) {
      const v =
        ((INV[st[c]! >>> 24]! << 24) | (INV[(st[(c + 3) & 3]! >>> 16) & 0xff]! << 16) | (INV[(st[(c + 2) & 3]! >>> 8) & 0xff]! << 8) | INV[st[(c + 1) & 3]! & 0xff]!) ^ k[o + c]!
      out[4 * c] = v >>> 24
      out[4 * c + 1] = (v >>> 16) & 0xff
      out[4 * c + 2] = (v >>> 8) & 0xff
      out[4 * c + 3] = v & 0xff
    }
    return out
  }
}

export const des = (key: Bytes): Block => new DES(key)
export const des3 = (key: Bytes): Block => new TripleDES(key)
export const rc2 = (key: Bytes, bits: number): Block => new RC2(key, bits)
export const aes = (key: Bytes): Block => new AES(key)

/** RC4, for the oldest .p12 files. It is its own inverse. */
export function rc4(key: Bytes, data: Bytes): Bytes {
  const s = Uint8Array.from({ length: 256 }, (_, i) => i)
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 0xff
    ;[s[i], s[j]] = [s[j]!, s[i]!]
  }
  const out = new Uint8Array(data.length)
  for (let n = 0, i = 0, j = 0; n < data.length; n++) {
    i = (i + 1) & 0xff
    j = (j + s[i]!) & 0xff
    ;[s[i], s[j]] = [s[j]!, s[i]!]
    out[n] = data[n]! ^ s[(s[i]! + s[j]!) & 0xff]!
  }
  return out
}

function cbcRaw(c: Block, iv: Bytes, data: Bytes): Bytes {
  const n = c.size
  const out = new Uint8Array(data.length)
  let prev = iv
  for (let i = 0; i < data.length; i += n) {
    const blk = data.subarray(i, i + n)
    const p = c.decrypt(blk)
    for (let k = 0; k < n; k++) out[i + k] = p[k]! ^ prev[k]!
    prev = blk
  }
  return out
}

/** Unwraps a 3DES key with the CMS Triple-DES key wrap (RFC 3217). */
export async function des3Unwrap(kek: Bytes, wrapped: Bytes): Promise<Bytes> {
  if (wrapped.length !== 40) throw new BadPadding('bad wrapped key')
  const c = new TripleDES(kek)
  const temp2 = cbcRaw(c, Uint8Array.from([0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05]), wrapped).reverse()
  const cekicv = cbcRaw(c, temp2.subarray(0, 8), temp2.subarray(8))
  const cek = cekicv.slice(0, 24)
  const icv = new Uint8Array(await crypto.subtle.digest('SHA-1', cek)).subarray(0, 8)
  let d = 0
  for (let k = 0; k < 8; k++) d |= icv[k]! ^ cekicv[24 + k]!
  if (d !== 0) throw new BadPadding('the key did not unwrap')
  return cek
}

/** Thrown when padding is wrong: usually a wrong key or password. */
export class BadPadding extends Error {}

/** CBC decryption with PKCS #7 padding removed. */
export function cbcDecrypt(c: Block, iv: Bytes, data: Bytes): Bytes {
  const n = c.size
  if (data.length === 0 || data.length % n !== 0 || iv.length !== n) throw new BadPadding('bad length')
  const out = new Uint8Array(data.length)
  let prev = iv
  for (let i = 0; i < data.length; i += n) {
    const blk = data.subarray(i, i + n)
    const p = c.decrypt(blk)
    for (let k = 0; k < n; k++) out[i + k] = p[k]! ^ prev[k]!
    prev = blk
  }
  const pad = out[out.length - 1]!
  if (pad < 1 || pad > n) throw new BadPadding('bad padding')
  for (let k = out.length - pad; k < out.length; k++) if (out[k] !== pad) throw new BadPadding('bad padding')
  return out.slice(0, out.length - pad)
}

/** CBC encryption with PKCS #7 padding, for tests and older formats. */
export function cbcEncrypt(c: Block, iv: Bytes, data: Bytes): Bytes {
  const n = c.size
  const pad = n - (data.length % n)
  const buf = new Uint8Array(data.length + pad).fill(pad)
  buf.set(data)
  let prev = iv
  for (let i = 0; i < buf.length; i += n) {
    const x = new Uint8Array(n)
    for (let k = 0; k < n; k++) x[k] = buf[i + k]! ^ prev[k]!
    prev = c.encrypt(x)
    buf.set(prev, i)
  }
  return buf
}

const KW_IV = [0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]

/** AES key wrap (RFC 3394). */
export function aesWrap(kek: Bytes, key: Bytes): Bytes {
  const c = new AES(kek)
  const n = key.length / 8
  const a = Uint8Array.from(KW_IV)
  const r = Array.from({ length: n }, (_, i) => key.slice(8 * i, 8 * i + 8))
  for (let j = 0; j < 6; j++) {
    for (let i = 0; i < n; i++) {
      const b = c.encrypt(Uint8Array.from([...a, ...r[i]!]))
      const t = n * j + i + 1
      a.set(b.subarray(0, 8))
      for (let k = 0; k < 4; k++) a[7 - k]! ^= (t >>> (8 * k)) & 0xff
      r[i] = b.slice(8)
    }
  }
  return Uint8Array.from([...a, ...r.flatMap((x) => [...x])])
}

/** AES key unwrap (RFC 3394); throws BadPadding when the check fails. */
export function aesUnwrap(kek: Bytes, wrapped: Bytes): Bytes {
  if (wrapped.length < 24 || wrapped.length % 8 !== 0) throw new BadPadding('bad wrapped key')
  const c = new AES(kek)
  const n = wrapped.length / 8 - 1
  const a = wrapped.slice(0, 8)
  const r = Array.from({ length: n }, (_, i) => wrapped.slice(8 * (i + 1), 8 * (i + 2)))
  for (let j = 5; j >= 0; j--) {
    for (let i = n - 1; i >= 0; i--) {
      const t = n * j + i + 1
      for (let k = 0; k < 4; k++) a[7 - k]! ^= (t >>> (8 * k)) & 0xff
      const b = c.decrypt(Uint8Array.from([...a, ...r[i]!]))
      a.set(b.subarray(0, 8))
      r[i] = b.slice(8)
    }
  }
  let d = 0
  for (let k = 0; k < 8; k++) d |= a[k]! ^ 0xa6
  if (d !== 0) throw new BadPadding('the key did not unwrap')
  return Uint8Array.from(r.flatMap((x) => [...x]))
}
