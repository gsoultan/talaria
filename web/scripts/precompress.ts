// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Writes .br and .gz siblings for compressible build output, so the Go server
// can send precompressed files without spending CPU per request.
import { readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { brotliCompressSync, constants, gzipSync } from 'node:zlib'

const root = process.argv[2] ?? 'dist'
const compressible = /\.(js|mjs|css|html|svg|json|webmanifest|txt|wasm)$/

async function walk(dir: string): Promise<string[]> {
  const out: string[] = []
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name)
    if (e.isDirectory()) out.push(...(await walk(p)))
    else if (compressible.test(e.name)) out.push(p)
  }
  return out
}

let saved = 0
for (const file of await walk(root)) {
  const buf = await readFile(file)
  if ((await stat(file)).size < 1024) continue
  const br = brotliCompressSync(buf, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } })
  const gz = gzipSync(buf, { level: 9 })
  await writeFile(`${file}.br`, br)
  await writeFile(`${file}.gz`, gz)
  saved += buf.length - br.length
}
console.log(`precompressed ${root}: brotli saves ${(saved / 1024).toFixed(0)} KiB`)
