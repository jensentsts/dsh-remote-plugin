/**
 * Where should the chunked fast path switch on?
 *
 * Measures per-size latency for the legacy single-frame `fs.write`/`fs.read`
 * path and for the chunked `fs.put.*`/`fs.get` path with a compressible
 * ("realistic source file") payload. The fast path costs two extra round trips
 * (begin/commit) and a hash round trip on download, so below some size the
 * legacy path wins; this prints both so the threshold is a measured choice.
 *
 * Usage (from the harness checkout so tsx resolves):
 *   node --import tsx/esm tools/bench-sizes.mjs <host> <port> <remoteDir>
 */

import { randomBytes } from 'node:crypto'
import { join } from 'node:path'

import { LinkClient } from '../lib/link.js'
import { downloadToBuffer, uploadBuffer } from '../src/transfer-client.ts'

const [host, portArg, remoteDir] = process.argv.slice(2)
const home = process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? '', '.dsh')
const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 600_000,
}), m => console.log(m), 'bench-sizes')
const request = (op, args, timeoutMs) => link.request(op, args, timeoutMs)
const now = () => Number(process.hrtime.bigint() / 1000n) / 1000
const dir = remoteDir.replace(/\/+$/u, '')

const realistic = size => Buffer.from(Array.from({ length: Math.ceil(size / 40) }, (_, i) =>
  `${String(i).padStart(6, '0')} ${randomBytes(16).toString('hex')}\n`).join('').slice(0, size), 'utf8')

const rows = []
for (const size of [64 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024, 4 * 1024 * 1024]) {
  const data = realistic(size)
  const remotePath = `${dir}/size-${size}.bin`
  const b64 = data.toString('base64')

  let started = now()
  await link.request('fs.write', { path: `${remotePath}.legacy`, dataB64: b64 }, 600_000)
  const legacyWriteMs = now() - started

  started = now()
  await uploadBuffer(request, `${remotePath}.fast`, data)
  const fastWriteMs = now() - started

  const window = 256 * 1024
  started = now()
  let offset = 0
  while (offset < data.length) {
    const reply = await link.request('fs.read', { path: `${remotePath}.legacy`, offset, length: window }, 600_000)
    const got = Buffer.from(String(reply.dataB64 ?? ''), 'base64').length
    if (!got) break
    offset += got
  }
  const legacyReadMs = now() - started

  started = now()
  await downloadToBuffer(request, `${remotePath}.fast`)
  const fastReadMs = now() - started

  rows.push({ size, legacyWriteMs, fastWriteMs, legacyReadMs, fastReadMs })
}

const fmt = ms => `${ms.toFixed(0)} ms`
console.log('\nsize      legacy write  fast write   legacy read  fast read')
for (const row of rows) {
  console.log(`${String(row.size / 1024).padStart(6)} KiB  ${fmt(row.legacyWriteMs).padStart(10)}  ${fmt(row.fastWriteMs).padStart(10)}  ${fmt(row.legacyReadMs).padStart(11)}  ${fmt(row.fastReadMs).padStart(9)}`)
}
link.close()
