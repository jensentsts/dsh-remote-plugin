/**
 * Throughput benchmark for the peer filesystem ops over a real link.
 *
 * Measures what the current protocol actually delivers for big files: one
 * `fs.write` for a whole blob, then `fs.read` windows back. The numbers are the
 * baseline the optimized path (chunked + pipelined + compressed) has to beat,
 * and the same script is re-run after the change.
 *
 * Usage (from the harness checkout so tsx resolves):
 *   node tools/bench-fs.mjs <host> <port> <remoteDir>
 */

import { createHash, randomBytes } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { LinkClient } from '../lib/link.js'

const [host, portArg, remoteDir] = process.argv.slice(2)
if (host === undefined || portArg === undefined || remoteDir === undefined) {
  console.error('usage: node tools/bench-fs.mjs <host> <port> <remoteDir>')
  process.exit(2)
}
const home = process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? '', '.dsh')
const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 600_000,
}), message => console.log(message), 'bench')

const now = () => Number(process.hrtime.bigint() / 1000n) / 1000
const rate = (bytes, ms) => `${(bytes / 1024 / 1024).toFixed(2)} MiB in ${ms.toFixed(0)} ms = ${(bytes / 1024 / 1024 / (ms / 1000)).toFixed(2)} MiB/s`

async function timed(label, fn) {
  const started = now()
  const value = await fn()
  const ms = now() - started
  console.log(`${label.padEnd(34)} ${rate(value, ms)}`)
  return { value: value, ms: ms }
}

// Payloads: incompressible, compressible, and text-ish.
const size = Number(process.env.BENCH_SIZE ?? 8 * 1024 * 1024)
const payloads = {
  random: randomBytes(size),
  zeros: Buffer.alloc(size),
  text: Buffer.from('the quick brown fox jumps over the lazy dog 0123456789\n'.repeat(Math.ceil(size / 56)).slice(0, size), 'utf8'),
  // Random hex lines compress about 2x, which is what real source/binary-ish
  // text does — the headline "realistic" case for the fast path comparison.
  realistic: Buffer.from(Array.from({ length: Math.ceil(size / 40) }, (_, i) =>
    `${String(i).padStart(6, '0')} ${randomBytes(16).toString('hex')}\n`).join('').slice(0, size), 'utf8'),
}
const only = process.env.BENCH_ONLY
const dir = mkdtempSync(join(tmpdir(), 'dshr-bench-'))

for (const [name, data] of Object.entries(payloads)) {
  if (only !== undefined && only !== '' && name !== only) continue
  const sha = createHash('sha256').update(data).digest('hex')
  const remotePath = `${remoteDir.replace(/\/+$/u, '')}/bench-${name}.bin`

  // Baseline write: one frame carrying the whole base64 blob.
  const b64 = data.toString('base64')
  const write = await timed(`write ${name} (${(data.length / 1024 / 1024).toFixed(1)} MiB)`, async () => {
    const reply = await link.request('fs.write', { path: remotePath, dataB64: b64, createOnly: false }, 600_000)
    return reply.written
  })
  if (write.value !== data.length) console.log('  WARNING: written size mismatch', write.value, data.length)

  // Baseline read: windowed fs.read calls, sequential, one round trip each.
  const window = Number(process.env.BENCH_WINDOW ?? 256 * 1024)
  const chunks = []
  await timed(`read ${name} (${window / 1024} KiB windows)`, async () => {
    let offset = 0
    while (offset < data.length) {
      const reply = await link.request('fs.read', { path: remotePath, offset, length: window }, 600_000)
      const chunk = Buffer.from(String(reply.dataB64 ?? ''), 'base64')
      if (chunk.length === 0) break
      chunks.push(chunk)
      offset += chunk.length
    }
    return offset
  })
  const got = createHash('sha256').update(Buffer.concat(chunks)).digest('hex')
  console.log(`  sha256 match: ${got === sha}`)
  const local = join(dir, `bench-${name}.bin`)
  writeFileSync(local, data)
}

const ping = await timed('ping round trip (bytes carried)', async () => {
  const started = now()
  await link.request('ping', {}, 30_000)
  return now() - started
})
console.log(`  ping RTT ~${ping.ms.toFixed(1)} ms`)
link.close()
