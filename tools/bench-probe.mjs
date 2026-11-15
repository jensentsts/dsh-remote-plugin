/**
 * Probe where the tunnel budget actually goes, without touching the model
 * context: `exec` (plain text JSON) vs `fs.write` (base64 JSON), raw vs
 * pre-gzipped payloads. Used to choose what the fast path must optimize.
 *
 * Usage: node tools/bench-probe.mjs <host> <port> <remoteDir>
 */

import { gzipSync } from 'node:zlib'
import { join } from 'node:path'
import { LinkClient } from '../lib/link.js'

const [host, portArg, remoteDir] = process.argv.slice(2)
const home = process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? '', '.dsh')
const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 600_000,
}), m => console.log(m), 'probe')

const now = () => Number(process.hrtime.bigint() / 1000n) / 1000
const run = async (label, wireBytes, fn) => {
  const t = now()
  const got = await fn()
  const ms = now() - t
  console.log(`${label.padEnd(44)} wire=${(wireBytes / 1024 / 1024).toFixed(2)} MiB  ${ms.toFixed(0)} ms  = ${(wireBytes / 1024 / 1024 / (ms / 1000)).toFixed(2)} MiB/s  (ret ${got})`)
}

const size = 8 * 1024 * 1024
const text = Buffer.from('the quick brown fox jumps over the lazy dog 0123456789\n'.repeat(size / 56 + 1).slice(0, size), 'utf8')
const gz = gzipSync(text, { level: 6 })
console.log(`text=${(text.length / 1e6).toFixed(2)} MB  gzip=${(gz.length / 1e6).toFixed(2)} MB  ratio=${(text.length / gz.length).toFixed(2)}x`)

const dir = remoteDir.replace(/\/+$/u, '')

// exec: remote->local PLAIN text inside JSON (no base64) — the pure network path.
await run('exec output 8 MiB text (plain JSON)', size, async () => {
  const reply = await link.request('exec', {
    cmd: `$s=[string]::new([char]120, ${size}); [Console]::Out.Write($s)`,
    shell: 'powershell',
  }, 600_000)
  return String(reply.stdout ?? '').length
})

// fs.write raw text: local->remote base64 JSON.
const b64Raw = text.toString('base64')
await run('fs.write raw 8 MiB (base64 JSON)', b64Raw.length, async () => {
  const reply = await link.request('fs.write', { path: `${dir}/probe-raw.bin`, dataB64: b64Raw }, 600_000)
  return reply.size
})

// fs.write pre-gzipped text: same op, 1/8 the payload.
const b64gz = gz.toString('base64')
await run('fs.write gzip 8 MiB text (base64 JSON)', b64gz.length, async () => {
  const reply = await link.request('fs.write', { path: `${dir}/probe-gz.bin`, dataB64: b64gz }, 600_000)
  return reply.size
})

// fs.read of the gz file back: remote->local.
await run('fs.read 8 MiB (256K windows)', size, async () => {
  let off = 0
  while (off < text.length) {
    const reply = await link.request('fs.read', { path: `${dir}/probe-raw.bin`, offset: off, length: 256 * 1024 }, 600_000)
    const got = Buffer.from(String(reply.dataB64 ?? ''), 'base64').length
    if (!got) break
    off += got
  }
  return off
})

link.close()
