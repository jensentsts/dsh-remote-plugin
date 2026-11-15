/**
 * Fast-path throughput benchmark over a real link.
 *
 * Same payload shapes as `bench-fs.mjs` (the baseline) but through the chunked,
 * per-block-compressed `fs.put.*` / `fs.get` path, so the two runs are directly
 * comparable. Needs a peer that advertises the transfer ops (r19+).
 *
 * Usage (from the harness checkout so tsx resolves):
 *   node --import tsx/esm tools/bench-transfer.mjs <host> <port> <remoteDir>
 */

import { createHash, randomBytes } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { LinkClient } from '../lib/link.js'
import { downloadToBuffer, downloadToFile, uploadBuffer, uploadFile } from '../src/transfer-client.ts'

const [host, portArg, remoteDir] = process.argv.slice(2)
if (host === undefined || portArg === undefined || remoteDir === undefined) {
  console.error('usage: node --import tsx/esm tools/bench-transfer.mjs <host> <port> <remoteDir>')
  process.exit(2)
}
const home = process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? '', '.dsh')
const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 600_000,
}), m => console.log(m), 'bench-transfer')
const request = (op, args, timeoutMs) => link.request(op, args, timeoutMs)

const now = () => Number(process.hrtime.bigint() / 1000n) / 1000
const size = Number(process.env.BENCH_SIZE ?? 8 * 1024 * 1024)
const dir = remoteDir.replace(/\/+$/u, '')
const tmp = mkdtempSync(join(tmpdir(), 'dshr-bench-fast-'))

// Same three shapes as the baseline, plus a "realistic source file" whose gzip
// ratio is about 2x instead of the baseline's unrealistically repetitive text.
const payloads = {
  random: randomBytes(size),
  zeros: Buffer.alloc(size),
  text: Buffer.from('the quick brown fox jumps over the lazy dog 0123456789\n'.repeat(Math.ceil(size / 56)).slice(0, size), 'utf8'),
  realistic: Buffer.from(Array.from({ length: Math.ceil(size / 40) }, (_, i) =>
    `${String(i).padStart(6, '0')} ${randomBytes(16).toString('hex')}\n`).join('').slice(0, size), 'utf8'),
}

const report = []
const only = process.env.BENCH_ONLY
for (const [name, data] of Object.entries(payloads)) {
  if (only !== undefined && only !== '' && name !== only) continue
  const remotePath = `${dir}/fast-${name}.bin`
  const localPath = join(tmp, `${name}.bin`)
  writeFileSync(localPath, data)
  const sha = createHash('sha256').update(data).digest('hex')
  const mib = data.length / 1024 / 1024
  const rate = ms => Number((mib / (Math.max(ms, 1) / 1000)).toFixed(2))

  const up = await uploadBuffer(request, remotePath, data)
  let started = now()
  const down = await downloadToBuffer(request, remotePath)
  const downMs = now() - started
  const upFile = await uploadFile(request, localPath, `${remotePath}.file`)
  const localOut = join(tmp, `${name}.out.bin`)
  started = now()
  const downFile = await downloadToFile(request, remotePath, localOut)
  const downFileMs = now() - started

  const row = {
    name,
    sizeMiB: Number(mib.toFixed(2)),
    uploadMiBs: rate(up.durationMs),
    downloadMiBs: rate(downMs),
    uploadFileMiBs: rate(upFile.durationMs),
    downloadFileMiBs: rate(downFileMs),
    shaOk: up.sha256 === sha && down.sha256 === sha && upFile.sha256 === sha && downFile.sha256 === sha,
  }
  report.push(row)
  console.log(JSON.stringify(row))
}

console.log('\nsummary (MiB/s)')
for (const row of report) {
  console.log(`${row.name.padEnd(10)} ${String(row.sizeMiB).padStart(5)} MiB  up=${String(row.uploadMiBs).padStart(5)}  down=${String(row.downloadMiBs).padStart(5)}  upFile=${String(row.uploadFileMiBs).padStart(5)}  downFile=${String(row.downloadFileMiBs).padStart(5)}  sha=${row.shaOk ? 'ok' : 'MISMATCH'}`)
}
link.close()
