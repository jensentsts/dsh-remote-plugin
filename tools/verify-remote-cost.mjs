/**
 * End-to-end check of the remote-cost pipeline against a REAL peer turn.
 *
 * Takes a remote session that already has a live handle (drive one turn with
 * `remote_agent_prompt` first), asks the peer for its per-call usage through the
 * new `usage.read` op, runs the exact client-side store code over it, and leaves
 * an `external_usage.json` snapshot in a temp dir. That snapshot is then fed to
 * the installed cost-meter's own parser by `verify-cost-contract.mjs <file>`.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm tools/verify-remote-cost.mjs <host> <port> <sessionId>
 */

import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { LinkClient } from '../src/link.ts'
import { sanitizeSample, RemoteCostStore } from '../src/cost-report.ts'

const [host, portArg, sessionId] = process.argv.slice(2)
if (host === undefined || portArg === undefined || sessionId === undefined) {
  console.error('usage: node --import tsx/esm tools/verify-remote-cost.mjs <host> <port> <sessionId>')
  process.exit(2)
}

const home = process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? '', '.dsh')
const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 120_000,
}), message => console.log(message), 'verify-remote-cost')

const reply = await link.request('usage.read', { sessionId, fromSeq: 0 }, 120_000)
console.log('usage.read:', JSON.stringify({
  available: reply.available,
  reason: reply.reason,
  seq: reply.seq,
  fromSeq: reply.fromSeq,
  nextSeq: reply.nextSeq,
  records: Array.isArray(reply.records) ? reply.records.length : -1,
}))
if (reply.available !== true) {
  link.close()
  console.error('the peer has no live handle for that session; drive one turn first')
  process.exit(1)
}

const samples = []
let cursor = Number(reply.fromSeq ?? 0)
for (const raw of Array.isArray(reply.records) ? reply.records : []) {
  const sample = sanitizeSample(raw, sessionId)
  if (sample !== null) samples.push(sample)
  const seq = Number(raw?.seq)
  if (Number.isFinite(seq) && seq > cursor) cursor = seq
}
const nextSeq = Number.isFinite(Number(reply.nextSeq)) ? Number(reply.nextSeq) : cursor
link.close()

const dir = mkdtempSync(join(tmpdir(), 'dshr-remote-cost-'))
const store = new RemoteCostStore({
  storeFile: join(dir, 'client-cost.json'),
  snapshotFile: join(dir, 'external_usage.json'),
  sourceName: 'remote/verify',
  sourcePrefix: 'remote/',
  log: message => console.log('log:', message),
})
store.load()
await store.record(sessionId, samples, nextSeq)
const summary = store.summary()

const tokens = samples.reduce((sum, record) => ({
  input: sum.input + record.input,
  output: sum.output + record.output,
  cached: sum.cached + record.cached,
  cacheWrite: sum.cacheWrite ?? 0,
  reasoning: sum.reasoning ?? 0,
}), { input: 0, output: 0, cached: 0, cacheWrite: 0, reasoning: 0 })
console.log('sanitized calls:', samples.length, 'tokens:', JSON.stringify(tokens))
console.log('store summary:', JSON.stringify(summary))
console.log('snapshot:', join(dir, 'external_usage.json'))
console.log('store:', join(dir, 'client-cost.json'))
console.log(`next: node tools/verify-cost-contract.mjs "${join(dir, 'external_usage.json')}"`)
