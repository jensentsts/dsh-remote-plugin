/**
 * Diagnostic, not a test: does the OLD request pattern actually corrupt the
 * stream?
 *
 * The previous `LinkClient.request()` did `send()` then `recv()` on a shared
 * session. Two callers doing that concurrently share one `ByteReader` and one
 * AES-GCM receive counter, so the diagnosis was that concurrency corrupts the
 * link — the "peer closed the link" failures. This file replays that pattern
 * against a real peer to see whether the diagnosis holds, because a fix built on
 * a wrong root cause is worthless.
 *
 * It always exits 0: it reports counts, it does not assert.
 *
 *   node test/old-pattern-repro.mjs
 */
import { createServer } from 'node:net'
import { generateKeyPair, privateToPem, publicToPem, clientHandshake, serverHandshake } from '../lib/protocol.js'

const serverKeys = generateKeyPair()
const clientKeys = generateKeyPair()

const net = createServer(socket => {
  void (async () => {
    const session = await serverHandshake(socket, serverKeys.privateKey, clientKeys.publicKey)
    for (;;) {
      const request = await session.recv()
      if (request === null) break
      const payload = { id: request.id, ok: true, seq: request.marker }
      // Jittered replies so arrival order genuinely interleaves.
      setTimeout(() => { session.send(payload).catch(() => {}) }, Math.floor(Math.random() * 25))
    }
  })().catch(() => {})
})
await new Promise(resolve => net.listen(0, '127.0.0.1', resolve))

const { connect } = await import('node:net')
const socket = connect({ host: '127.0.0.1', port: net.address().port })
await new Promise(resolve => socket.once('connect', resolve))
socket.setNoDelay(true)
socket.setTimeout(0)
const session = await clientHandshake(socket, clientKeys.privateKey, serverKeys.publicKey)

const CONCURRENCY = 4
const ROUNDS = 12
let good = 0
let bad = 0
const reasons = new Map()

for (let round = 0; round < ROUNDS; round += 1) {
  const results = await Promise.allSettled(
    Array.from({ length: CONCURRENCY }, async (_, index) => {
      // THE OLD PATTERN, verbatim.
      await session.send({ id: index, op: 'ping', marker: `r${round}-${index}` })
      const reply = await session.recv(2000)
      if (reply === null) throw new Error('peer closed the link')
      if (reply.seq !== `r${round}-${index}`) throw new Error(`wrong reply: got ${String(reply.seq)}`)
      return true
    }),
  )
  for (const result of results) {
    if (result.status === 'fulfilled') { good += 1; continue }
    bad += 1
    const key = String(result.reason?.message ?? result.reason).slice(0, 70)
    reasons.set(key, (reasons.get(key) ?? 0) + 1)
  }
}

console.log(`old pattern, ${ROUNDS} rounds x ${CONCURRENCY} concurrent exchanges`)
console.log(`  clean : ${good}`)
console.log(`  broken: ${bad}`)
for (const [reason, count] of reasons) console.log(`    ${count}x ${reason}`)
net.close()
socket.destroy()
