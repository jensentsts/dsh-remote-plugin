/**
 * Offline test for `LinkClient`'s multiplexing.
 *
 * The bug this pins down: the old client did `send()` then `recv()` on a SHARED
 * session. Two concurrent callers therefore read from one `ByteReader` and both
 * advanced the single AES-GCM receive counter, so the stream failed
 * authentication and the peer dropped the link — the "peer closed the link"
 * failures. It is not a subtle race: it is guaranteed corruption.
 *
 * So this runs the real protocol over a real loopback socket, against a peer
 * that deliberately answers OUT OF ORDER, and asserts that every caller is
 * answered by its own request id, that concurrency is genuinely concurrent, and
 * that a dead connection is re-dialled rather than surfaced.
 *
 *   node test/link-concurrency.test.mjs
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair, privateToPem, publicToPem, serverHandshake } from '../lib/protocol.js'
import { LinkClient } from '../lib/link.js'

let passed = 0
let failed = 0

/** Run one named check, reporting rather than throwing so every case is seen. */
async function check(name, run) {
  try {
    await run()
    passed += 1
    console.log(`  ok   ${name}`)
  } catch (error) {
    failed += 1
    console.log(`  FAIL ${name}\n       ${error.message.split('\n')[0]}`)
  }
}

const serverKeys = generateKeyPair()
const clientKeys = generateKeyPair()
const scratch = mkdtempSync(join(tmpdir(), 'dsh-remote-link-'))

/** Connections the fake peer has accepted, so a re-dial is observable. */
let connections = 0

/** Requests the peer deliberately left open, awaiting an answer frame. */
const heldRequests = new Map()
/** All eight barrier requests must arrive before any response is released. */
const concurrentBarrier = []

/**
 * The fake peer: real handshake, real framing, deliberately unhelpful ordering.
 * @param socket - one accepted connection.
 */
function serve(socket) {
  connections += 1
  /** Reply later, tolerating a socket this test destroys on purpose. */
  const later = (session, payload, delay) => {
    setTimeout(() => { session.send(payload).catch(() => {}) }, delay)
  }
  void (async () => {
    const session = await serverHandshake(socket, serverKeys.privateKey, clientKeys.publicKey)
    for (;;) {
      const request = await session.recv()
      if (request === null) break
      // A frame with a `kind` is PEER-INITIATED: here, the answer coming back.
      if (request.kind === 'answer') {
        const held = heldRequests.get(String(request.qid))
        if (held !== undefined) {
          heldRequests.delete(String(request.qid))
          await session.send({ id: held.id, ok: true, reply: `answered:${JSON.stringify(request.answer)}` })
        }
        continue
      }
      const id = Number(request.id)
      const op = String(request.op)
      if (op === 'fail') {
        void session.send({ id, ok: false, error: 'peer said no', code: 'FS_STALE_VERSION' })
        continue
      }
      if (op === 'ask') {
        // Push the question, then hold the request open until the answer arrives —
        // exactly the shape of a relayed `ask_user_question`.
        const qid = `q-${id}`
        heldRequests.set(qid, { id })
        await session.send({
          kind: 'ask',
          qid,
          sessionId: request.marker,
          questions: [{ id: 'mode', question: 'pick one', options: [{ label: 'a' }, { label: 'b' }] }],
        })
        continue
      }
      if (op === 'bye') {
        // Answer, then hang up: the NEXT request has to re-dial.
        await session.send({ id, ok: true, echo: request.marker })
        setTimeout(() => { socket.destroy() }, 20)
        continue
      }
      if (op === 'barrier') {
        concurrentBarrier.push({ session, id })
        if (concurrentBarrier.length === 8) {
          const group = concurrentBarrier.splice(0)
          for (const held of group.reverse()) await held.session.send({ id: held.id, ok: true })
        }
        continue
      }
      // Reverse the arrival order: the later the id, the sooner its reply. A
      // client that pairs replies up by arrival order cannot pass this.
      later(session, { id, ok: true, echo: request.marker }, op === 'slow' ? 120 : Math.max(0, 45 - (id % 45)))
    }
  })().catch(() => {
    // A legacy responder rejects DSHP1 before authentication. Real listeners
    // close that connection; otherwise the modern client's legacy fallback has
    // no EOF to observe and waits the entire handshake timeout.
    socket.destroy()
  })
}

const net = createServer(serve)
await new Promise(resolve => net.listen(0, '127.0.0.1', resolve))
const port = net.address().port

const notices = []
const link = new LinkClient(
  () => ({
    host: '127.0.0.1',
    port,
    privateKey: privateToPem(clientKeys.privateKey),
    peerPublicKey: publicToPem(serverKeys.publicKey),
    autoGenerateKey: false,
    // Scratch paths on purpose: a parse failure must never touch the real
    // ${DSH_HOME}/dsh-remote key material.
    privateKeyFile: join(scratch, 'client.key'),
    peerPublicKeyFile: join(scratch, 'server.pub'),
    timeoutMs: 5000,
    allowLegacyHandshake: true, // This fixture intentionally implements the old pre-selector server.
  }),
  message => { notices.push(message) },
  'test-link',
)

console.log('LinkClient multiplexing')

await check('concurrent requests are each answered by their own id', async () => {
  const replies = await Promise.all(
    Array.from({ length: 12 }, (_, index) => link.request('ping', { marker: `m${index}` })),
  )
  assert.deepEqual(
    replies.map(reply => reply.echo),
    Array.from({ length: 12 }, (_, index) => `m${index}`),
    'every caller must receive its own reply, whatever order they arrive in',
  )
})

await check('concurrency is real, not serialized', async () => {
  // A serialized client deadlocks at the first request because the peer waits
  // for all eight. This proves overlap without a flaky wall-clock threshold.
  await Promise.all(Array.from({ length: 8 }, () => link.request('barrier')))
  assert.equal(concurrentBarrier.length, 0, 'all eight arrived before any reply was sent')
})

await check('nothing is left parked once every call settles', () => {
  assert.equal(link.inFlight, 0)
})

await check('a peer failure rejects with its message and typed code', async () => {
  await assert.rejects(
    () => link.request('fail'),
    (error) => error.message === 'peer said no' && error.peerCode === 'FS_STALE_VERSION',
  )
  assert.equal(link.inFlight, 0, 'a failed request must not leave its waiter behind')
})

await check('a per-request timeout does not poison the session', async () => {
  await assert.rejects(() => link.request('slow', {}, 1), /timed out after 1 ms/u)
  // The reply for the timed-out id still arrives later and must be discarded, not
  // handed to the next caller.
  const reply = await link.request('ping', { marker: 'after-timeout' })
  assert.equal(reply.echo, 'after-timeout')
})

await check('a dead connection is re-dialled rather than surfaced', async () => {
  const before = connections
  const reply = await link.request('bye', { marker: 'first' })
  assert.equal(reply.echo, 'first')
  await new Promise(resolve => setTimeout(resolve, 60))
  const after = await link.request('ping', { marker: 'second' })
  assert.equal(after.echo, 'second')
  assert.ok(connections > before, `expected a fresh connection, saw ${before} -> ${connections}`)
})

await check('a peer-initiated question reaches onEvent, and its answer completes the parked request', async () => {
  const events = []
  link.onEvent(frame => events.push(frame))
  // This is a relayed `ask_user_question`: the peer pushes the question while the
  // request that triggered it stays parked, and only the answer completes it.
  const parked = link.request('ask', { marker: 'session-under-test' })
  const deadline = Date.now() + 2000
  while (events.length === 0 && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.equal(events.length, 1, 'the peer-initiated frame must reach onEvent')
  const frame = events[0]
  assert.equal(frame.kind, 'ask')
  assert.equal(frame.sessionId, 'session-under-test')
  assert.equal(frame.questions[0].id, 'mode')

  await link.notify({
    kind: 'answer',
    qid: frame.qid,
    answer: { answers: [{ id: 'mode', selected: ['b'] }] },
  })
  const reply = await parked
  assert.match(String(reply.reply), /^answered:/u, 'the parked request must resume with the answer applied')
  assert.match(String(reply.reply), /"selected":\["b"\]/u)
})

link.close()
net.close()
console.log(`\n${passed} passed, ${failed} failed`)
if (notices.length > 0) console.log(`(${notices.length} link notice(s): ${notices[0]})`)
process.exit(failed === 0 ? 0 : 1)
