/** In-memory transport tests only: no profile, key files, or network dials. */
import assert from 'node:assert/strict'
import { RelaySocket, RELAY_CHUNK_BYTES, RELAY_RECEIVE_BYTES, decodeRelayData } from '../src/relay-socket.ts'
import { clientHandshake, serverHandshake, generateKeyPair, HandshakeError } from '../src/protocol.ts'

let checks = 0
async function check(name: string, body: () => unknown | Promise<unknown>): Promise<void> {
  await body(); checks += 1; console.log(`ok ${name}`)
}
const tick = (): Promise<void> => new Promise(resolve => setImmediate(resolve))
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
function write(socket: RelaySocket, bytes: Buffer): Promise<void> {
  return new Promise((resolve, reject) => { socket.write(bytes, error => error == null ? resolve() : reject(error)) })
}
function pair(): { left: RelaySocket; right: RelaySocket } {
  let left!: RelaySocket, right!: RelaySocket
  function channel(peer: () => RelaySocket) {
    return { async request(op: string, args: Record<string, unknown>) {
      if (op === 'relay.write') {
        // Real hub RPCs yield to the readable stream between acknowledgements.
        await tick()
        if (!peer().receive(args.seq, args.dataB64)) throw new Error('relay fixture receiver closed')
        return { written: true }
      }
      if (op === 'relay.close') { peer().remoteClosed(); return { closed: true } }
      throw new Error(`unexpected fixture op ${op}`)
    } }
  }
  left = new RelaySocket('left', channel(() => right))
  right = new RelaySocket('right', channel(() => left))
  return { left, right }
}

await check('48 KiB writes use strict increasing sequences and await every acknowledgement', async () => {
  const calls: Array<{ op: string; args: Record<string, unknown> }> = []
  const gates: Array<ReturnType<typeof deferred<Record<string, unknown>>>> = []
  const socket = new RelaySocket('ordered', { request(op, args) {
    calls.push({ op, args })
    if (op === 'relay.close') return Promise.resolve({ closed: true })
    const gate = deferred<Record<string, unknown>>(); gates.push(gate); return gate.promise
  } })
  try {
    const bytes = Buffer.alloc(RELAY_CHUNK_BYTES * 2 + 17, 0xa3)
    let completed = false
    const result = write(socket, bytes).then(() => { completed = true })
    assert.equal(calls.length, 1)
    assert.equal(completed, false)
    assert.equal(socket.writableNeedDrain, true)
    gates[0]!.resolve({ written: true }); await tick()
    assert.equal(calls.length, 2)
    assert.equal(completed, false)
    gates[1]!.resolve({ written: true }); await tick()
    assert.equal(calls.length, 3)
    gates[2]!.resolve({ written: true }); await result
    assert.deepEqual(calls.map(call => call.args.seq), [1, 2, 3])
    const decoded = calls.map(call => decodeRelayData(call.args.dataB64))
    assert.deepEqual(decoded.map(block => block.length), [RELAY_CHUNK_BYTES, RELAY_CHUNK_BYTES, 17])
    assert.deepEqual(Buffer.concat(decoded), bytes)
    assert.equal(socket.bytesWritten, bytes.length)
  } finally { socket.destroy(); await tick() }
})

await check('malformed sequence and non-canonical base64 close exactly their tunnel', async () => {
  const vectors: Array<[unknown, unknown]> = [
    [0, 'YQ=='], [2, 'YQ=='], [1.5, 'YQ=='], ['1', 'YQ=='], [Infinity, 'YQ=='],
    [1, 'YQ'], [1, 'YQ==\n'], [1, 'Y Q=='], [1, 'YR=='], [1, '===='], [1, 'YQ-_'],
    [1, Buffer.from('a')], [1, Buffer.alloc(RELAY_CHUNK_BYTES + 1).toString('base64')],
  ]
  for (const [seq, value] of vectors) {
    let closed = 0
    const socket = new RelaySocket('bad', { async request(op) { if (op === 'relay.close') closed++; return { closed: true } } })
    assert.equal(socket.receive(seq, value), false)
    assert.equal(socket.destroyed, true)
    await tick()
    assert.equal(closed, 1)
    assert.equal(socket.readableLength, 0)
  }
  const socket = new RelaySocket('repeat', { async request() { return { closed: true } } })
  assert.equal(socket.receive(1, 'YQ=='), true)
  assert.equal(socket.receive(1, 'YQ=='), false)
  assert.equal(socket.destroyed, true)
  await tick()
})

await check('slow-reader receive memory is capped at 1 MiB including stream backlog', async () => {
  const socket = new RelaySocket('slow', { async request() { return { closed: true } } })
  let seq = 1
  let bytes = 0
  while (bytes < RELAY_RECEIVE_BYTES) {
    const count = Math.min(RELAY_CHUNK_BYTES, RELAY_RECEIVE_BYTES - bytes)
    assert.equal(socket.receive(seq++, Buffer.alloc(count, 1).toString('base64')), true)
    bytes += count
  }
  assert.equal(socket.readableLength, RELAY_RECEIVE_BYTES)
  assert.equal(socket.receive(seq, 'AA=='), false)
  assert.equal(socket.destroyed, true)
  assert.ok(socket.readableLength <= RELAY_RECEIVE_BYTES)
  await tick()
})

await check('read consumption releases buffer credit; empty canonical data keeps strict sequence', async () => {
  const socket = new RelaySocket('consume', { async request() { return { closed: true } } }, { maxReceiveBytes: 16 })
  try {
    assert.equal(socket.receive(1, ''), true)
    assert.equal(socket.receive(2, Buffer.alloc(16, 9).toString('base64')), true)
    assert.equal(socket.read(8).length, 8)
    assert.equal(socket.receive(3, Buffer.alloc(8, 4).toString('base64')), true)
    assert.equal(socket.readableLength, 16)
  } finally { socket.destroy(); await tick() }
})

await check('destroy cancels a stalled write, sends one close and clears idle timeout', async () => {
  let closes = 0
  let timeouts = 0
  const waiting = deferred<Record<string, unknown>>()
  const socket = new RelaySocket('cancel', { request(op) {
    if (op === 'relay.close') { closes++; return Promise.resolve({ closed: true }) }
    return waiting.promise
  } })
  socket.setTimeout(10, () => { timeouts++ }).setNoDelay(true).setKeepAlive(true).unref().ref()
  const result = write(socket, Buffer.alloc(1))
  socket.destroy()
  await assert.rejects(result, /closed|destroy/i)
  waiting.resolve({ written: true })
  await new Promise<void>(resolve => setTimeout(resolve, 20))
  assert.equal(timeouts, 0)
  assert.equal(closes, 1)
  assert.equal(socket.readyState, 'closed')
})

await check('remote close emits no echo and failed acknowledgements fail the write', async () => {
  let calls = 0
  const socket = new RelaySocket('remote', { async request() { calls++; return { written: true } } })
  socket.remoteClosed()
  await tick()
  assert.equal(calls, 0)
  const bad = new RelaySocket('ack', { async request(op) { return op === 'relay.close' ? { closed: true } : { written: false } } })
  await assert.rejects(write(bad, Buffer.from('abc')), /acknowledgement/)
  await tick()
  assert.equal(bad.destroyed, true)
})

await check('existing mutually authenticated DSHR2 works over the opaque virtual socket', async () => {
  const { left, right } = pair()
  const client = generateKeyPair(), server = generateKeyPair()
  const [initiator, responder] = await Promise.all([
    clientHandshake(left.asSocket(), client.privateKey, server.publicKey),
    serverHandshake(right.asSocket(), server.privateKey, client.publicKey),
  ])
  try {
    const content = 'a'.repeat(1024 * 1024)
    const [received] = await Promise.all([responder.recv(), initiator.send({ content })])
    assert.deepEqual(received, { content })
    const [reply] = await Promise.all([initiator.recv(), responder.send({ count: content.length })])
    assert.deepEqual(reply, { count: content.length })
  } finally { initiator.close(); responder.close(); await tick() }
})

await check('an outer relay cannot substitute an inner target public-key pin', async () => {
  const { left, right } = pair()
  const client = generateKeyPair(), server = generateKeyPair(), wrong = generateKeyPair()
  const outcome = await Promise.allSettled([
    clientHandshake(left.asSocket(), client.privateKey, wrong.publicKey),
    serverHandshake(right.asSocket(), server.privateKey, client.publicKey),
  ])
  assert.equal(outcome[0]!.status, 'rejected')
  if (outcome[0]!.status === 'rejected') assert.ok(outcome[0]!.reason instanceof HandshakeError)
  assert.equal(left.destroyed, true)
  assert.equal(right.destroyed, true)
  await tick()
})

console.log(`ALL PASS: ${checks} bounded RelaySocket groups`)
