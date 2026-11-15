import test from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, createHash, createPublicKey, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto'
import { once } from 'node:events'
import { connect, createServer } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { Duplex, PassThrough } from 'node:stream'
import {
  ByteReader, DEFAULT_FRAME_TIMEOUT_MS, DEFAULT_MAX_FRAME_BYTES, HandshakeError, MAGIC,
  MAX_FRAME, MAX_SEQUENCE, Session, clientHandshake, fingerprint, generateKeyPair, hkdf,
  parsePrivateKey, parsePublicKey, privateToPem, publicFromRaw, publicToPem, rawPublic, serverHandshake,
} from '../src/protocol.ts'
import type { SessionOptions } from '../src/protocol.ts'

const authError = (error: unknown): boolean => error instanceof HandshakeError
const tick = (): Promise<void> => new Promise(resolve => setImmediate(resolve))
const after = (milliseconds: number): Promise<void> => new Promise(resolve => setTimeout(resolve, milliseconds))
const asSocket = (stream: Duplex): Socket => stream as unknown as Socket

async function socketPair(): Promise<{ client: Socket; server: Socket; close(): Promise<void> }> {
  const listener = createServer()
  const accepted = once(listener, 'connection')
  listener.listen(0, '127.0.0.1')
  await once(listener, 'listening')
  const client = connect((listener.address() as AddressInfo).port, '127.0.0.1')
  client.on('error', () => {})
  await once(client, 'connect')
  const [server] = await accepted as [Socket]
  server.on('error', () => {})
  return { client, server, async close() {
    client.destroy(); server.destroy()
    await new Promise<void>(resolve => listener.close(() => resolve()))
  } }
}

/** Build the original DSHR2 wire independently of the module's private codec. */
function wireFrame(key: Buffer, plaintext: string | Buffer, counter = 1, initiator = true): Buffer {
  const sequence = Buffer.alloc(8); sequence.writeBigUInt64BE(BigInt(counter))
  const direction = Buffer.from(initiator ? 'C2S' : 'S2C')
  const traffic = Buffer.from(hkdfSync('sha256', key, Buffer.alloc(32), Buffer.from(initiator ? 'dshr2 c2s' : 'dshr2 s2c'), 32))
  const cipher = createCipheriv('aes-256-gcm', traffic, Buffer.concat([Buffer.alloc(4), sequence]))
  cipher.setAAD(Buffer.concat([direction, sequence]))
  const body = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  const header = Buffer.alloc(4); header.writeUInt32BE(body.length)
  return Buffer.concat([header, body])
}

function receiver(options: SessionOptions = {}) {
  const stream = new PassThrough({ highWaterMark: 64 })
  const socket = asSocket(stream)
  const key = randomBytes(32)
  const reader = new ByteReader(socket)
  return { stream, socket, key, reader, session: new Session(socket, reader, key, false, options) }
}

class ControlledSocket extends Duplex {
  readonly frames: Buffer[] = []
  callback: ((error?: Error | null) => void) | undefined
  constructor() { super({ readableHighWaterMark: 64, writableHighWaterMark: 8 }) }
  override _read(): void {}
  override _write(chunk: Buffer, _encoding: BufferEncoding, done: (error?: Error | null) => void): void {
    this.frames.push(Buffer.from(chunk)); this.callback = done
  }
  complete(error?: Error): void { const done = this.callback; this.callback = undefined; done?.(error) }
}

function controlled(options: SessionOptions = {}) {
  const stream = new ControlledSocket()
  const socket = asSocket(stream)
  const reader = new ByteReader(socket)
  return { stream, reader, session: new Session(socket, reader, randomBytes(32), true, options) }
}

test('HKDF is standard SHA256 and rejects invalid output lengths without changing wire derivation', () => {
  const input = Buffer.from('synthetic key material'), salt = Buffer.from('salt'), info = Buffer.from('dshr2')
  assert.deepEqual(hkdf(input, salt, info, 64), Buffer.from(hkdfSync('sha256', input, salt, info, 64)))
  for (const length of [-1, 0, 1.5, 8161, Infinity, NaN]) assert.throws(() => hkdf(input, salt, info, length), authError)
})

test('X25519 PEM, exact hex and canonical padded base64 preserve key identity and full fingerprint', () => {
  const pair = generateKeyPair(), raw = rawPublic(pair.publicKey)
  for (const encoded of [publicToPem(pair.publicKey), raw.toString('hex'), raw.toString('hex').toUpperCase(), raw.toString('base64')]) {
    assert.deepEqual(rawPublic(parsePublicKey(` \n${encoded}\n `)), raw)
  }
  const privateRaw = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32)
  for (const encoded of [privateToPem(pair.privateKey), privateRaw.toString('hex'), privateRaw.toString('base64')]) {
    assert.deepEqual(rawPublic(createPublicKey(parsePrivateKey(encoded))), raw)
  }
  assert.equal(fingerprint(pair.publicKey), `SHA256:${createHash('sha256').update(raw).digest('hex')}`)
  assert.equal(fingerprint(pair.publicKey).length, 71)
})

test('permissive base64 junk, whitespace, padding aliases, wrong lengths and concatenated PEM fail closed', () => {
  const raw = Buffer.alloc(32, 255), encoded = raw.toString('base64')
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  const last = alphabet.indexOf(encoded[42]!)
  const noncanonical = encoded.slice(0, 42) + alphabet[(last & ~3) | 1] + '='
  for (const value of ['', encoded.slice(0, -1), encoded + '=', encoded + '!', encoded.slice(0, 5) + '\n' + encoded.slice(5), encoded.replaceAll('/', '_'), noncanonical, 'ab'.repeat(31), 'ab'.repeat(33), 'x'.repeat(9000)]) {
    assert.throws(() => parsePublicKey(value), authError, value.slice(0, 50))
    assert.throws(() => parsePrivateKey(value), authError, value.slice(0, 50))
  }
  const pair = generateKeyPair()
  assert.throws(() => parsePublicKey(publicToPem(pair.publicKey) + publicToPem(pair.publicKey)), authError)
  assert.throws(() => publicFromRaw(Buffer.alloc(31)), authError)
  assert.throws(() => publicFromRaw(new Uint8Array(32) as Buffer), authError)
})

test('all key codec entrypoints enforce X25519 algorithm and public/private role', () => {
  const curve = generateKeyPairSync('ed25519'), pair = generateKeyPair()
  assert.throws(() => parsePrivateKey(curve.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()), authError)
  assert.throws(() => parsePublicKey(curve.publicKey.export({ type: 'spki', format: 'pem' }).toString()), authError)
  assert.throws(() => parsePublicKey(privateToPem(pair.privateKey)), authError)
  assert.throws(() => parsePrivateKey(publicToPem(pair.publicKey)), authError)
  for (const invalid of [pair.privateKey, curve.publicKey, {}]) {
    assert.throws(() => rawPublic(invalid as typeof pair.publicKey), authError)
    assert.throws(() => fingerprint(invalid as typeof pair.publicKey), authError)
    assert.throws(() => publicToPem(invalid as typeof pair.publicKey), authError)
  }
  assert.throws(() => privateToPem(pair.publicKey), authError)
})

test('ByteReader reads fragmented fields linearly and never drains bytes not requested', async () => {
  const stream = new PassThrough({ highWaterMark: 64 }), socket = asSocket(stream)
  const reader = new ByteReader(socket)
  try {
    const pending = reader.read(3, 300)
    stream.write(Buffer.from('a')); stream.write(Buffer.from('b')); stream.write(Buffer.from('cTAIL'))
    assert.equal((await pending)?.toString(), 'abc')
    assert.equal(socket.readableLength, 4)
    assert.equal((await reader.read(4, 300))?.toString(), 'TAIL')
    assert.equal((await reader.read(0))?.length, 0)
    assert.equal(socket.listenerCount('data'), 0)
  } finally { reader.dispose(); stream.destroy() }
})

test('ByteReader timeout and explicit disposal clean every waiter, timer and owned listener', async () => {
  for (const action of ['timeout', 'dispose'] as const) {
    const stream = new PassThrough(), socket = asSocket(stream), reader = new ByteReader(socket)
    const pending = reader.read(1, action === 'timeout' ? 20 : 300)
    const rejected = assert.rejects(pending, authError)
    if (action === 'dispose') reader.dispose()
    await rejected; await tick()
    assert.equal(socket.listenerCount('readable'), 0)
    assert.equal(socket.listenerCount('end'), 0)
    assert.equal(socket.listenerCount('close'), 0)
    assert.equal(socket.listenerCount('error'), 0)
    assert.equal(socket.destroyed, true)
    await assert.rejects(reader.read(1), authError)
  }
})

test('ByteReader rejects concurrency, unsafe sizes and partial EOF instead of silently dropping bytes', async () => {
  const stream = new PassThrough(), socket = asSocket(stream), reader = new ByteReader(socket)
  try {
    for (const size of [-1, NaN, 1.5, MAX_FRAME + 1]) await assert.rejects(reader.read(size), authError)
    const pending = reader.read(4, 300)
    const rejected = assert.rejects(pending, authError)
    await assert.rejects(reader.read(1), authError)
    stream.end(Buffer.from('ab'))
    await rejected
    assert.equal(socket.destroyed, true)
  } finally { reader.dispose(); stream.destroy() }
})

test('paused ByteReader preserves native backpressure rather than accumulating pushed buffers', async () => {
  const stream = new PassThrough({ highWaterMark: 8 }), reader = new ByteReader(asSocket(stream))
  try {
    assert.equal(stream.write(Buffer.alloc(64)), false)
    assert.equal(stream.listenerCount('data'), 0)
    assert.ok(stream.readableLength <= 64)
    assert.equal((await reader.read(4, 300))?.length, 4)
    assert.equal(stream.readableLength, 60)
  } finally { reader.dispose(); stream.destroy() }
})

test('session options reject disabled deadlines, unsafe limits and key/role mistakes', () => {
  for (const options of [{ frameTimeoutMs: 0 }, { frameTimeoutMs: Infinity }, { maxFrameBytes: MAX_FRAME + 1 }, { maxFrameBytes: 17 }, { maxQueuedBytes: 1 }, { maxPendingSends: 0 }]) {
    const stream = new PassThrough(), reader = new ByteReader(asSocket(stream))
    try { assert.throws(() => new Session(asSocket(stream), reader, randomBytes(32), true, options), authError) }
    finally { reader.dispose(); stream.destroy() }
  }
  const stream = new PassThrough(), reader = new ByteReader(asSocket(stream))
  try { assert.throws(() => new Session(asSocket(stream), reader, Buffer.alloc(31), true), authError) }
  finally { reader.dispose(); stream.destroy() }
  assert.equal(DEFAULT_MAX_FRAME_BYTES, 32 * 1024 * 1024)
  assert.equal(DEFAULT_FRAME_TIMEOUT_MS, 30_000)
})

test('independent DSHR2 frames still decrypt and concurrent sends preserve exact order', async () => {
  const pair = await socketPair(), key = randomBytes(32)
  const left = new Session(pair.client, new ByteReader(pair.client), key, true)
  const right = new Session(pair.server, new ByteReader(pair.server), key, false)
  try {
    const sent = Promise.all(Array.from({ length: 20 }, (_, index) => left.send({ index })))
    for (let index = 0; index < 20; index++) assert.deepEqual(await right.recv(500), { index })
    await sent
    assert.ok(left.bytesSent > 0)
    assert.equal(left.bytesSent, right.bytesReceived)
  } finally { left.close(); right.close(); await pair.close() }
  const rx = receiver()
  try {
    rx.stream.write(wireFrame(rx.key, '{"compatible":true}'))
    assert.deepEqual(await rx.session.recv(300), { compatible: true })
  } finally { rx.session.close() }
})

test('tamper, replay, skipped sequence and opposite direction frames terminate the session', async () => {
  for (const mode of ['tag', 'ciphertext', 'replay', 'skip', 'direction'] as const) {
    const rx = receiver()
    try {
      let frame = wireFrame(rx.key, '{"value":1}', mode === 'skip' ? 2 : 1, mode !== 'direction')
      if (mode === 'tag') frame[frame.length - 1]! ^= 1
      if (mode === 'ciphertext') frame[5]! ^= 1
      rx.stream.write(frame)
      if (mode === 'replay') { assert.deepEqual(await rx.session.recv(300), { value: 1 }); rx.stream.write(frame) }
      await assert.rejects(rx.session.recv(300), authError, mode)
      assert.equal(rx.socket.destroyed, true, mode)
      assert.equal((rx.session as unknown as { recvCounter: number }).recvCounter, mode === 'replay' ? 1 : 0)
      await assert.rejects(rx.session.recv(300), authError)
      await assert.rejects(rx.session.send({}), authError)
    } finally { rx.session.close() }
  }
})

test('nonrecord JSON, malformed JSON and invalid UTF8 terminate on the first bad authenticated frame', async () => {
  for (const plaintext of ['null', '[]', '5', 'true', '"text"', '{broken}', Buffer.from([0xff, 0xfe])]) {
    const rx = receiver()
    try {
      rx.stream.write(wireFrame(rx.key, plaintext))
      await assert.rejects(rx.session.recv(300), authError)
      assert.equal(rx.socket.destroyed, true)
      assert.equal(rx.session.bytesReceived, 0)
    } finally { rx.session.close() }
  }
})

test('inbound frame size is checked before allocating/reading its body', async () => {
  for (const length of [0, 16, 17, 65, MAX_FRAME + 1]) {
    const rx = receiver({ maxFrameBytes: 64 })
    try {
      const header = Buffer.alloc(4); header.writeUInt32BE(length)
      rx.stream.write(header)
      await assert.rejects(rx.session.recv(300), authError)
      assert.equal(rx.socket.destroyed, true)
    } finally { rx.session.close() }
  }
})

test('outbound invalid or oversized JSON never consumes a sequence or writes a frame', async () => {
  const tx = controlled({ maxFrameBytes: 64 })
  try {
    const cycle: Record<string, unknown> = {}; cycle.self = cycle
    for (const payload of [null, [], 5, undefined, cycle, { toJSON: () => [] }, { value: 'x'.repeat(100) }]) await assert.rejects(tx.session.send(payload), authError)
    assert.equal(tx.stream.frames.length, 0)
    assert.equal((tx.session as unknown as { sendCounter: number }).sendCounter, 0)
  } finally { tx.session.close() }
})

test('partial header/body EOF is terminal, while EOF before a header is clean null', async () => {
  for (const cut of [1, 3, 4, 7]) {
    const rx = receiver()
    try {
      const pending = rx.session.recv(300)
      const rejected = assert.rejects(pending, authError)
      rx.stream.end(wireFrame(rx.key, '{"data":true}').subarray(0, cut))
      await rejected
      assert.equal(rx.socket.destroyed, true)
    } finally { rx.session.close() }
  }
  const rx = receiver()
  const pending = rx.session.recv(300)
  rx.stream.end()
  assert.equal(await pending, null)
  rx.session.close()
})

test('partial frame has one total deadline but an idle header wait is unlimited', async () => {
  const rx = receiver({ frameTimeoutMs: 45 })
  try {
    const pending = rx.session.recv()
    const observed = pending.then(value => ({ value }), error => ({ error }))
    await after(55)
    assert.equal(rx.socket.destroyed, false, 'idle has no partial-frame timer')
    const frame = wireFrame(rx.key, '{"data":true}')
    rx.stream.write(frame.subarray(0, 1))
    await after(25)
    rx.stream.write(frame.subarray(1, 4))
    const result = await observed
    assert.ok('error' in result && authError(result.error), 'header/body do not receive fresh timeouts')
    assert.equal(rx.socket.destroyed, true)
    assert.equal(rx.socket.listenerCount('readable'), 0)
  } finally { rx.session.close() }
})

test('counter exhaustion and invalid sequence state fail closed before nonce reuse', async () => {
  for (const state of [MAX_SEQUENCE, MAX_SEQUENCE + 1, -1, 1.5, NaN]) {
    const rx = receiver()
    const internal = rx.session as unknown as { recvCounter: number }
    internal.recvCounter = state
    await assert.rejects(rx.session.recv(300), authError)
    assert.equal(rx.socket.destroyed, true)
    const tx = controlled()
    ;(tx.session as unknown as { sendCounter: number }).sendCounter = state
    await assert.rejects(tx.session.send({}), authError)
    assert.equal(tx.stream.frames.length, 0)
    assert.equal(tx.stream.destroyed, true)
  }
})

test('receive concurrency guard rejects a second owner without corrupting the admitted receive', async () => {
  const rx = receiver()
  try {
    const pending = rx.session.recv(300)
    await assert.rejects(rx.session.recv(300), authError)
    rx.stream.write(wireFrame(rx.key, '{"owner":1}'))
    assert.deepEqual(await pending, { owner: 1 })
  } finally { rx.session.close() }
})

test('send queue honors callback plus drain, enforces pending bounds and cleans up after success', async () => {
  const tx = controlled({ maxPendingSends: 2, frameTimeoutMs: 300 })
  try {
    const first = tx.session.send({ n: 1 }), second = tx.session.send({ n: 2 })
    await assert.rejects(tx.session.send({ n: 3 }), authError)
    assert.equal(tx.stream.frames.length, 1)
    tx.stream.complete()
    await first
    assert.equal(tx.stream.frames.length, 2)
    tx.stream.complete()
    await second
    assert.equal(tx.stream.listenerCount('drain'), 0)
    assert.equal((tx.session as unknown as { queuedBytes: number }).queuedBytes, 0)
    assert.equal((tx.session as unknown as { pendingSends: number }).pendingSends, 0)
  } finally { tx.session.close() }
})

test('queued byte budget rejects excess work without poisoning the admitted send', async () => {
  const tx = controlled({ maxQueuedBytes: 40, frameTimeoutMs: 300 })
  try {
    const first = tx.session.send({ n: 1 })
    await assert.rejects(tx.session.send({ n: 2 }), authError)
    assert.equal(tx.stream.frames.length, 1)
    tx.stream.complete(); await first
  } finally { tx.session.close() }
})

test('write deadline or explicit close rejects active and queued sends with no orphan listeners', async () => {
  for (const mode of ['timeout', 'close'] as const) {
    const tx = controlled({ frameTimeoutMs: 20 })
    const a = tx.session.send({ a: 1 }), b = tx.session.send({ b: 2 })
    const aRejected = assert.rejects(a, authError), bRejected = assert.rejects(b, authError)
    if (mode === 'close') tx.session.close()
    await Promise.all([aRejected, bRejected]); await tick()
    assert.equal(tx.stream.destroyed, true)
    for (const event of ['readable', 'drain', 'error', 'close', 'end']) assert.equal(tx.stream.listenerCount(event), 0, `${mode}:${event}`)
    assert.equal((tx.session as unknown as { queuedBytes: number }).queuedBytes, 0)
    assert.equal((tx.session as unknown as { pendingSends: number }).pendingSends, 0)
  }
})

test('a native write callback error rejects active and queued sends and remains handled', async () => {
  const tx = controlled({ frameTimeoutMs: 300 })
  const active = tx.session.send({ first: true }), queued = tx.session.send({ second: true })
  const a = assert.rejects(active, authError), b = assert.rejects(queued, authError)
  tx.stream.complete(new Error('synthetic transport failure'))
  await Promise.all([a, b]); await tick()
  assert.equal(tx.stream.destroyed, true)
  assert.equal((tx.session as unknown as { pendingSends: number }).pendingSends, 0)
  for (const event of ['readable', 'drain', 'error', 'close', 'end']) assert.equal(tx.stream.listenerCount(event), 0, event)
})

test('unchanged DSHR2 handshake still exchanges messages with real sockets and optional limits', async () => {
  const pair = await socketPair(), serverKeys = generateKeyPair(), clientKeys = generateKeyPair()
  let client: Session | undefined, server: Session | undefined
  try {
    const both = await Promise.all([
      clientHandshake(pair.client, clientKeys.privateKey, serverKeys.publicKey, { maxFrameBytes: 1024 }),
      serverHandshake(pair.server, serverKeys.privateKey, clientKeys.publicKey, { maxFrameBytes: 1024 }),
    ])
    ;[client, server] = both
    await client.send({ request: true })
    assert.deepEqual(await server.recv(500), { request: true })
    await server.send({ response: true })
    assert.deepEqual(await client.recv(500), { response: true })
  } finally { client?.close(); server?.close(); await pair.close() }
})

test('handshake rejects wrong pins and wrong key roles as HandshakeError and releases all listeners', async () => {
  for (const mode of ['pin', 'role', 'algorithm'] as const) {
    const pair = await socketPair(), serverKeys = generateKeyPair(), clientKeys = generateKeyPair()
    const baseline = new Map(['readable', 'end', 'close', 'error'].map(event => [event, pair.client.listenerCount(event)]))
    const closed = new Promise<void>(resolve => pair.client.once('close', () => resolve()))
    try {
      if (mode === 'pin') {
        const bad = generateKeyPair()
        const results = await Promise.allSettled([
          clientHandshake(pair.client, clientKeys.privateKey, bad.publicKey),
          serverHandshake(pair.server, serverKeys.privateKey, clientKeys.publicKey),
        ])
        assert.ok(results.every(result => result.status === 'rejected' && authError(result.reason)))
      } else {
        const wrong = mode === 'role' ? clientKeys.publicKey : generateKeyPairSync('ed25519').privateKey
        await assert.rejects(clientHandshake(pair.client, wrong, serverKeys.publicKey), authError)
      }
      assert.equal(pair.client.destroyed, true)
      await closed
      for (const event of ['readable', 'end', 'close', 'error']) assert.ok(pair.client.listenerCount(event) <= baseline.get(event)!, `${mode}:${event}:${pair.client.listeners(event).map(fn => fn.name).join(',')}`)
    } finally { await pair.close() }
  }
})

test('zero-order ephemeral key and truncated handshake fail authentication and close', async () => {
  for (const truncated of [false, true]) {
    const pair = await socketPair(), own = generateKeyPair(), peer = generateKeyPair()
    try {
      const pending = serverHandshake(pair.server, own.privateKey, peer.publicKey)
      const rejected = assert.rejects(pending, authError)
      pair.client.end(truncated ? MAGIC : Buffer.concat([MAGIC, Buffer.alloc(64)]))
      await rejected
      assert.equal(pair.server.destroyed, true)
      assert.equal(pair.server.listenerCount('readable'), 0)
    } finally { await pair.close() }
  }
})
