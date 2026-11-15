import assert from 'node:assert/strict'
import { createServer, connect } from 'node:net'
import type { Socket, AddressInfo } from 'node:net'
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LinkClient, KEY_SELECTOR_ACK, KEY_SELECTOR_MAGIC, readHandshakeField } from '../src/link.ts'
import type { EndpointConfig } from '../src/link.ts'
import { generateKeyPair, privateToPem, publicToPem, serverHandshake, HandshakeError } from '../src/protocol.ts'
import { resolvePrivateKey, resolvePeerPublicKey } from '../src/keys.ts'

const identity = generateKeyPair()
const client = generateKeyPair()
const other = generateKeyPair()
const sockets = new Set<Socket>()
let releaseEvent: (() => Promise<void>) | undefined
let accepted = 0
let handled = 0
const modern = createServer(socket => {
  accepted++; sockets.add(socket); socket.once('close', () => sockets.delete(socket))
  void (async () => {
    assert.deepEqual(await readHandshakeField(socket, 5), KEY_SELECTOR_MAGIC)
    await readHandshakeField(socket, 64)
    socket.write(KEY_SELECTOR_ACK)
    const channel = await serverHandshake(socket, identity.privateKey, client.publicKey)
    for (;;) {
      const request = await channel.recv()
      if (request === null) break
      handled++
      if (request.op === 'exec') { socket.destroy(); break }
      if (request.marker === 'event-test') releaseEvent = async () => channel.send({ kind: 'note', sessionId: 'owned', text: 'late old-trust event' })
      await channel.send({ id: request.id, ok: true, pong: true, ...(request.op === 'references.list' ? { kind: 'directory' } : {}) })
    }
  })().catch(() => { socket.destroy() })
})
await new Promise<void>(resolve => modern.listen(0, '127.0.0.1', resolve))
const port = (modern.address() as AddressInfo).port
const config = (): EndpointConfig => ({ host: '127.0.0.1', port, privateKey: privateToPem(client.privateKey), peerPublicKey: publicToPem(identity.publicKey), autoGenerateKey: false, timeoutMs: 2000 })
let checks = 0
const check = async (name: string, body: () => unknown | Promise<unknown>) => { await body(); checks++; console.log(`ok ${name}`) }

try {
  await check('selector handshake works without any legacy opt-in', async () => {
    const link = new LinkClient(config, () => {})
    try { assert.equal((await link.request('ping')).pong, true) } finally { link.dispose() }
  })
  await check('a response business kind does not collide with peer-event envelopes', async () => {
    const link = new LinkClient(config, () => {})
    try { assert.equal((await link.request('references.list', { kind: 'workspace', resolve: true })).kind, 'directory') } finally { link.dispose() }
  })
  await check('ambiguous mutating operations are not replayed', async () => {
    const link = new LinkClient(config, () => {})
    const before = handled
    try { await assert.rejects(link.request('exec', { command: 'fixture' })); assert.equal(handled - before, 1) } finally { link.dispose() }
  })
  await check('changed pin invalidates an already connected channel', async () => {
    let current = config()
    const link = new LinkClient(() => current, () => {})
    try {
      await link.request('ping')
      current = { ...current, peerPublicKey: publicToPem(other.publicKey) }
      const before = handled
      await assert.rejects(link.request('ping'), /identity changed|no longer valid/)
      assert.equal(handled, before)
    } finally { link.dispose() }
  })
  await check('events from a rotated pin are refused before dispatch without another request', async () => {
    let current = config()
    let eventCount = 0
    const link = new LinkClient(() => current, () => {})
    link.onEvent(() => { eventCount++ })
    try {
      await link.request('ping', { marker: 'event-test' })
      current = { ...current, peerPublicKey: publicToPem(other.publicKey) }
      assert.ok(releaseEvent)
      await releaseEvent()
      await new Promise<void>(resolve => setTimeout(resolve, 30))
      assert.equal(eventCount, 0)
      assert.equal(link.connected, false)
    } finally { link.dispose(); releaseEvent = undefined }
  })
  await check('rotation of a pin file is checked before channel reuse', async () => {
    const folder = mkdtempSync(join(tmpdir(), 'dshr-pin-'))
    const file = join(folder, 'server.pub')
    writeFileSync(file, publicToPem(identity.publicKey))
    const current = { ...config(), peerPublicKey: '', peerPublicKeyFile: file }
    const link = new LinkClient(() => current, () => {})
    try {
      await link.request('ping')
      writeFileSync(file, publicToPem(other.publicKey))
      await assert.rejects(link.request('ping'), /identity changed|no longer valid/)
    } finally { link.dispose() }
  })
  await check('connection lifetime requires fresh proof and permanent disposal is final', async () => {
    const link = new LinkClient(() => ({ ...config(), maxSessionMs: 100 }), () => {})
    try {
      await link.request('ping')
      const old = accepted
      await new Promise<void>(resolve => setTimeout(resolve, 130))
      assert.equal((await link.request('ping')).pong, true)
      assert.ok(accepted > old)
    } finally { link.dispose() }
    const before = accepted
    await assert.rejects(link.request('ping'), /disposed/)
    assert.equal(accepted, before)
  })
  await check('invalid endpoints, request names and unsafe timers fail before dialing', async () => {
    for (const bad of [{ port: 65536 }, { port: NaN }, { timeoutMs: Infinity }, { maxSessionMs: 0 }]) {
      const link = new LinkClient(() => ({ ...config(), ...bad }), () => {})
      await assert.rejects(link.request('ping'), HandshakeError); link.dispose()
    }
    const link = new LinkClient(config, () => {})
    try { await assert.rejects(link.request('__proto__')); await assert.rejects(link.request('ping', {}, NaN)) } finally { link.dispose() }
  })
  await check('secure default refuses a legacy responder without a second connection', async () => {
    let legacyConnections = 0
    const legacy = createServer(socket => {
      legacyConnections++
      void (async () => { try { await serverHandshake(socket, identity.privateKey, client.publicKey) } finally { socket.destroy() } })().catch(() => {})
    })
    await new Promise<void>(resolve => legacy.listen(0, '127.0.0.1', resolve))
    const legacyPort = (legacy.address() as AddressInfo).port
    const link = new LinkClient(() => ({ ...config(), port: legacyPort }), () => {})
    try { await assert.rejects(link.request('ping'), /legacy handshake is disabled/); assert.equal(legacyConnections, 1) }
    finally { link.dispose(); await new Promise<void>(resolve => legacy.close(() => resolve())) }
  })
  await check('key generation never replaces an existing identity and key files are bounded', async () => {
    const folder = mkdtempSync(join(tmpdir(), 'dshr-keyfiles-'))
    const file = join(folder, 'client.key')
    const first = resolvePrivateKey({ privateKeyFile: file }, 'unused')
    assert.equal(first.generated, true)
    assert.equal(resolvePrivateKey({ privateKeyFile: file }, 'unused').pem, first.pem)
    const large = join(folder, 'too-large.pub')
    writeFileSync(large, 'x'.repeat(20_000))
    assert.throws(() => resolvePeerPublicKey({ peerPublicKeyFile: large }, 'unused'), /16 KiB/)
    if (process.platform !== 'win32') {
      chmodSync(file, 0o644)
      assert.throws(() => resolvePrivateKey({ privateKeyFile: file }, 'unused'), /owner-only/)
      chmodSync(file, 0o600)
    }
    const symbolic = join(folder, 'symlink.key')
    try { symlinkSync(file, symbolic, 'file') } catch (error) {
      if (process.platform !== 'win32' || !['EPERM', 'EACCES'].includes(String((error as { code?: string }).code))) throw error
      return
    }
    assert.throws(() => resolvePrivateKey({ privateKeyFile: symbolic }, 'unused'), /regular file/)
  })
  console.log(`ALL PASS: ${checks} hardened Link/client-key security groups`)
} finally {
  for (const socket of sockets) socket.destroy()
  await new Promise<void>(resolve => modern.close(() => resolve()))
}
