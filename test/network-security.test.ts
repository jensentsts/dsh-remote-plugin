/** Network fault tests: only generated keys, loopback TCP and a fresh temp home. */
import assert from 'node:assert/strict'
import { connect, createServer } from 'node:net'
import type { Socket, AddressInfo } from 'node:net'
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { updateVolatile } from '@deepseek-ai/cosmokit'
import { NetworkGuard, allowedOperations, expirationTime, networkLimits, validateRequestEnvelope } from '../src/network-guard.ts'
import { LinkClient } from '../src/link.ts'
import { clientHandshake, generateKeyPair, privateToPem, publicToPem } from '../src/protocol.ts'
import type { AuthorizedPeer } from '../src/server.ts'
import { traceFixture } from './trace-fixture.ts'

const original = process.env.DSH_HOME
const home = mkdtempSync(join(tmpdir(), 'dshr-network-'))
process.env.DSH_HOME = home
const server = await import('../src/server.ts')
const keys = generateKeyPair()
const owner = generateKeyPair()
const other = generateKeyPair()
const cleanup: Array<() => unknown> = []
let passed = 0
async function check(name: string, fn: () => Promise<void> | void) { await fn(); passed += 1; console.log(`ok ${name}`) }
const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
async function until(fn: () => boolean) { for (let n = 0; !fn(); n += 1) { assert.ok(n < 500, 'condition did not settle'); await delay(10) } }
function changed(ref: Parameters<typeof updateVolatile>[0], source: Parameters<typeof updateVolatile>[1]) { updateVolatile(ref, source) }
async function start(config: Record<string, unknown> = {}) {
  const probe = createServer(); await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port
  await new Promise<void>(resolve => probe.close(() => resolve()))
  const handlers = new Map<string, Array<(...args: unknown[]) => unknown>>()
  const disposers: Array<() => unknown> = []
  const active = new Map<string, { signal: AbortSignal, release: () => void }>()
  const agents = new Map<string, { session: { id: string, seq: number, header: { cwd: string }, snapshotEvents: () => never[] }, sent: unknown[], cancels: number, whenIdle: () => Promise<void>, cancel: () => void, followup: (message: unknown) => void }>()
  let blockAgents = false
  const services: Record<string, unknown> = {
    agentPresets: { defaultId: 'standard', async resolve() { return { id: 'standard' } }, async list() { return [] }, async mount() {}, async acquireScope() { return { key: {}, async [Symbol.asyncDispose]() {} } }, async compositionInventory() { return [] } },
    workspaceRegistry: { list: () => [], async create(path: string) { return { path, async attachSession() {} } } },
    agentDefaultModel: { currentSelection: () => ({ provider: 'fixture', model: 'fixture' }) },
    storageDomain: traceFixture(),
    agents: {
      async resume(request: { resumeSessionId: string }) { throw Object.assign(new Error('no persisted fixture'), { name: 'SessionPersistenceNotFoundError', sessionId: request.resumeSessionId }) },
      async create(request: { sessionId: string }) {
        const agent = { session: { id: request.sessionId, seq: 0, header: { cwd: home }, snapshotEvents: () => [] as never[] }, sent: [] as unknown[], cancels: 0,
          async whenIdle() { if (blockAgents) await new Promise(() => {}) },
          cancel() { agent.cancels += 1 }, followup(message: unknown) { agent.sent.push(message) } }
        agents.set(request.sessionId, agent)
        return { agent }
      }, list: () => [],
    },
    sessions: { async flush() {} },
    tools: { get(name: string) { if (name !== 'hold') return undefined; return {
      execute(args: { marker: string }, exec: { signal: AbortSignal }) { return new Promise(resolve => { active.set(args.marker, { signal: exec.signal, release: () => resolve({ done: true }) }) }) },
      output: { render() { return [{ type: 'text', text: 'done' }] } },
    } }, schemas: () => [] },
  }
  const parsed = server.Config({ host: '127.0.0.1', port, privateKey: privateToPem(keys.privateKey), autoGenerateKey: false,
    authorizedPeers: { owner: { peerPublicKey: publicToPem(owner.publicKey), maxPermission: 3 } },
    audit: false, journal: false, journalFile: join(home, `journal-${port}`), heartbeatFile: join(home, `heartbeat-${port}`), ...config })
  server.apply({ logger: { info() {}, debug() {}, warn() {}, error() {} }, get(name: string) { return services[name] },
    on(name: string, fn: (...args: unknown[]) => unknown) { const list = handlers.get(name) ?? []; list.push(fn); handlers.set(name, list); return () => {} },
    effect(fn: () => unknown) { const value = fn(); if (typeof value === 'function') disposers.push(value as () => unknown); return () => {} },
  } as never, parsed as never)
  await until(() => existsSync(join(home, `heartbeat-${port}`)))
  const stop = () => { for (const dispose of disposers) dispose() }
  cleanup.push(stop)
  return { port, parsed, active, agents, stop,
    blockAgents(value: boolean) { blockAgents = value },
    fire() { for (const fn of handlers.get('loader/volatile-update') ?? []) fn([]) },
    policy(profile: AuthorizedPeer) { changed(parsed.authorizedPeers, server.Config({ authorizedPeers: { owner: { peerPublicKey: publicToPem(owner.publicKey), maxPermission: 3, ...profile } } }).authorizedPeers) },
  }
}
function link(port: number, serverKey = keys.publicKey, client = owner) {
  const instance = new LinkClient(() => ({ host: '127.0.0.1', port, privateKey: privateToPem(client.privateKey), peerPublicKey: publicToPem(serverKey), autoGenerateKey: false, timeoutMs: 1500 }), () => {})
  cleanup.push(() => instance.close()); return instance
}
async function raw(port: number) { const socket = connect(port, '127.0.0.1'); cleanup.push(() => socket.destroy()); await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject) }); return socket }
async function closes(socket: Socket, budget = 1000) { if (socket.destroyed) return; await Promise.race([new Promise<void>(resolve => socket.once('close', resolve)), delay(budget).then(() => { throw new Error('socket did not close') })]) }

try {
  await check('network accounting is finite, bounded and expires lockouts', () => {
    let now = 0
    const guard = new NetworkGuard(() => ({ maxConnections: 2, maxPendingHandshakes: 1, maxTrackedAddresses: 16, maxHandshakeFailures: 1, lockoutSeconds: 1, maxHandshakesPerMinute: 1 }), () => now)
    const first = guard.admit('fixture-address')!; assert.ok(first)
    assert.equal(guard.admit('other-address'), undefined)
    first.failed(); first.release(); first.release()
    assert.equal(guard.admit('fixture-address'), undefined)
    now = 61000
    const later = guard.admit('fixture-address')!; assert.ok(later); later.release()
    for (let i = 0; i < 100; i += 1) { const next = guard.admit(`address-${i}`); next?.failed(); next?.release() }
    assert.ok(guard.snapshot().addresses <= 16)
    assert.deepEqual({ active: guard.snapshot().active, pending: guard.snapshot().pending }, { active: 0, pending: 0 })
    assert.equal(networkLimits({ maxConnections: Number.NaN }).maxConnections, 64)
    assert.equal(networkLimits({ maxSessionMs: 0 }).maxSessionMs, 100)
  })
  await check('envelope ids, exact allowed ops and expiry are strict', () => {
    for (const value of [null, [], { id: 0, op: 'ping' }, { id: 1.5, op: 'ping' }, { id: 1, op: 'PING' }, { id: 1, op: 'a'.repeat(65) }, { id: 1, op: 'ping', kind: 'answer' }]) assert.throws(() => validateRequestEnvelope(value, 0))
    assert.throws(() => validateRequestEnvelope({ id: 1, op: 'ping' }, 1))
    assert.equal(validateRequestEnvelope({ id: 2, op: 'fs.read' }, 1).type, 'request')
    assert.equal(validateRequestEnvelope({ id: 2, op: 'references.list', kind: 'workspace' }, 1).type, 'request')
    assert.throws(() => allowedOperations(['fs.*']))
    for (const expiry of ['2030-02-30T00:00:00Z', '2030-01-01', '2030-01-01T00:00:60Z', '2030-01-01T00:00:00-00:00']) assert.throws(() => expirationTime(expiry))
    assert.ok(expirationTime('2032-02-29t00:00:00z'))
  })
  await check('slowloris has a total deadline and pending/global limits release slots', async () => {
    const slow = await start({ handshakeTimeoutMs: 120, maxPendingHandshakes: 1, maxConnections: 2 })
    const stalled = await raw(slow.port); stalled.write('D')
    const refused = await raw(slow.port); await closes(refused)
    await closes(stalled)
    slow.stop()
    // The deliberately tiny attack deadline is not a performance assertion for
    // legitimate key agreement. Use a fresh normal-budget listener: client EOF
    // alone is not a barrier for the old listener's server-side slot release.
    // Deterministic same-guard release/idempotence is asserted in group 1.
    const service = await start({ handshakeTimeoutMs: 15000, maxPendingHandshakes: 1, maxConnections: 2 })
    const healthy = link(service.port); assert.equal((await healthy.request('ping')).pong, true)
    const second = link(service.port); assert.equal((await second.request('ping')).pong, true)
    const full = await raw(service.port); await closes(full)
    service.stop(); await until(() => !healthy.connected && !second.connected)
  })
  await check('stop destroys unauthenticated sockets and default rejects direct legacy', async () => {
    const service = await start()
    const pending = await raw(service.port); service.stop(); await closes(pending)
    const legacy = await start({ authorizedPeers: {}, peerPublicKey: publicToPem(owner.publicKey) })
    const channel = await raw(legacy.port)
    await assert.rejects(clientHandshake(channel, owner.privateKey, keys.publicKey))
  })
  await check('request duplicate id is fatal and cannot replay an operation', async () => {
    const service = await start({ authorizedPeers: {}, peerPublicKey: publicToPem(owner.publicKey), allowLegacyHandshake: true })
    const socket = await raw(service.port); const session = await clientHandshake(socket, owner.privateKey, keys.publicKey)
    await session.send({ id: 1, op: 'ping' }); assert.equal((await session.recv())?.pong, true)
    await session.send({ id: 1, op: 'ping' }); await closes(socket)
  })
  await check('unknown clients and disabled/expired/malformed policies never authenticate', async () => {
    const service = await start(); await assert.rejects(link(service.port, keys.publicKey, other).request('ping'))
    for (const profile of [{ disabled: true }, { validUntil: '2000-01-01T00:00:00Z' }, { validUntil: '2030-02-30T00:00:00Z' }, { allowedOps: ['*'] }]) {
      const denied = await start({ authorizedPeers: { owner: { peerPublicKey: publicToPem(owner.publicKey), ...profile } } })
      await assert.rejects(link(denied.port).request('ping'))
    }
  })
  await check('read-only roots default deny credentials and explicitly confine native reads', async () => {
    const root = join(home, 'read-root'); mkdirSync(root)
    const secret = join(home, 'private-key-fixture'); writeFileSync(secret, 'secret-fixture')
    const data = join(root, 'allowed'); writeFileSync(data, 'readable')
    const service = await start({ authorizedPeers: { owner: { peerPublicKey: publicToPem(owner.publicKey), maxPermission: 1, readRoots: [root] } } })
    const peer = link(service.port)
    for (const op of ['fs.read', 'fs.hash', 'fs.get', 'fs.stat', 'fs.list']) await assert.rejects(peer.request(op, { path: secret }), /readRoots/)
    assert.equal(Buffer.from(String((await peer.request('fs.read', { path: data })).dataB64), 'base64').toString(), 'readable')
    assert.equal((await peer.request('fs.stat', { path: join(root, 'missing') })).exists, false)
    const empty = await start({ authorizedPeers: { owner: { peerPublicKey: publicToPem(owner.publicKey), maxPermission: 1 } } })
    await assert.rejects(link(empty.port).request('fs.read', { path: data }), /readRoots/)
  })
  await check('allowedOps cannot elevate ceiling and principal concurrency spans sockets', async () => {
    const service = await start({ maxInFlightPerPrincipal: 1 })
    const first = link(service.port); const second = link(service.port)
    const parked = first.request('caps.call', { name: 'hold', callId: 'owned', arguments: { marker: 'owned' } }, 5000, { retries: 0 }).catch(error => error)
    await until(() => service.active.has('owned'))
    await assert.rejects(second.request('caps.call', { name: 'hold', callId: 'other', arguments: { marker: 'other' } }), /concurrency/)
    assert.equal((await second.request('caps.cancel', { callId: 'owned' })).cancelled, true)
    await parked; service.active.get('owned')!.release()
    service.policy({ maxPermission: 1, allowedOps: ['exec', 'ping'] }); service.fire()
    const restricted = link(service.port)
    await assert.rejects(restricted.request('exec', { cmd: 'forbidden' }), /ceiling is 1/)
    await assert.rejects(restricted.request('sysinfo'), /allowedOps/)
  })
  await check('live revocation cancels owned caps/uploads/queued agents and closes only revoked identity', async () => {
    const service = await start(); const peer = link(service.port)
    const parked = peer.request('caps.call', { name: 'hold', callId: 'held', arguments: { marker: 'held' } }, 5000, { retries: 0 }).catch(error => error)
    await until(() => service.active.has('held'))
    const bytes = Buffer.from('pending-upload')
    const begin = await peer.request('fs.put.begin', { path: join(home, 'pending-target'), size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') })
    await peer.request('agent.ensure', { sessionId: 'queued' }); service.blockAgents(true)
    const queued = peer.request('agent.prompt', { sessionId: 'queued', text: 'must-never-run' }, 5000, { retries: 0 }).catch(error => error)
    await delay(30)
    service.policy({ disabled: true }); service.fire()
    await until(() => !peer.connected && service.active.get('held')!.signal.aborted)
    await Promise.all([parked, queued]); service.active.get('held')!.release()
    assert.ok([...service.agents.values()].every(agent => agent.sent.length === 0 && agent.cancels > 0))
    assert.equal(existsSync(`${join(home, 'pending-target')}.${begin.uploadId}.dshremote-upload`), false)
  })
  await check('identity rotation is live; unrelated settings do not drop the connection', async () => {
    const service = await start(); const peer = link(service.port)
    assert.equal((await peer.request('ping')).pong, true)
    changed(service.parsed.audit, server.Config({ audit: true }).audit); service.fire()
    assert.equal((await peer.request('ping')).pong, true); assert.equal(peer.connected, true)
    const replacement = generateKeyPair()
    changed(service.parsed.privateKey, server.Config({ privateKey: privateToPem(replacement.privateKey) }).privateKey); service.fire()
    await until(() => !peer.connected)
    await assert.rejects(link(service.port).request('ping'))
    assert.equal((await link(service.port, replacement.publicKey).request('ping')).pong, true)
  })
  await check('old socket age cannot cancel a younger same-principal socket or work', async () => {
    const service = await start({ maxSessionMs: 550 }); const first = link(service.port)
    await first.request('ping'); await delay(300)
    const second = link(service.port); await second.request('ping')
    const parked = second.request('caps.call', { name: 'hold', callId: 'fresh', arguments: { marker: 'fresh' } }, 3000, { retries: 0 }).catch(error => error)
    await until(() => service.active.has('fresh'))
    await delay(300)
    assert.equal(first.connected, false); assert.equal(second.connected, true)
    assert.equal(service.active.get('fresh')!.signal.aborted, false)
    service.active.get('fresh')!.release(); await parked
  })
  console.log(`\n${passed} network security groups passed`)
} finally {
  for (const dispose of cleanup.reverse()) { try { dispose() } catch {} }
  for (let n = 0; n < 20; n += 1) { try { await delay(10); rmSync(home, { recursive: true, force: true }); break } catch { if (n === 19) throw new Error('fixture cleanup failed') } }
  if (original === undefined) delete process.env.DSH_HOME
  else process.env.DSH_HOME = original
}
