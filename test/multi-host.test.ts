/** Offline mesh security integration: generated keys, real loopback sockets only. */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer, connect } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { updateVolatile } from '@deepseek-ai/cosmokit'
import type { AuthorizedPeer } from '../src/server.ts'
import { LinkClient, KEY_SELECTOR_ACK, KEY_SELECTOR_MAGIC, readHandshakeField } from '../src/link.ts'
import { clientHandshake, generateKeyPair, privateToPem, publicToPem, rawPublic, serverHandshake } from '../src/protocol.ts'
import { PeerRegistry, validatePeerNames } from '../src/peers.ts'
import { traceFixture } from './trace-fixture.ts'

const home = mkdtempSync(join(tmpdir(), 'dshr-mesh-'))
const previousHome = process.env.DSH_HOME
process.env.DSH_HOME = home
const server = await import('../src/server.ts')
const identity = generateKeyPair()
const alice = generateKeyPair()
const bob = generateKeyPair()
const reader = generateKeyPair()
const writer = generateKeyPair()
const stranger = generateKeyPair()
const hashOf = (key: typeof alice.publicKey): string => createHash('sha256').update(rawPublic(key)).digest('hex')
const localId = (key: typeof alice.publicKey, wire: string): string => `remote-${hashOf(key)}-${wire}`
const scope = {}
let passed = 0
const cleanup: Array<() => void> = []
async function check(label: string, run: () => Promise<void> | void): Promise<void> {
  await run()
  passed += 1
  console.log(`ok ${label}`)
}

function harness() {
  const agents = new Map<string, {
    id: string
    ctx: object
    session: { id: string, header: { cwd: string }, seq: number, snapshotEvents: () => never[] }
    followup: (message: unknown) => void
    whenIdle: () => Promise<void>
    cancel: () => void
    cancelled: number
    sent: unknown[]
  }>()
  const accounts: string[] = []
  const calls = new Map<string, { signal: AbortSignal, finish: () => void, callId: string }>()
  let creates = 0
  let resumes = 0
  const services: Record<string, unknown> = {
    storageDomain: traceFixture(),
    agents: {
      async resume(request: { resumeSessionId: string }) {
        resumes += 1
        const agent = agents.get(request.resumeSessionId)
        if (agent === undefined) throw Object.assign(new Error('no persisted session'), { name: 'SessionPersistenceNotFoundError', sessionId: request.resumeSessionId })
        return { agent }
      },
      async create(request: { sessionId: string, meta: { cwd: string } }) {
        creates += 1
        await new Promise<void>(resolve => setTimeout(resolve, 10))
        assert.equal(agents.has(request.sessionId), false, 'concurrent ensure must not duplicate creation')
        const sent: unknown[] = []
        const agent = {
          id: request.sessionId, ctx: scope,
          session: { id: request.sessionId, header: { cwd: request.meta.cwd }, seq: 0, snapshotEvents: () => [] as never[] },
          sent, cancelled: 0,
          followup(message: unknown) { sent.push(message) },
          async whenIdle() {},
          cancel() { agent.cancelled += 1 },
        }
        agents.set(request.sessionId, agent)
        return { agent }
      },
      get: (id: string) => agents.get(id), list: () => [...agents.values()],
    },
    agentPresets: {
      defaultId: 'standard',
      async resolve() { return { id: 'standard' } },
      async list() { return [{ id: 'standard' }] },
      async mount() {},
      async acquireScope() { return { key: scope, async [Symbol.asyncDispose]() {} } },
      async compositionInventory() { return [] },
      composedPreset() { return 'standard' },
    },
    workspaceRegistry: {
      list() { return [{ id: 'ws-fixture', title: 'Fixture workspace', path: home, sessionIds: accounts }] },
      async create(path: string) { return { path, async attachSession(id: string) { accounts.unshift(id) } } },
    },
    pluginManager: { async listPlugins() { return [{ entryId: 'fixture-plugin', moduleName: 'fixture-plugin', enabled: true }] } },
    sessions: { get: (id: string) => agents.get(id)?.session, async flush() {}, list: () => [...agents.values()].map(row => row.session) },
    tools: {
      schemas() { return [{ name: 'fixture_hold', description: 'fixture', parameters: { type: 'object' } }] },
      get(name: string) {
        if (name !== 'fixture_hold') return undefined
        return {
          async execute(args: { marker: string }, exec: { signal: AbortSignal, callId: string }) {
            return await new Promise(resolve => {
              calls.set(args.marker, { signal: exec.signal, callId: exec.callId, finish: () => resolve({ marker: args.marker }) })
            })
          },
          output: { render(_args: unknown, value: unknown) { return [{ type: 'text', text: JSON.stringify(value) }] } },
        }
      },
    },
    agentDefaultModel: { currentSelection() { return { provider: 'fixture', model: 'fixture' } } },
    sessionTitle: { rename() {} },
  }
  return { services, agents, calls, counts: () => ({ creates, resumes }) }
}

type Harness = ReturnType<typeof harness>
async function start(config: Record<string, unknown>, fake = harness()) {
  const probe = createServer()
  await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port
  await new Promise<void>(resolve => probe.close(() => resolve()))
  const handlers = new Map<string, Array<(...args: unknown[]) => unknown>>()
  const stops: Array<() => unknown> = []
  const heartbeat = join(home, `heartbeat-${port}.json`)
  const parsed = server.Config({
    host: '127.0.0.1', port, privateKey: privateToPem(identity.privateKey), autoGenerateKey: false,
    peerPublicKeyFile: '', audit: false, journalFile: join(home, `journal-${port}.jsonl`), heartbeatFile: heartbeat,
    ...config,
  })
  const ctx = {
    logger: { info() {}, warn() {}, debug() {}, error() {} },
    get(name: string) { return fake.services[name] },
    effect(callback: () => unknown) { const stop = callback(); if (typeof stop === 'function') stops.push(stop as () => unknown); return () => {} },
    on(event: string, handler: (...args: unknown[]) => unknown) {
      const existing = handlers.get(event) ?? []; existing.push(handler); handlers.set(event, existing); return () => {}
    },
  }
  server.apply(ctx as never, parsed as never)
  for (let attempts = 0; !existsSync(heartbeat); attempts += 1) {
    assert.ok(attempts < 100, 'server must bind')
    await new Promise<void>(resolve => setTimeout(resolve, 10))
  }
  const stop = () => { for (const dispose of stops.reverse()) dispose() }
  cleanup.push(stop)
  return {
    port, fake, parsed, stop,
    fire(event: string, ...args: unknown[]) { return Promise.all((handlers.get(event) ?? []).map(handler => handler(...args))) },
  }
}
const linkTo = (port: number, key = alice) => {
  const link = new LinkClient(() => ({ host: '127.0.0.1', port, privateKey: privateToPem(key.privateKey), peerPublicKey: publicToPem(identity.publicKey), autoGenerateKey: false, timeoutMs: 5000, allowLegacyHandshake: true }), () => {})
  cleanup.push(() => link.close())
  return link
}
async function waitFor(predicate: () => boolean): Promise<void> {
  for (let count = 0; !predicate(); count += 1) {
    assert.ok(count < 300, 'fixture condition must become ready')
    await new Promise<void>(resolve => setTimeout(resolve, 10))
  }
}

try {
  await check('peer names and registry updates fail atomically', async () => {
    validatePeerNames(['alpha', 'beta-2', '10', '..-'])
    for (const value of ['A', 'rmt', '.', '..', 'alpha/beta', 'alpha:beta', '__proto__', 'constructor', 'prototype', '中文']) {
      assert.throws(() => validatePeerNames([value]))
    }
    assert.throws(() => validatePeerNames(['Alpha', 'alpha']))
    const ctx = new Context()
    await ctx.plugin(PeerRegistry, { peers: { alpha: { host: 'fixture.invalid' } }, defaultPeer: 'alpha' } as never)
    const registry = (ctx as unknown as { dshRemotePeers: PeerRegistry }).dshRemotePeers
    assert.throws(() => registry.profile('toString'), { code: 'FS_NOT_FOUND' })
    assert.throws(() => registry.update({ peers: { beta: {} }, defaultPeer: 'missing' }), { code: 'FS_NOT_FOUND' })
    assert.deepEqual(registry.list(), ['alpha'])
    assert.equal(registry.defaultPeerName(), 'alpha')
    assert.throws(() => registry.update({ peers: { rmt: {} } }))
    assert.deepEqual(registry.list(), ['alpha'])
  })

  const root = join(home, 'write-root')
  mkdirSync(root)
  const running = await start({
    peerPublicKey: publicToPem(stranger.publicKey), // Must never supplement the allowlist.
    authorizedPeers: {
      alpha: { peerPublicKey: publicToPem(alice.publicKey), maxPermission: 3 },
      beta: { peerPublicKey: publicToPem(bob.publicKey), maxPermission: 3 },
      reader: { peerPublicKey: publicToPem(reader.publicKey), maxPermission: 1 },
      writer: { peerPublicKey: publicToPem(writer.publicKey), maxPermission: 2, workspaceRoot: root },
    },
  })
  const a = linkTo(running.port)
  const b = linkTo(running.port, bob)
  const readOnly = linkTo(running.port, reader)
  const confined = linkTo(running.port, writer)
  const pushesA: Array<Record<string, unknown>> = []
  const pushesB: Array<Record<string, unknown>> = []
  a.onEvent(frame => pushesA.push(frame))
  b.onEvent(frame => pushesB.push(frame))

  await check('two proven keys authenticate concurrently; unknown legacy pin is refused', async () => {
    const replies = await Promise.all([a.request('ping'), b.request('ping')])
    assert.ok(replies.every(reply => reply.pong === true))
    const unknown = linkTo(running.port, stranger)
    await assert.rejects(unknown.request('ping'), /refused the selected client key/)
    assert.equal(unknown.connected, false)
  })

  await check('a forged selector cannot impersonate an allowed key', async () => {
    const socket = connect(running.port, '127.0.0.1')
    cleanup.push(() => socket.destroy())
    await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject) })
    socket.write(Buffer.concat([KEY_SELECTOR_MAGIC, rawPublic(alice.publicKey), Buffer.alloc(32)]))
    assert.deepEqual(await readHandshakeField(socket, KEY_SELECTOR_ACK.length), KEY_SELECTOR_ACK)
    await assert.rejects(clientHandshake(socket, stranger.privateKey, identity.publicKey), /authentication FAILED/)
    socket.destroy()
  })

  await check('session-free references.list is read-only and advertised', async () => {
    const before = running.fake.counts()
    const result = await readOnly.request('references.list', { kind: 'all' })
    assert.equal(result.available, true)
    assert.equal((result.workspaces as unknown[]).length, 1)
    assert.equal((result.plugins as unknown[]).length, 1)
    assert.deepEqual(running.fake.counts(), before)
    const info = await a.request('sysinfo')
    assert.ok((info.ops as string[]).includes('references.list'))
    const journal = await readOnly.request('journal.read', { fromSeq: 0, full: true })
    assert.ok(!(journal.entries as Array<{ op?: string }>).some(row => row.op === 'references.list'))
  })

  await check('same wire session id and concurrent ensure cannot cross identities', async () => {
    await Promise.all([a.request('agent.ensure', { sessionId: 'shared' }), a.request('agent.ensure', { sessionId: 'shared' }), b.request('agent.ensure', { sessionId: 'shared' })])
    assert.equal(running.fake.agents.size, 2)
    assert.ok(running.fake.agents.has(localId(alice.publicKey, 'shared')))
    assert.ok(running.fake.agents.has(localId(bob.publicKey, 'shared')))
    await b.request('agent.ensure', { sessionId: localId(alice.publicKey, 'shared') })
    assert.equal(running.fake.agents.size, 3, 'guessing another local id creates only a new own-namespaced session')
    assert.equal(running.fake.agents.get(localId(alice.publicKey, 'shared'))?.sent.length, 0)
    const cancelledBefore = running.fake.agents.get(localId(alice.publicKey, 'shared'))!.cancelled
    const attack = await b.request('agent.interrupt', { sessionId: localId(alice.publicKey, 'shared') })
    assert.equal(attack.interrupted, false)
    assert.equal(running.fake.agents.get(localId(alice.publicKey, 'shared'))!.cancelled, cancelledBefore)
  })

  await check('sysinfo/session/caps/journal lists never expose another principal', async () => {
    const forbidden = hashOf(bob.publicKey)
    for (const [op, args] of [['sysinfo', {}], ['agent.sessions', {}], ['caps.list', {}], ['journal.read', { fromSeq: 0, full: true }]] as const) {
      const reply = await a.request(op, args)
      assert.equal(JSON.stringify(reply).includes(forbidden), false, op)
    }
    const events = await b.request('agent.events', { sessionId: 'shared' })
    assert.equal(events.sessionId, 'shared')
    assert.deepEqual(events.events, [])
    const usage = await a.request('usage.read', { sessionId: localId(bob.publicKey, 'shared') })
    assert.equal(usage.available, false)
  })

  await check('notes and relayed questions route by owner, never newest foreign connection', async () => {
    const agent = running.fake.agents.get(localId(alice.publicKey, 'shared'))!
    pushesA.length = 0; pushesB.length = 0
    await running.fire('session/event', agent.session, { type: 'user/message', data: { id: 'human-fixture', content: [{ type: 'text', text: 'owner-only-note' }], source: { kind: 'user', rpcId: 'fixture-rpc' } } })
    await a.request('ping'); await b.request('ping')
    assert.ok(pushesA.some(frame => frame.kind === 'note' && frame.sessionId === 'shared'))
    assert.equal(pushesB.length, 0)
    let settled = false
    const pending = running.fire('user-questions/request', { agent, questions: [{ id: 'pick', question: 'fixture?' }] }, () => { throw new Error('must relay own session') })
    void pending.then(() => { settled = true })
    await waitFor(() => pushesA.some(frame => frame.kind === 'ask'))
    const ask = pushesA.find(frame => frame.kind === 'ask')!
    assert.equal(pushesB.length, 0)
    await b.notify({ kind: 'answer', qid: ask.qid, answer: { answers: [{ id: 'pick', selected: ['forged'] }] } })
    await b.request('ping')
    assert.equal(settled, false, 'knowing qid does not authorize answering another connection question')
    await a.notify({ kind: 'answer', qid: ask.qid, answer: { answers: [{ id: 'pick', selected: ['owner'] }] } })
    const [answer] = await pending
    assert.deepEqual(answer, { answers: [{ id: 'pick', selected: ['owner'] }] })
  })

  await check('caps cancellation is keyed by identity, duplicates reserved before await', async () => {
    const parkedA = a.request('caps.call', { callId: 'same-call', name: 'fixture_hold', arguments: { marker: 'alice' } }, 10000, { retries: 0 }).then(value => value, error => error as Error)
    const parkedB = b.request('caps.call', { callId: 'same-call', name: 'fixture_hold', arguments: { marker: 'bob' } }, 10000, { retries: 0 }).then(value => value, error => error as Error)
    await waitFor(() => running.fake.calls.has('alice') && running.fake.calls.has('bob'))
    assert.notEqual(running.fake.calls.get('alice')!.callId, running.fake.calls.get('bob')!.callId,
      'peer-supplied ids must not collide inside tool-owned runtime resources')
    await assert.rejects(a.request('caps.call', { callId: 'same-call', name: 'fixture_hold' }), /already running/)
    assert.equal((await b.request('caps.cancel', { callId: 'same-call' })).cancelled, true)
    assert.equal(running.fake.calls.get('alice')!.signal.aborted, false)
    assert.equal(running.fake.calls.get('bob')!.signal.aborted, true)
    assert.ok(await parkedB instanceof Error)
    running.fake.calls.get('bob')!.finish()
    a.close()
    assert.ok(await parkedA instanceof Error)
    assert.equal(a.connected, false, 'close must not silently redial pending work')
    const reconnected = linkTo(running.port)
    assert.equal((await reconnected.request('caps.cancel', { callId: 'same-call' })).cancelled, true)
    assert.equal(running.fake.calls.get('alice')!.signal.aborted, true)
    running.fake.calls.get('alice')!.finish()
    assert.equal((await reconnected.request('agent.ensure', { sessionId: 'shared' })).created, false)
    a.onEvent(frame => pushesA.push(frame))
  })

  await check('exec ids cannot be cancelled by a foreign identity or overwritten', async () => {
    if (process.platform !== 'win32') return
    const currentA = linkTo(running.port)
    const parkedA = currentA.request('exec', { cmd: 'Start-Sleep -Seconds 20', execId: 'same-exec', timeoutMs: 30000 }, 40000, { retries: 0 }).then(value => value, error => error as Error)
    const parkedB = b.request('exec', { cmd: 'Start-Sleep -Seconds 20', execId: 'same-exec', timeoutMs: 30000 }, 40000, { retries: 0 })
    await new Promise<void>(resolve => setTimeout(resolve, 800))
    await assert.rejects(currentA.request('exec', { cmd: 'Write-Output duplicate', execId: 'same-exec' }), /already running/)
    assert.equal((await b.request('exec.cancel', { execId: 'same-exec' })).cancelled, true)
    assert.equal((await parkedB).cancelled, true)
    assert.equal((await b.request('exec.cancel', { execId: 'same-exec' })).cancelled, false)
    currentA.close()
    assert.ok(await parkedA instanceof Error)
    const samePrincipal = linkTo(running.port)
    assert.equal((await samePrincipal.request('exec.cancel', { execId: 'same-exec' })).cancelled, true)
  })

  await check('uploads cannot be committed or aborted by another identity; reconnect resumes', async () => {
    const currentA = linkTo(running.port)
    const path = join(home, 'owned-upload.txt')
    const bytes = Buffer.from('owner-only-transfer')
    const begin = await currentA.request('fs.put.begin', { path, size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), encoding: 'raw', createOnly: true })
    assert.equal((await b.request('fs.put.abort', { uploadId: begin.uploadId })).aborted, false)
    await assert.rejects(b.request('fs.put.chunk', { uploadId: begin.uploadId, index: 0, dataB64: bytes.toString('base64'), encoding: 'raw' }), /unknown upload/)
    await assert.rejects(b.request('fs.put.commit', { uploadId: begin.uploadId }), /unknown upload/)
    currentA.close()
    const reconnected = linkTo(running.port)
    await reconnected.request('fs.put.chunk', { uploadId: begin.uploadId, index: 0, dataB64: bytes.toString('base64'), encoding: 'raw' })
    await reconnected.request('fs.put.commit', { uploadId: begin.uploadId })
    assert.equal(readFileSync(path, 'utf8'), bytes.toString())
  })

  await check('permission minimum, traversal and symlink fences are enforced on server', async () => {
    await assert.rejects(readOnly.request('exec', { cmd: 'Write-Output forbidden' }), error => (error as { peerCode?: unknown }).peerCode === 'FS_PERMISSION_DENIED')
    await assert.rejects(readOnly.request('fs.write', { path: join(root, 'denied'), dataB64: '' }), /permission level 2/)
    await confined.request('fs.write', { path: join(root, 'allowed.txt'), dataB64: Buffer.from('ok').toString('base64') })
    for (const path of [join(home, 'outside.txt'), `${root}/../escape.txt`, `${root}-sibling/file.txt`,
      ...(process.platform === 'win32' ? [`${root}/.. /escape.txt`, `${root}/NUL`, `${root}/file.txt:stream`] : [])]) {
      await assert.rejects(confined.request('fs.write', { path, dataB64: '' }), error => (error as { peerCode?: unknown }).peerCode === 'FS_PERMISSION_DENIED')
    }
    const outside = join(home, 'symlink-outside'); mkdirSync(outside)
    const linked = join(root, 'linked')
    symlinkSync(outside, linked, process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(confined.request('fs.write', { path: join(linked, 'escape.txt'), dataB64: '' }), error => (error as { peerCode?: unknown }).peerCode === 'FS_PERMISSION_DENIED')
    const lowerServer = await start({ maxPermission: 1, authorizedPeers: { alpha: { peerPublicKey: publicToPem(alice.publicKey), maxPermission: 3 } } })
    await assert.rejects(linkTo(lowerServer.port).request('exec', { cmd: 'Write-Output forbidden' }), /ceiling is 1/)
  })

  await check('legacy client to empty allowlist retains exact session ids', async () => {
    const legacy = await start({ peerPublicKey: publicToPem(alice.publicKey), allowLegacyHandshake: true })
    const socket = connect(legacy.port, '127.0.0.1'); cleanup.push(() => socket.destroy())
    await new Promise<void>((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject) })
    const channel = await clientHandshake(socket, alice.privateKey, identity.publicKey)
    await channel.send({ id: 1, op: 'agent.ensure', sessionId: 'legacy-session' })
    assert.equal((await channel.recv())?.ok, true)
    assert.ok(legacy.fake.agents.has('legacy-session'))
    const modern = linkTo(legacy.port)
    assert.equal((await modern.request('agent.ensure', { sessionId: 'legacy-session' })).created, false)
  })

  await check('LinkClient falls back only before authentication and never replays business errors', async () => {
    let accepts = 0; let calls = 0
    const sockets = new Set<Socket>()
    const old = createServer(socket => {
      accepts += 1; sockets.add(socket)
      void (async () => {
        const channel = await serverHandshake(socket, identity.privateKey, alice.publicKey)
        for (;;) {
          const request = await channel.recv(); if (request === null) return
          calls += 1
          await channel.send({ id: request.id, ok: request.op === 'ping', pong: true, error: 'business-denied', code: 'FS_PERMISSION_DENIED' })
        }
      })().catch(() => {}).finally(() => socket.destroy())
    })
    await new Promise<void>(resolve => old.listen(0, '127.0.0.1', resolve))
    cleanup.push(() => { for (const socket of sockets) socket.destroy(); old.close() })
    const current = linkTo((old.address() as AddressInfo).port)
    const startAt = Date.now()
    assert.equal((await current.request('ping')).pong, true)
    assert.ok(Date.now() - startAt < 3000, 'legacy selector rejection must not wait 15 seconds')
    assert.equal(accepts, 2, 'one selector attempt and exactly one legacy fallback')
    await assert.rejects(current.request('mutating.fixture'), /business-denied/)
    assert.equal(calls, 2, 'business refusal must not be re-executed by retry')
    assert.equal(accepts, 2)
  })

  await check('live downgrades revoke writes, and changed roots fence staged uploads', async () => {
    const policies = structuredClone(running.parsed.authorizedPeers.get()) as Record<string, AuthorizedPeer>
    const changed = server.Config({ authorizedPeers: { ...policies, writer: { ...policies.writer, workspaceRoot: join(home, 'other-root') } } })
    mkdirSync(join(home, 'other-root'))
    const bytes = Buffer.from('staged-before-policy-update')
    const staged = await confined.request('fs.put.begin', { path: join(root, 'staged.txt'), size: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), encoding: 'raw' })
    await confined.request('fs.put.chunk', { uploadId: staged.uploadId, index: 0, dataB64: bytes.toString('base64'), encoding: 'raw' })
    updateVolatile(running.parsed.authorizedPeers, changed.authorizedPeers)
    await assert.rejects(confined.request('fs.put.commit', { uploadId: staged.uploadId }))
    assert.equal(existsSync(join(root, 'staged.txt')), false)
    updateVolatile(running.parsed.authorizedPeers, server.Config({ authorizedPeers: structuredClone(policies) }).authorizedPeers)
    await assert.rejects(confined.request('fs.put.abort', { uploadId: staged.uploadId }), /unknown upload|confined path/)
    const downgraded = server.Config({ authorizedPeers: { ...policies, alpha: { ...policies.alpha, maxPermission: 1 } } })
    updateVolatile(running.parsed.authorizedPeers, downgraded.authorizedPeers)
    const same = linkTo(running.port)
    await assert.rejects(same.request('agent.ensure', { sessionId: 'after-downgrade' }), /ceiling is 1/)
    assert.equal((await same.request('ping')).pong, true)
    updateVolatile(running.parsed.authorizedPeers, server.Config({ authorizedPeers: structuredClone(policies) }).authorizedPeers)
    const { alpha: _removed, ...remaining } = policies
    updateVolatile(running.parsed.authorizedPeers, server.Config({ authorizedPeers: remaining }).authorizedPeers)
    await assert.rejects(same.request('ping'))
    updateVolatile(running.parsed.authorizedPeers, server.Config({ authorizedPeers: structuredClone(policies) }).authorizedPeers)
  })

  await check('replacing a legacy pin cannot expose a previous key journal', async () => {
    const legacy = await start({ peerPublicKey: publicToPem(alice.publicKey) })
    const first = linkTo(legacy.port)
    await first.request('agent.ensure', { sessionId: 'legacy-private-fixture' })
    updateVolatile(legacy.parsed.peerPublicKey, server.Config({ peerPublicKey: publicToPem(bob.publicKey) }).peerPublicKey)
    const second = linkTo(legacy.port, bob)
    const journal = await second.request('journal.read', { fromSeq: 0, full: true })
    assert.equal(JSON.stringify(journal).includes('legacy-private-fixture'), false)
    const info = await second.request('sysinfo')
    assert.deepEqual(info.sessions, [])
    await assert.rejects(first.request('ping'))
  })

  await check('two server halves can simultaneously be clients of each other', async () => {
    const otherIdentity = generateKeyPair()
    // This fixture uses another peer's key as its server private key, precisely
    // as two installations may configure the same identity for both halves.
    const left = await start({ authorizedPeers: { beta: { peerPublicKey: publicToPem(otherIdentity.publicKey), maxPermission: 1 } } })
    const right = await start({ privateKey: privateToPem(otherIdentity.privateKey), authorizedPeers: { alpha: { peerPublicKey: publicToPem(identity.publicKey), maxPermission: 1 } } })
    const outboundLeft = new LinkClient(() => ({ host: '127.0.0.1', port: right.port, privateKey: privateToPem(identity.privateKey), peerPublicKey: publicToPem(otherIdentity.publicKey), autoGenerateKey: false }), () => {})
    const outboundRight = new LinkClient(() => ({ host: '127.0.0.1', port: left.port, privateKey: privateToPem(otherIdentity.privateKey), peerPublicKey: publicToPem(identity.publicKey), autoGenerateKey: false }), () => {})
    cleanup.push(() => outboundLeft.close(), () => outboundRight.close())
    assert.ok((await Promise.all([outboundLeft.request('ping'), outboundRight.request('ping')])).every(result => result.pong === true))
  })
  console.log(`\n${passed} multi-host security checks passed`)
} finally {
  for (const stop of cleanup.reverse()) { try { stop() } catch {} }
  process.env.DSH_HOME = previousHome
  // This exact absolute path was minted by mkdtemp above, never caller input.
  assert.ok(home.startsWith(join(tmpdir(), 'dshr-mesh-')))
  await new Promise<void>(resolve => setTimeout(resolve, 100))
  rmSync(home, { recursive: true, force: true })
}
