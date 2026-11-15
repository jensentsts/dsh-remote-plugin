/** Real Cordis + storage domain + authenticated local mock wire. No exec, model call or external peer. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import Storage from '@deepseek-ai/dsh-storage'
import * as StorageDomain from '@deepseek-ai/dsh-storage-domain'
import { SessionPersistenceNotFoundError } from '@deepseek-ai/dsh-session-persistence'
import { SessionId } from '@deepseek-ai/dsh-session'
import { LinkClient } from '../src/link.ts'
import { generateKeyPair, privateToPem, publicToPem } from '../src/protocol.ts'
import { isDefiniteSessionNotFound } from '../src/agent-delivery.ts'
import { createMessageTraces } from '../src/message-traces.ts'
import { createRemoteProvider } from '../src/remote-provider.ts'
import { createRunRegistry } from '../src/remote-runs.ts'
import { NO_START_CAPABILITIES, settleRunResult, subprocessRunHandle } from '@deepseek-ai/dsh-subagent'
const remoteServer = await import(process.env.DSH_REMOTE_TEST_BUILT === '1' ? '../lib/server.js' : '../src/server.ts')

const waitUntil = async predicate => {
  const deadline = Date.now() + 5000
  while (!await predicate()) { if (Date.now() > deadline) throw new Error('local fixture did not settle'); await new Promise(resolve => setTimeout(resolve, 10)) }
}
const freePort = async () => {
  const probe = createServer(); await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = probe.address().port; await new Promise(resolve => probe.close(resolve)); return port
}

// The backend survives domain reopen so storage schema, flush-before-memory and
// the plugin's close/reopen lifetime are exercised through the real facility.
function memoryBackend() {
  const media = new Map()
  return {
    media, async close() {}, kv: { async open(descriptor) {
      let state = media.get(descriptor.name)
      if (!state) { state = { tables: {}, global: null }; media.set(descriptor.name, state) }
      return {
        async loadAll() { return structuredClone(state) },
        async putRecord(table, key, value) { (state.tables[table] ??= {})[key] = structuredClone(value) },
        async deleteRecord(table, key) { delete state.tables[table]?.[key] },
        async deleteRecords(table, keys) { for (const key of keys) delete state.tables[table]?.[key] },
        async setGlobal(value) { state.global = structuredClone(value) }, async close() {},
      }
    } },
  }
}

test('remote exports genuine messages and scoped source, anchors durable input, returns actual note placement, and never creates on unsafe resume failures', async () => {
  const home = await mkdtemp(join(tmpdir(), 'dshr-messages-'))
  const previousHome = process.env.DSH_HOME; process.env.DSH_HOME = home
  const ctx = new Context()
  const backend = memoryBackend()
  const live = new Map(), failures = new Map(), admissions = []
  let creates = 0, busy = false
  await ctx.plugin(Storage)
  ctx.storage.backend.register('remote-fixture', backend)
  ctx.provide('storage.backend.remote-fixture', {})
  await ctx.plugin(StorageDomain, { backend: 'remote-fixture' })
  const owner = generateKeyPair(), stranger = generateKeyPair(), server = generateKeyPair()
  const port = await freePort(), heartbeatFile = join(home, 'heartbeat.json')
  const rowsOf = () => [...ctx.storageDomain.get('dsh_remote_message_traces')?.table('traces').entries() ?? []].map(([, row]) => row)
  ctx.provide('agentDefaultModel', { currentSelection: () => ({ provider: 'fixture', model: 'fixture' }) })
  ctx.provide('agentPresets', { async resolve() { return { id: 'standard' } }, async mount() {} })
  ctx.provide('workspaceRegistry', { async create(path) { return { path, async attachSession() {} } }, list: () => [] })
  ctx.provide('sessions', { async flush() {}, get: () => undefined })
  ctx.provide('agents', {
    async resume({ resumeSessionId }) {
      if (failures.has(resumeSessionId)) throw failures.get(resumeSessionId)
      if (live.has(resumeSessionId)) return { agent: live.get(resumeSessionId) }
      throw new SessionPersistenceNotFoundError(resumeSessionId)
    },
    async create({ sessionId }) {
      creates++
      const events = []
      const session = { id: sessionId, seq: 0, header: { cwd: home }, snapshotEvents: () => events }
      const append = (type, data) => { const event = { seq: session.seq++, time: 1000 + session.seq, type, data }; events.push(event); return event }
      const admit = (message, mode) => {
        assert.equal(rowsOf().find(row => row.messageId === message.id)?.state, 'admitting', 'intent must be durable before inbox side effect')
        admissions.push({ message, mode })
        append('turn/start', { turn: 1 })
        append('user/message', message)
        const emit = (id, content, extra = {}) => append('assistant/message', { turn: 1, step: 1, message: { id, role: 'assistant', source: { kind: 'model', provider: 'actual-provider', model: 'actual-model', replayState: { secret: 'hidden' } }, content }, ...extra })
        emit(`first-${session.seq}`, [{ type: 'text', text: 'first genuine reply' }])
        emit(`thought-${session.seq}`, [{ type: 'reasoning', text: 'hidden thinking' }])
        append('assistant/attempt', { turn: 1, step: 1, stream: [] })
        emit(`partial-${session.seq}`, [{ type: 'text', text: 'interrupted fragment' }], { interrupted: true })
        emit(`second-${session.seq}`, [{ type: 'text', text: 'second genuine reply' }, { type: 'file', attachment: { attachmentId: 'remote-file-ref', name: 'file.txt', bytes: 20 } }], { step: 2 })
        append('turn/end', { turn: 1, reason: { kind: 'completed' } })
      }
      const agent = { id: sessionId, session, followup(message) { admit(message, 'queue') }, steer(message) { admit(message, 'steer') }, async whenIdle() { if (busy) await new Promise(() => {}) }, cancel() {} }
      live.set(sessionId, agent); return { agent }
    },
    get: id => live.get(id), list: () => [...live.values()],
  })
  const plugin = ctx.plugin(remoteServer, { host: '127.0.0.1', port, privateKey: privateToPem(server.privateKey), autoGenerateKey: false,
    authorizedPeers: { owner: { peerPublicKey: publicToPem(owner.publicKey), maxPermission: 3 }, stranger: { peerPublicKey: publicToPem(stranger.publicKey), maxPermission: 1 } },
    audit: false, journal: false, heartbeatFile, workspace: home })
  const link = new LinkClient(() => ({ host: '127.0.0.1', port, privateKey: privateToPem(owner.privateKey), peerPublicKey: publicToPem(server.publicKey), autoGenerateKey: false }), () => {})
  const other = new LinkClient(() => ({ host: '127.0.0.1', port, privateKey: privateToPem(stranger.privateKey), peerPublicKey: publicToPem(server.publicKey), autoGenerateKey: false }), () => {})
  try {
    await plugin
    await waitUntil(async () => { try { return JSON.parse(await readFile(heartbeatFile, 'utf8')).port === port } catch { return false } })
    const info = await link.request('sysinfo', {}, 5000)
    assert.equal(info.features.replies, 'committed-assistant-v1')
    assert.deepEqual(info.features.noteModes, ['queue', 'steer', 'auto'])
    const result = await link.request('agent.prompt', { sessionId: 'same-chat', text: 'request' }, 5000)
    assert.equal(result.reply, 'first genuine reply\n\nsecond genuine reply')
    assert.equal(result.replies.length, 2)
    assert.equal(result.input.messageId, admissions[0].message.id)
    assert.equal(result.input.seq, 1)
    const beforeInvalid = creates
    await assert.rejects(link.request('agent.note', { sessionId: 'not-created', text: 'invalid mode', mode: 'bad' }, 5000), /mode must/)
    assert.equal(creates, beforeInvalid)
    assert.equal(result.replies[1].content[1].attachment.attachmentId, 'remote-file-ref')
    assert.equal(result.replies[0].source.provider, 'actual-provider')
    assert.equal(JSON.stringify(result).includes('hidden thinking'), false)
    assert.equal(JSON.stringify(result).includes('interrupted fragment'), false)
    assert.equal(admissions[0].message.source.kind, 'dsh-remote')
    assert.equal(admissions[0].message.source.remoteSessionId, 'same-chat')
    assert.match(rowsOf()[0].sessionId, /^remote-/)
    assert.equal(rowsOf()[0].state, 'committed'); assert.equal(rowsOf()[0].seq, 1)
    busy = true
    const steer = await link.request('agent.note', { sessionId: 'same-chat', text: 'steer' }, 5000)
    assert.equal(steer.mode, 'steer'); assert.equal(steer.processing, 'next-step')
    const queued = await link.request('agent.note', { sessionId: 'same-chat', text: 'queue', mode: 'queue' }, 5000)
    assert.equal(queued.mode, 'queue'); assert.equal(queued.processing, 'next-turn')
    busy = false
    const idle = await link.request('agent.note', { sessionId: 'same-chat', text: 'idle' }, 5000)
    assert.equal(idle.mode, 'queue'); assert.equal(idle.processing, 'starting')
    await assert.rejects(other.request('agent.prompt', { sessionId: 'same-chat', text: 'no admission' }, 5000), /ceiling is 1/)
    const history = await link.request('agent.events', { sessionId: 'same-chat', fromSeq: 0, limit: 400 }, 5000)
    assert.equal(history.events.some(row => row.type === 'assistant/attempt'), false)
    assert.equal(history.events.find(row => row.type === 'user/message').source.kind, 'dsh-remote')
    const scopedPrefix = rowsOf()[0].sessionId.slice(0, -'same-chat'.length)
    const before = creates
    for (const [name, error] of [
      ['corrupt', Object.assign(new Error('corrupt fixture'), { name: 'SessionPersistenceCorruptionError' })],
      ['held', Object.assign(new Error('writer-held fixture'), { name: 'SessionAlreadyOwnedError' })],
      ['unsupported', Object.assign(new Error('unsupported fixture'), { name: 'SessionFormatUnsupportedError' })],
      ['generic', new Error('no such session')],
    ]) { failures.set(scopedPrefix + name, error); await assert.rejects(link.request('agent.ensure', { sessionId: name }, 5000), new RegExp(error.message)) }
    assert.equal(creates, before)
    assert.equal(isDefiniteSessionNotFound(new SessionPersistenceNotFoundError(SessionId('exact')), 'exact'), true)
    await plugin.dispose()
    assert.equal(ctx.storageDomain.get('dsh_remote_message_traces'), undefined)
    const reopened = createMessageTraces(ctx)
    const stored = await reopened.store()
    const key = Object.keys(backend.media.get('dsh_remote_message_traces').tables.traces)[0]
    assert.equal(stored.get(key).version, 1)
    assert.ok(stored.get(key).messageId)
    await reopened.close()
    const registry = createRunRegistry({ maxRuns: () => 1 })
    const run = registry.start({ sessionId: 'same-chat', description: 'fixture', text: 'mock' })
    registry.settle(run.id, { status: 'completed', reply: result.reply, replies: result.replies, replyFormat: result.replyFormat })
    assert.equal(registry.get(run.id).replies.length, 2)
    registry.get(run.id).replies[0].text = 'cannot mutate registry'
    assert.equal(registry.get(run.id).replies[0].text, 'first genuine reply')
    const provider = createRemoteProvider({ kit: { NO_START_CAPABILITIES, settleRunResult, subprocessRunHandle }, prompt: async () => ({ ...result }), sessionFor: () => 'same-chat', interrupt: async () => { throw new Error('finished run must not interrupt') }, log() {} })
    const providerRun = await provider.start({ parent: { session: { id: 'local' } }, prompt: [{ type: 'text', text: 'fixture' }], signal: new AbortController().signal })
    const settled = await providerRun.result
    assert.equal(settled.replies.length, 2)
    assert.equal(settled.output.some(block => block.type === 'file'), false, 'remote attachment ids are not local ids')
    await providerRun.dispose()
  } finally {
    busy = false; link.close(); other.close(); await ctx.fiber.dispose()
    if (previousHome === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = previousHome
    assert.ok(home.startsWith(join(tmpdir(), 'dshr-messages-')))
    await rm(home, { recursive: true, force: true })
  }
})
