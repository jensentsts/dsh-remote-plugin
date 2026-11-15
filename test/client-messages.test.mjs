/** Consumer and pure presenter coverage against an encrypted fixture server. No external peer or exec. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { generateKeyPair, privateToPem, publicToPem, serverHandshake } from '../src/protocol.ts'
import { KEY_SELECTOR_ACK, readHandshakeField } from '../src/link.ts'
const client = await import(process.env.DSH_REMOTE_TEST_BUILT === '1' ? '../lib/client.js' : '../src/client.ts')

const eventually = async predicate => {
  const end = Date.now() + 5000
  while (!await predicate()) { if (Date.now() > end) throw new Error('fixture not ready'); await new Promise(resolve => setTimeout(resolve, 10)) }
}

test('foreground/background presenters preserve each actual message and legacy/steer/failure paths never claim unavailable capabilities or replay ambiguous input', async () => {
  const home = await mkdtemp(join(tmpdir(), 'dshr-client-messages-'))
  const previous = process.env.DSH_HOME; process.env.DSH_HOME = home
  const keys = generateKeyPair(), peer = generateKeyPair(), sockets = new Set(), requests = []
  let behavior = 'new'
  const reply = sessionId => ({ sessionId, replyFormat: 'committed-assistant-v1', reply: 'one\n\ntwo', reason: 'completed', created: false, replies: ['one', 'two'].map((text, index) => ({
    version: 1, sessionId, seq: index + 10, time: index + 100, turn: 1, step: index + 1, messageId: `message-${index + 1}`,
    source: { kind: 'model', provider: 'true-provider', model: 'true-model' }, provider: 'true-provider', model: 'true-model',
    content: [{ type: 'text', text }], text, attachmentScope: 'remote-session',
  })) })
  const listener = createServer(socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket))
    void (async () => {
      await readHandshakeField(socket, 5); await readHandshakeField(socket, 64); socket.write(KEY_SELECTOR_ACK)
      const channel = await serverHandshake(socket, peer.privateKey, keys.publicKey)
      for (;;) {
        const row = await channel.recv(); if (row === null) return
        requests.push(row)
        if (row.op === 'sysinfo') {
          if (behavior === 'probe-fail') { await channel.send({ id: row.id, ok: false, error: 'observation unavailable' }); continue }
          await channel.send({ id: row.id, ok: true, ops: ['agent.note', 'agent.prompt'], ...(behavior === 'legacy' ? {} : { features: { noteModes: ['queue', 'steer', 'auto'] } }) }); continue
        }
        if (row.op === 'agent.note') {
          if (behavior === 'ambiguous') { await channel.send({ id: row.id, ok: false, error: 'receipt storage unsupported after wake' }); continue }
          await channel.send({ id: row.id, ok: true, accepted: true, ...(behavior === 'legacy' ? {} : { mode: row.mode === 'queue' ? 'queue' : 'steer', processing: row.mode === 'queue' ? 'next-turn' : 'next-step' }) }); continue
        }
        await channel.send({ id: row.id, ok: true, ...reply(row.sessionId) })
      }
    })().catch(() => socket.destroy())
  })
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve))
  const ctx = new Context(), tools = new Map()
  ctx.provide('tools', { register(definition) { tools.set(definition.name, definition); return () => tools.delete(definition.name) }, get() {} })
  const mounted = []
  async function mount(label) {
    const fiber = ctx.plugin(client, { host: '127.0.0.1', port: listener.address().port, privateKey: privateToPem(keys.privateKey),
      peerPublicKey: publicToPem(peer.publicKey), autoGenerateKey: false, maxPermission: 3, costReporting: false, remoteCapabilities: false,
      promptGuidance: false, subagentProvider: false, sessionMemoryFile: join(home, `${label}.json`) })
    mounted.push(fiber); await fiber; await eventually(() => tools.has('remote_agent_prompt'))
    return { fiber, call: (name, args) => tools.get(name).execute(args, { agent: { session: { id: `local-${label}` } }, signal: new AbortController().signal }) }
  }
  try {
    const current = await mount('new')
    const foreground = await current.call('remote_agent_prompt', { text: 'fixture', session_id: 'remote-fixture' })
    assert.equal(foreground.replies.length, 2)
    const view = tools.get('remote_agent_prompt').output.render({}, foreground).map(block => block.text ?? '').join('')
    assert.ok(view.includes('remote reply 1/2') && view.includes('remote reply 2/2') && view.includes('true-provider/true-model'))
    const run = await current.call('remote_run_start', { description: 'fixture', text: 'background', session_id: 'remote-fixture' })
    const status = await current.call('remote_run_status', { run_id: run.runId, wait_ms: 1000 })
    assert.equal(status.replies.length, 2)
    const statusView = tools.get('remote_run_status').output.render({}, status).map(block => block.text ?? '').join('')
    assert.ok(statusView.includes('remote reply 1/2') && statusView.includes('remote reply 2/2'))
    const steered = await current.call('remote_send_message', { session_id: 'remote-fixture', message: 'steer', mode: 'steer' })
    assert.equal(steered.mode, 'steer'); assert.equal(steered.processing, 'next-step')
    behavior = 'ambiguous'
    const prompts = requests.filter(row => row.op === 'agent.prompt').length
    await assert.rejects(current.call('remote_send_message', { session_id: 'remote-fixture', message: 'do not replay' }), /receipt storage unsupported/)
    assert.equal(requests.filter(row => row.op === 'agent.prompt').length, prompts)
    await current.fiber.dispose(); tools.clear() // collector is not the production effect-owned Tools registry
    behavior = 'legacy'
    const legacy = await mount('legacy')
    const before = requests.length
    await assert.rejects(legacy.call('remote_send_message', { session_id: 'legacy', message: 'steer', mode: 'steer' }), /does not advertise steering/)
    assert.equal(requests.slice(before).some(row => row.op === 'agent.note'), false)
    const queued = await legacy.call('remote_send_message', { session_id: 'legacy', message: 'queue' })
    assert.equal(queued.mode, 'queue'); assert.ok(queued.note.includes('旧peer'))
    assert.equal(requests.at(-1).mode, undefined)
    await legacy.fiber.dispose(); tools.clear()
    behavior = 'probe-fail'
    const failed = await mount('failed')
    const count = requests.length
    await assert.rejects(failed.call('remote_send_message', { session_id: 'failed', message: 'no fallback' }), /observation unavailable/)
    assert.deepEqual(requests.slice(count).map(row => row.op), ['sysinfo'])
    await failed.fiber.dispose()
  } finally {
    for (const fiber of mounted) await fiber.dispose()
    await ctx.fiber.dispose(); for (const socket of sockets) socket.destroy()
    await new Promise(resolve => listener.close(resolve))
    if (previous === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = previous
    assert.ok(home.startsWith(join(tmpdir(), 'dshr-client-messages-'))); await rm(home, { recursive: true, force: true })
  }
})
