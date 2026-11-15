import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { createVolatile, updateVolatile } from '@deepseek-ai/cosmokit'
import { generateKeyPair, privateToPem, publicToPem, serverHandshake } from '../src/protocol.ts'
import { KEY_SELECTOR_ACK, readHandshakeField } from '../src/link.ts'

const scratch = mkdtempSync(join(tmpdir(), 'dshr-authority-'))
process.env.DSH_HOME = scratch
const plugin = await import('../src/client.ts')
const clientKeys = generateKeyPair()
const serverKeys = generateKeyPair()
const sockets = new Set<Socket>()
let requests = 0
async function endpoint() {
  const listener = createServer(socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket))
    void (async () => {
      await readHandshakeField(socket, 5); await readHandshakeField(socket, 64); socket.write(KEY_SELECTOR_ACK)
      const channel = await serverHandshake(socket, serverKeys.privateKey, clientKeys.publicKey)
      for (;;) {
        const row = await channel.recv(); if (row === null) break
        requests++
        await channel.send({ id: row.id, ok: true, sessionId: row.sessionId, created: true, events: [] })
      }
    })().catch(() => socket.destroy())
  })
  await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve))
  return { port: (listener.address() as AddressInfo).port, listener }
}
const first = await endpoint()
const second = await endpoint()
const profile = { host: '127.0.0.1', port: first.port, privateKey: privateToPem(clientKeys.privateKey), peerPublicKey: publicToPem(serverKeys.publicKey), autoGenerateKey: false, maxPermission: 3, timeoutMs: 2000 }
const cfg = plugin.Config({ peers: { studio: profile }, defaultPeer: 'studio', privateKey: profile.privateKey, peerPublicKey: profile.peerPublicKey,
  costReporting: false, remoteCapabilities: false, promptGuidance: false, subagentProvider: false, sessionMemoryFile: join(scratch, 'sessions.json') })
const tools = new Map<string, { execute(args: Record<string, unknown>, exec?: unknown): Promise<unknown> }>()
const events = new Map<string, Array<() => void>>()
const disposers: Array<() => unknown> = []
const ctx: Record<string, unknown> = {
  logger: { info() {}, debug() {}, warn() {}, error() {} },
  on(name: string, fn: () => void) { events.set(name, [...(events.get(name) ?? []), fn]); return () => {} },
  effect(fn: () => unknown) { const stop = fn(); if (typeof stop === 'function') disposers.push(stop as () => unknown); return stop },
  plugin() {}, provide() {}, get() { return undefined },
}
ctx.inject = (dependencies: string[], run: (child: unknown) => void) => {
  const child = { ...ctx, tools: { register(def: { name: string; execute(args: Record<string, unknown>, exec?: unknown): Promise<unknown> }) { tools.set(def.name, def); return () => tools.delete(def.name) }, get() { return undefined } } }
  if (dependencies.includes('subagents')) return () => {}
  run(child); return () => {}
}
plugin.apply(ctx as never, cfg as never)
const call = (name: string, args: Record<string, unknown>) => tools.get(name)!.execute(args, { agent: { session: { id: 'local-chat' } } })
const change = (next: typeof profile) => {
  updateVolatile(cfg.peers as never, createVolatile({ studio: next }) as never)
  for (const fn of events.get('loader/volatile-update') ?? []) fn()
}
try {
  await call('remote_agent_ensure', { session_id: 'owned' })
  assert.equal(requests, 1)
  change({ ...profile, maxPermission: 1 })
  await assert.rejects(call('remote_agent_ensure', { session_id: 'owned' }), /ceiling is 1/)
  assert.equal(requests, 1, 'a session binding must not retain an old higher permission')
  change({ ...profile, maxPermission: 3 })
  await call('remote_agent_ensure', { session_id: 'owned' })
  assert.equal(requests, 2, 'same identity may resume after a live permission restoration')
  change({ ...profile, port: second.port })
  await assert.rejects(call('remote_agent_ensure', { session_id: 'owned' }), /cannot migrate/)
  assert.equal(requests, 2, 'even the same key at a different endpoint cannot receive an existing bound session silently')
  updateVolatile(cfg.peers as never, createVolatile({}) as never)
  for (const fn of events.get('loader/volatile-update') ?? []) fn()
  await assert.rejects(call('remote_agent_events', { session_id: 'owned' }), /Unknown|revoked/)
  assert.equal(requests, 2, 'removal cannot resurrect an old transport held by a session')
  change(profile)
  for (const stop of disposers) await stop()
  const beforeDisposed = requests
  await assert.rejects(call('remote_ping', {}), /disposed/)
  assert.equal(requests, beforeDisposed, 'an unregistered tool callback cannot recreate its facade after plugin unload')
  console.log('ALL PASS: live client ceiling, transport retirement, revocation and session authority binding')
} finally {
  for (const stop of disposers.reverse()) await stop()
  for (const socket of sockets) socket.destroy()
  await Promise.all([first.listener, second.listener].map(listener => new Promise<void>(resolve => listener.close(() => resolve()))))
}
