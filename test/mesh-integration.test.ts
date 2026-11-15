/** Real loopback hub and two outbound-only nodes; no external host or profile. */
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { mkdtempSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import { generateKeyPair, privateToPem, publicToPem } from '../src/protocol.ts'
import { LinkClient } from '../src/link.ts'
import type { AuthorizedPeer } from '../src/server.ts'

const original = process.env.DSH_HOME
const home = mkdtempSync(join(tmpdir(), 'dshr-mesh-e2e-'))
process.env.DSH_HOME = home
const server = await import('../src/server.ts')
const { default: Mesh } = await import('../src/mesh.ts')
const hubKey = generateKeyPair(), aliceKey = generateKeyPair(), bobKey = generateKeyPair(), aliceServer = generateKeyPair(), bobServer = generateKeyPair(), wrong = generateKeyPair()
const cleanup: Array<() => unknown | Promise<unknown>> = []
const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
async function until(test: () => boolean, message: string) { for (let i = 0; !test(); i++) { assert.ok(i < 500, message); await delay(10) } }
async function launch(identity: ReturnType<typeof generateKeyPair>, authorizedPeers: Record<string, AuthorizedPeer>, relayEnabled = false) {
  const probe = createServer(); await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port; await new Promise<void>(resolve => probe.close(() => resolve()))
  const heartbeat = join(home, `heartbeat-${port}`), disposers: Array<() => unknown> = []
  const config = server.Config({ host: '127.0.0.1', port, privateKey: privateToPem(identity.privateKey), autoGenerateKey: false,
    authorizedPeers, relayEnabled, audit: false, journal: false, journalFile: join(home, `journal-${port}`), heartbeatFile: heartbeat })
  server.apply({ logger: { info() {}, debug() {}, warn() {}, error() {} }, get() { return undefined }, on() { return () => {} },
    effect(fn: () => unknown) { const result = fn(); if (typeof result === 'function') disposers.push(result as () => unknown); return () => {} },
  } as never, config as never)
  cleanup.push(() => { for (const stop of disposers) stop() })
  await until(() => existsSync(heartbeat), 'test server must listen')
  return { port }
}
async function node(port: number, key: ReturnType<typeof generateKeyPair>, targetPort: number, acceptInbound = true) {
  const ctx = new Context()
  const fiber = ctx.plugin(Mesh, { host: '127.0.0.1', port, privateKey: privateToPem(key.privateKey), autoGenerateKey: false,
    peerPublicKey: publicToPem(hubKey.publicKey), targetPort, acceptInbound, timeoutMs: 5000, autoReconnect: false })
  cleanup.push(async () => { ctx.get('dshRemoteMesh')?.dispose(); await fiber.dispose() })
  await until(() => ctx.get('dshRemoteMesh') !== undefined, 'mesh service must start')
  const mesh = ctx.get('dshRemoteMesh')!
  await until(() => mesh.status().registered === true, 'mesh node must register with the hub')
  return mesh
}
function routed(mesh: { open(target: string): Promise<Socket> }, target: string, client: ReturnType<typeof generateKeyPair>, pin: ReturnType<typeof generateKeyPair>) {
  const link = new LinkClient(() => ({ relayTarget: target, privateKey: privateToPem(client.privateKey), peerPublicKey: publicToPem(pin.publicKey), autoGenerateKey: false, timeoutMs: 5000 }), () => {}, 'loopback mesh target', config => mesh.open(config.relayTarget!))
  cleanup.push(() => link.dispose()); return link
}
try {
  const hub = await launch(hubKey, {
    alpha: { peerPublicKey: publicToPem(aliceKey.publicKey), maxPermission: 1, relayTargets: ['beta'] },
    beta: { peerPublicKey: publicToPem(bobKey.publicKey), maxPermission: 1, relayTargets: ['alpha'] },
  }, true)
  const alphaServer = await launch(aliceServer, { beta: { peerPublicKey: publicToPem(bobKey.publicKey), maxPermission: 1 } })
  const betaServer = await launch(bobServer, { alpha: { peerPublicKey: publicToPem(aliceKey.publicKey), maxPermission: 1 } })
  const alpha = await node(hub.port, aliceKey, alphaServer.port)
  const beta = await node(hub.port, bobKey, betaServer.port)
  const ab = routed(alpha, 'beta', aliceKey, bobServer), ba = routed(beta, 'alpha', bobKey, aliceServer)
  assert.equal((await ab.request('ping')).pong, true)
  assert.equal((await ba.request('ping')).pong, true)
  console.log('ok two outbound-only nodes communicate in both directions through one hub entry')
  assert.ok((await Promise.all(Array.from({ length: 6 }, () => ab.request('ping')))).every(reply => reply.pong === true))
  console.log('ok multiplexed RPC survives nested authenticated encrypted channels')
  await assert.rejects(ab.request('exec', { cmd: 'must-never-run' }), /permission|ceiling/)
  const impostor = routed(alpha, 'beta', aliceKey, wrong)
  await assert.rejects(impostor.request('ping'), /authentication|pin|handshake/i)
  console.log('ok hub forwarding grants no target permission and cannot replace target public-key pins')
  await assert.rejects(alpha.open('unknown'), /unknown|online|allowed|target|route/i)
  beta.dispose()
  await until(() => !ab.connected, 'disconnecting a node must close its routed channels')
  console.log('ok unknown routes fail closed and disconnected nodes invalidate their tunnels')
  console.log('ALL PASS: one-entry hub, bidirectional control, inner pinning and target authorization')
} finally {
  for (const stop of cleanup.reverse()) { try { await stop() } catch {} }
  await delay(30)
  rmSync(home, { recursive: true, force: true })
  if (original === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = original
}
