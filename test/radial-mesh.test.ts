/** Three outbound-only spokes on one hub entry: every pair is mutually controllable, and nothing else is. */
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
const home = mkdtempSync(join(tmpdir(), 'dshr-mesh-radial-'))
process.env.DSH_HOME = home
const server = await import('../src/server.ts')
const { default: Mesh } = await import('../src/mesh.ts')
type Pair = ReturnType<typeof generateKeyPair>
const hubKey = generateKeyPair()
const id = { alpha: generateKeyPair(), beta: generateKeyPair(), gamma: generateKeyPair(), delta: generateKeyPair() }
const srv = { alpha: generateKeyPair(), beta: generateKeyPair(), gamma: generateKeyPair() }
const cleanup: Array<() => unknown | Promise<unknown>> = []
const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
async function until(test: () => boolean, message: string) { for (let i = 0; !test(); i++) { assert.ok(i < 500, message); await delay(10) } }
const silent = { logger: { info() {}, debug() {}, warn() {}, error() {} }, get() { return undefined }, on() { return () => {} } }
async function launch(identity: Pair, authorizedPeers: Record<string, AuthorizedPeer>, relayEnabled = false) {
  const probe = createServer(); await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port; await new Promise<void>(resolve => probe.close(() => resolve()))
  const heartbeat = join(home, `heartbeat-${port}`), disposers: Array<() => unknown> = []
  const config = server.Config({ host: '127.0.0.1', port, privateKey: privateToPem(identity.privateKey), autoGenerateKey: false,
    authorizedPeers, relayEnabled, audit: false, journal: false, journalFile: join(home, `journal-${port}`), heartbeatFile: heartbeat })
  server.apply({ ...silent, effect(fn: () => unknown) { const result = fn(); if (typeof result === 'function') disposers.push(result as () => unknown); return () => {} },
  } as never, config as never)
  cleanup.push(() => { for (const stop of disposers) stop() })
  await until(() => existsSync(heartbeat), 'radial server must listen')
  return { port }
}
async function node(port: number, key: Pair, targetPort: number, acceptInbound = true) {
  const ctx = new Context()
  const fiber = ctx.plugin(Mesh, { host: '127.0.0.1', port, privateKey: privateToPem(key.privateKey), autoGenerateKey: false,
    peerPublicKey: publicToPem(hubKey.publicKey), targetPort, acceptInbound, timeoutMs: 5000, autoReconnect: false })
  cleanup.push(async () => { ctx.get('dshRemoteMesh')?.dispose(); await fiber.dispose() })
  await until(() => ctx.get('dshRemoteMesh') !== undefined, 'mesh service must start')
  const mesh = ctx.get('dshRemoteMesh')!
  await until(() => mesh.status().registered === true, 'spoke must register with the one hub entry')
  return mesh
}
function routed(mesh: { open(target: string): Promise<Socket> }, target: string, client: Pair, pin: Pair) {
  const link = new LinkClient(() => ({ relayTarget: target, privateKey: privateToPem(client.privateKey), peerPublicKey: publicToPem(pin.publicKey), autoGenerateKey: false, timeoutMs: 5000 }), () => {}, 'radial target', config => mesh.open(config.relayTarget!))
  cleanup.push(() => link.dispose()); return link
}
const pin = (key: Pair) => publicToPem(key.publicKey)
try {
  const hub = await launch(hubKey, {
    alpha: { peerPublicKey: pin(id.alpha), maxPermission: 1, relayTargets: ['beta', 'gamma'] },
    beta: { peerPublicKey: pin(id.beta), maxPermission: 1, relayTargets: ['alpha', 'gamma'] },
    gamma: { peerPublicKey: pin(id.gamma), maxPermission: 1, relayTargets: ['alpha', 'beta'] },
    delta: { peerPublicKey: pin(id.delta), maxPermission: 1, relayTargets: ['alpha'] },
  }, true)
  const host = {
    alpha: await launch(srv.alpha, { beta: { peerPublicKey: pin(id.beta), maxPermission: 1 }, gamma: { peerPublicKey: pin(id.gamma), maxPermission: 1 } }),
    beta: await launch(srv.beta, { alpha: { peerPublicKey: pin(id.alpha), maxPermission: 1 }, gamma: { peerPublicKey: pin(id.gamma), maxPermission: 1 } }),
    gamma: await launch(srv.gamma, { alpha: { peerPublicKey: pin(id.alpha), maxPermission: 1 }, beta: { peerPublicKey: pin(id.beta), maxPermission: 1 } }),
  }
  const alpha = await node(hub.port, id.alpha, host.alpha.port)
  const beta = await node(hub.port, id.beta, host.beta.port)
  const gamma = await node(hub.port, id.gamma, host.gamma.port, false)
  const delta = await node(hub.port, id.delta, 9)

  const ab = routed(alpha, 'beta', id.alpha, srv.beta), ba = routed(beta, 'alpha', id.beta, srv.alpha)
  const ca = routed(gamma, 'alpha', id.gamma, srv.alpha)
  const ac = routed(alpha, 'gamma', id.alpha, srv.gamma), bc = routed(beta, 'gamma', id.beta, srv.gamma)
  for (const [name, link] of [['alpha->beta', ab], ['beta->alpha', ba], ['gamma->alpha', ca]] as const) {
    assert.equal((await link.request('ping')).pong, true, `${name} must cross the single hub entry`)
  }
  console.log('ok spokes are mutually controllable through the one hub entry')
  assert.ok((await Promise.all(Array.from({ length: 4 }, () => ab.request('ping')))).every(reply => reply.pong === true))
  console.log('ok one spoke multiplexes concurrent authenticated tunnels')
  await assert.rejects(ab.request('exec', { cmd: 'must-never-run' }), /permission|ceiling/)
  await assert.rejects(ba.request('exec', { cmd: 'must-never-run' }), /permission|ceiling/)
  console.log('ok routing grants no target permission in any direction')
  await assert.rejects(ac.request('ping'), /denied|closed|refus|accept/i)
  await assert.rejects(bc.request('ping'), /denied|closed|refus|accept/i)
  console.log('ok a spoke that declares acceptInbound:false cannot be relayed to')
  await assert.rejects(alpha.open('delta'), /unknown|online|allowed|target|route|denied/i)
  await assert.rejects(delta.open('alpha'), /unknown|online|allowed|target|route|denied/i)
  console.log('ok a spoke outside the pair allowlist is unreachable in both directions')
  gamma.dispose()
  await until(() => !ac.connected, 'a disposed spoke must close its routed channels')
  assert.equal((await ba.request('ping')).pong, true)
  console.log('ok losing one spoke closes only its own tunnels and leaves the rest routable')
  console.log('ALL PASS: three-spoke radial topology on a single entry, closed by default outside the pair ACL')
} finally {
  for (const stop of cleanup.reverse()) { try { await stop() } catch {} }
  await delay(30)
  rmSync(home, { recursive: true, force: true })
  if (original === undefined) delete process.env.DSH_HOME; else process.env.DSH_HOME = original
}
