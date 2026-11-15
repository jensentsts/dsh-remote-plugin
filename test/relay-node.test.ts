/** Fake-channel mesh lifecycle tests: never touch a real profile, key, or host. */
import assert from 'node:assert/strict'
import { Duplex } from 'node:stream'
import type { Socket } from 'node:net'
import { Context } from '@deepseek-ai/cordis'
import { updateVolatile, createVolatile } from '@deepseek-ai/cosmokit'
import MeshService, { MeshNode, MeshConfigSchema, Config as ConfigSchema } from '../src/mesh.ts'
import type { Config, MeshChannel } from '../src/mesh.ts'

const id = '11111111-1111-4111-8111-111111111111'
const other = '22222222-2222-4222-8222-222222222222'
const tick = (): Promise<void> => new Promise(resolve => setImmediate(resolve))
const base = (): Config => ({ host: 'offline.invalid', port: 1, privateKey: 'fake-private', peerPublicKey: 'fake-hub-pin',
  autoGenerateKey: false, timeoutMs: 100, autoReconnect: false })
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
class FakeChannel implements MeshChannel {
  connected = true
  disposed = false
  calls: Array<{ op: string; args: Record<string, unknown>; retries?: number }> = []
  event: (frame: Record<string, unknown>) => void = () => {}
  disconnect: (error: Error) => void = () => {}
  handler: (op: string, args: Record<string, unknown>) => Promise<Record<string, unknown>> = async op => {
    if (op === 'relay.register') return { nodeId: 'alpha' }
    if (op === 'relay.open') return { tunnelId: id }
    if (op === 'relay.write') return { written: true }
    return { closed: true }
  }
  async request(op: string, args: Record<string, unknown> = {}, _timeout?: number, options: { retries?: number } = {}) {
    this.calls.push({ op, args, retries: options.retries })
    return await this.handler(op, args)
  }
  onEvent(handler: (frame: Record<string, unknown>) => void) { this.event = handler }
  onDisconnect(handler: (error: Error) => void) { this.disconnect = handler }
  lose() { this.connected = false; this.disconnect(new Error('fixture disconnect')) }
  dispose() { if (this.disposed) return; this.disposed = true; this.connected = false; this.disconnect(new Error('fixture disposed')) }
}
class LocalSocket extends Duplex {
  connecting = false
  writes: Buffer[] = []
  constructor() { super(); this.on('error', () => {}) }
  override _read() {}
  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void) { this.writes.push(Buffer.from(chunk)); callback() }
  setNoDelay() { return this }
  setTimeout() { return this }
  asSocket(): Socket { return this as unknown as Socket }
}
let checks = 0
async function check(name: string, body: () => unknown | Promise<unknown>) { await body(); checks++; console.log(`ok ${name}`) }

await check('no implicit hub address, no key generation, separate hub pin default', async () => {
  const config = MeshConfigSchema({})
  assert.equal(config.host, '')
  assert.equal(config.port, 0)
  assert.equal(config.autoGenerateKey, false)
  assert.equal(config.acceptInbound, false)
  assert.equal(config.targetPort, 11325)
  assert.match(config.peerPublicKeyFile!, /hub\.pub$/u)
  let created = 0
  const node = new MeshNode(() => config, () => {}, { createChannel() { created++; return new FakeChannel() } })
  await assert.rejects(node.open('beta'), /not configured/)
  assert.equal(created, 0)
  node.dispose()
  let blank = { ...base(), peerPublicKey: '', peerPublicKeyFile: '' }
  const noPin = new MeshNode(() => blank, () => {}, { createChannel() { created++; return new FakeChannel() } })
  await assert.rejects(noPin.open('beta'), /hub public-key pin is required/)
  assert.equal(created, 0)
  noPin.dispose()
})

await check('register completes before open; hub assigns identity; all mutations disable replay', async () => {
  const channel = new FakeChannel()
  const registration = deferred<Record<string, unknown>>()
  channel.handler = async op => op === 'relay.register' ? await registration.promise : { tunnelId: id }
  const node = new MeshNode(base, () => {}, { createChannel: () => channel })
  const opening = node.open('beta')
  assert.deepEqual(channel.calls.map(call => call.op), ['relay.register'])
  assert.deepEqual(channel.calls[0]!.args, {})
  registration.resolve({ nodeId: 'hub-assigned-alpha' })
  const socket = await opening
  assert.equal(node.status().nodeId, 'hub-assigned-alpha')
  assert.deepEqual(channel.calls.map(call => call.op), ['relay.register', 'relay.open'])
  assert.deepEqual(channel.calls[1]!.args, { target: 'beta' })
  assert.ok(channel.calls.every(call => call.retries === 0))
  socket.destroy(); node.dispose(); await tick()
})

await check('first data before open acknowledgement is retained with strict sequence', async () => {
  const channel = new FakeChannel()
  channel.handler = async op => {
    if (op === 'relay.register') return { nodeId: 'alpha' }
    if (op === 'relay.open') {
      channel.event({ kind: 'relay.data', tunnelId: id, seq: 1, dataB64: Buffer.from('first greeting').toString('base64') })
      return { tunnelId: id }
    }
    return { written: true, closed: true }
  }
  const node = new MeshNode(base, () => {}, { createChannel: () => channel })
  const socket = await node.open('beta')
  assert.equal(socket.read().toString(), 'first greeting')
  channel.event({ kind: 'relay.data', tunnelId: id, seq: 2, dataB64: 'YQ==' })
  assert.equal(socket.read().toString(), 'a')
  node.dispose(); await tick()
})

await check('early receive buffer cannot exceed 1 MiB or accept malformed sequence', async () => {
  for (const malformed of [false, true]) {
    const channel = new FakeChannel()
    channel.handler = async op => {
      if (op === 'relay.register') return { nodeId: 'alpha' }
      if (op === 'relay.open') {
        if (malformed) channel.event({ kind: 'relay.data', tunnelId: id, seq: 2, dataB64: 'YQ==' })
        else for (let seq = 1; seq <= 22; seq++) channel.event({ kind: 'relay.data', tunnelId: id, seq, dataB64: Buffer.alloc(48 * 1024).toString('base64') })
        return { tunnelId: id }
      }
      return { closed: true }
    }
    const node = new MeshNode(base, () => {}, { createChannel: () => channel })
    await assert.rejects(node.open('beta'), /closed|disconnected|cancelled/)
    assert.equal(channel.disposed, true)
    assert.equal(node.status().tunnels, 0)
    node.dispose()
  }
})

await check('inbound is off by default and only opaque bytes reach the fixed local port', async () => {
  const denied = new FakeChannel()
  let localCalls = 0
  const off = new MeshNode(base, () => {}, { createChannel: () => denied, connectLocal() { localCalls++; throw new Error('must not connect') } })
  await tick()
  denied.event({ kind: 'relay.offer', tunnelId: id, from: 'beta', host: 'external.invalid', port: 666 })
  await tick()
  assert.equal(localCalls, 0)
  assert.equal(denied.calls.at(-1)!.op, 'relay.close')
  off.dispose()
  const channel = new FakeChannel(), local = new LocalSocket()
  let port = 0
  const node = new MeshNode(() => ({ ...base(), acceptInbound: true, targetPort: 12345 }), () => {}, {
    createChannel: () => channel, connectLocal(value) { port = value; return local.asSocket() },
  })
  await tick()
  channel.event({ kind: 'relay.offer', tunnelId: id, from: 'beta', host: 'external.invalid', port: 666 })
  await tick(); await tick()
  assert.equal(port, 12345)
  assert.equal(channel.calls.filter(call => call.op === 'relay.accept').length, 1)
  const opaque = Buffer.from('{"op":"exec","cmd":"this is bytes, never RPC"}\0')
  channel.event({ kind: 'relay.data', tunnelId: id, seq: 1, dataB64: opaque.toString('base64') })
  await tick()
  assert.deepEqual(Buffer.concat(local.writes), opaque)
  local.push(Buffer.from('local opaque reply'))
  await tick(); await tick()
  assert.equal(Buffer.from(String(channel.calls.find(call => call.op === 'relay.write')!.args.dataB64), 'base64').toString(), 'local opaque reply')
  assert.equal(channel.calls.some(call => call.op === 'exec'), false)
  node.dispose(); await tick()
  assert.equal(local.destroyed, true)
})

await check('disconnect and settings rotation retire whole epochs without replay or stale callbacks', async () => {
  let current = base()
  const channels: FakeChannel[] = []
  const node = new MeshNode(() => current, () => {}, { createChannel() { const channel = new FakeChannel(); channels.push(channel); return channel } })
  const oldSocket = await node.open('beta')
  current = { ...current, peerPublicKey: 'rotated-pin' }
  node.refresh()
  assert.equal(channels[0]!.disposed, true)
  assert.equal(oldSocket.destroyed, true)
  const next = await node.open('beta')
  assert.equal(channels.length, 2)
  channels[0]!.event({ kind: 'relay.closed', tunnelId: id })
  assert.equal(next.destroyed, false)
  channels[1]!.lose()
  assert.equal(next.destroyed, true)
  assert.equal(node.status().registered, false)
  node.dispose(); await tick()
})

await check('invalid live settings fail closed instead of reusing the old valid hub identity', async () => {
  let current = base()
  let created = 0
  const node = new MeshNode(() => current, () => {}, { createChannel() { created++; return new FakeChannel() } })
  const socket = await node.open('beta')
  current = { ...current, maxSessionMs: 1 }
  node.refresh()
  assert.equal(socket.destroyed, true)
  await assert.rejects(node.open('beta'), /invalid mesh configuration/)
  assert.equal(created, 1)
  assert.equal(node.status().configured, false)
  current = base() // Restoring the very same original snapshot is valid again.
  node.refresh()
  const next = await node.open('beta')
  assert.equal(created, 2)
  next.destroy(); node.dispose(); await tick()
})

await check('disposal cancels stalled opens and capped reconnect timers permanently', async () => {
  const channel = new FakeChannel()
  const open = deferred<Record<string, unknown>>()
  channel.handler = async op => op === 'relay.register' ? { nodeId: 'alpha' } : await open.promise
  const node = new MeshNode(base, () => {}, { createChannel: () => channel })
  const pending = node.open('beta')
  await tick()
  node.dispose()
  await assert.rejects(pending, /cancelled|closed|disposed/)
  open.resolve({ tunnelId: id })
  assert.equal(channel.disposed, true)
  assert.equal(node.status().tunnels, 0)
  await assert.rejects(node.open('beta'), /disposed/)
  let count = 0
  const auto = new MeshNode(() => ({ ...base(), autoReconnect: true, reconnectMinMs: 100, reconnectMaxMs: 100 }), () => {}, {
    createChannel() { count++; return new FakeChannel() }, random: () => 1,
  })
  await tick()
  const epoch = auto as unknown as { epoch: { link: FakeChannel } }
  epoch.epoch.link.lose()
  assert.equal(auto.status().reconnectScheduled, true)
  auto.dispose()
  await new Promise<void>(resolve => setTimeout(resolve, 120))
  assert.equal(count, 1)
  assert.equal(auto.status().reconnectScheduled, false)
})

await check('Cordis exposes the service and root-volatile changes invalidate configuration', async () => {
  const ctx = new Context()
  const config = ConfigSchema({})
  const service = new MeshService(ctx, config)
  assert.ok(ctx.get('dshRemoteMesh') instanceof MeshService)
  assert.deepEqual(ctx.get('dshRemoteMesh')!.status(), service.status())
  assert.equal(service.status().configured, false)
  updateVolatile(config as never, createVolatile({ ...MeshConfigSchema({}), targetPort: 12345 }) as never)
  ctx.emit('loader/volatile-update', [[]])
  assert.equal(service.status().configured, false)
  service.dispose()
  await ctx.fiber.dispose()
  assert.equal(service.status().disposed, true)
})

console.log(`ALL PASS: ${checks} bounded mesh-node lifecycle groups`)
