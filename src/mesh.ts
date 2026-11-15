/** Outbound-only hub attachment. Relay payloads remain opaque end-to-end TCP. */
import { Service } from '@deepseek-ai/cordis'
import type { Context, Volatile } from '@deepseek-ai/cordis'
import { isVolatile } from '@deepseek-ai/cosmokit'
import z from '@deepseek-ai/schemastery'
import type {} from '@deepseek-ai/cordis-plugin-loader'
import { connect } from 'node:net'
import type { Socket } from 'node:net'
import { LinkClient } from './link.ts'
import type { EndpointConfig } from './link.ts'
import { raceAbort } from './async.ts'
import { dshHomePath } from './keys.ts'
import { RelaySocket, decodeRelayData, RELAY_RECEIVE_BYTES } from './relay-socket.ts'

export const name = 'dsh-remote-mesh'

export interface Config extends EndpointConfig {
  /** Accept only to the fixed local 127.0.0.1:targetPort. Disabled by default. */
  acceptInbound?: boolean
  targetPort?: number
  autoReconnect?: boolean
  reconnectMinMs?: number
  reconnectMaxMs?: number
}

/** Empty host/zero port mean unconfigured; there is no implicit network endpoint. */
export const MeshConfigSchema = z.object({
  host: z.string().default(''),
  port: z.number().step(1).min(0).max(65535).default(0),
  privateKey: z.string().role('secret').default(''),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.key')),
  autoGenerateKey: z.boolean().default(false),
  peerPublicKey: z.string().default(''),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'hub.pub')),
  timeoutMs: z.number().step(1).min(1).max(600000).default(15000),
  allowLegacyHandshake: z.boolean().default(false),
  maxSessionMs: z.number().step(1).min(100).max(3600000).default(3600000),
  acceptInbound: z.boolean().default(false),
  targetPort: z.number().step(1).min(1).max(65535).default(11325),
  autoReconnect: z.boolean().default(true),
  reconnectMinMs: z.number().step(1).min(100).max(60000).default(1000),
  reconnectMaxMs: z.number().step(1).min(100).max(60000).default(30000),
}).default({})

/** Root volatility makes the settings page editable without retaining old trust. */
export const Config = MeshConfigSchema.volatile()

declare module '@deepseek-ai/cordis' {
  interface Context { dshRemoteMesh: MeshService }
}

export interface MeshChannel {
  readonly connected: boolean
  request(op: string, args?: Record<string, unknown>, timeoutMs?: number, options?: { retries?: number }): Promise<Record<string, unknown>>
  onEvent(handler: (frame: Record<string, unknown>) => void): void
  onDisconnect(handler: (error: Error) => void): void
  dispose(): void
}

/** Only tests replace these seams; production always uses LinkClient and loopback. */
export interface MeshDependencies {
  createChannel?: (config: EndpointConfig) => MeshChannel
  connectLocal?: (port: number) => Socket
  random?: () => number
}

interface EarlyTunnel {
  chunks: Array<{ seq: number; bytes: Buffer }>
  next: number
  closed?: string
}
interface Epoch {
  readonly link: MeshChannel
  readonly config: Config
  readonly abort: AbortController
  readonly tunnels: Map<string, RelaySocket>
  readonly locals: Set<Socket>
  readonly incoming: Set<string>
  readonly early: Map<string, EarlyTunnel>
  earlyBytes: number
  earlyFrames: number
  pendingOpens: number
  retired: boolean
  registered: boolean
  nodeId?: string
  registration?: Promise<void>
}

const MAX_TUNNELS = 16
const MAX_EARLY_FRAMES = 1024
const TUNNEL_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
function nodeName(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9._-]{2,128}$/u.test(value)
    && !['rmt', '.', '..', '__proto__', 'constructor', 'prototype'].includes(value.toLowerCase())
}
function errorOf(value: unknown): Error { return value instanceof Error ? value : new Error('mesh operation failed') }
function configured(config: Config): boolean { return typeof config.host === 'string' && config.host.trim() !== '' && (config.port ?? 0) > 0 }

/**
 * One connection generation owns registration and every tunnel it created. Lost
 * generations are permanently disposed; relay mutations never cross a redial.
 */
export class MeshNode {
  private readonly read: () => Config
  private readonly log: (message: string) => void
  private readonly dependencies: MeshDependencies
  private current: Config
  private configId: string
  private invalidConfig = false
  private epoch: Epoch | undefined
  private disposed = false
  private failures = 0
  private reconnectTimer: ReturnType<typeof setTimeout> | undefined
  private lastError: string | undefined

  constructor(read: () => Config, log: (message: string) => void = () => {}, dependencies: MeshDependencies = {}) {
    this.read = read
    this.log = log
    this.dependencies = dependencies
    this.current = this.validate(read())
    this.configId = JSON.stringify(this.current)
    this.start()
  }

  private validate(input: Config): Config {
    const value = MeshConfigSchema(input)
    if ((value.reconnectMinMs ?? 1000) > (value.reconnectMaxMs ?? 30000)) throw new Error('mesh reconnect minimum exceeds maximum')
    // A mesh channel may only dial the hub itself, never recursively route itself.
    if (value.relayTarget !== undefined && value.relayTarget !== '') throw new Error('mesh hub cannot itself be a relay target')
    return value
  }

  /** Committed settings changes synchronously invalidate every old key/channel. */
  refresh(): void {
    if (this.disposed) return
    let value: Config
    try { value = this.validate(this.read()) }
    catch (error) {
      this.invalidConfig = true
      this.clearReconnect()
      if (this.epoch !== undefined) this.retire(this.epoch, errorOf(error), false)
      this.lastError = 'invalid mesh configuration'
      return
    }
    const identity = JSON.stringify(value)
    if (!this.invalidConfig && identity === this.configId) return
    this.invalidConfig = false
    this.configId = identity
    this.current = value
    this.failures = 0
    this.lastError = undefined
    this.clearReconnect()
    if (this.epoch !== undefined) this.retire(this.epoch, new Error('mesh configuration changed'), false)
    this.start()
  }

  private start(): void {
    if (this.disposed || this.invalidConfig || !configured(this.current) || this.epoch !== undefined || this.reconnectTimer !== undefined) return
    void this.ensureRegistered().catch(() => {})
  }

  private createEpoch(): Epoch {
    if (this.disposed) throw new Error('mesh disposed')
    if (this.invalidConfig) throw new Error('invalid mesh configuration')
    const config = this.current
    if (!configured(config)) throw new Error('mesh hub host and port are not configured')
    if (!(config.peerPublicKey?.trim()) && !(config.peerPublicKeyFile?.trim())) throw new Error('mesh hub public-key pin is required')
    const link = this.dependencies.createChannel?.(config)
      ?? new LinkClient(() => config, message => this.log(message), 'dsh-remote-mesh hub')
    const epoch: Epoch = { link, config, abort: new AbortController(), tunnels: new Map(), locals: new Set(), incoming: new Set(),
      early: new Map(), earlyBytes: 0, earlyFrames: 0, pendingOpens: 0, retired: false, registered: false }
    this.epoch = epoch
    link.onDisconnect(error => { this.retire(epoch, error) })
    link.onEvent(frame => {
      try {
        this.refresh()
        if (!epoch.retired && this.epoch === epoch) this.event(epoch, frame)
      } catch (error) { this.retire(epoch, errorOf(error)) }
    })
    return epoch
  }

  private assertEpoch(epoch: Epoch): void {
    if (this.disposed || epoch.retired || this.epoch !== epoch || epoch.abort.signal.aborted) throw new Error('mesh hub connection closed')
  }

  private async rpc(epoch: Epoch, op: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    this.assertEpoch(epoch)
    // After registration, never let LinkClient ensure() silently create a fresh
    // unregistered channel between this tunnel's writes.
    if (epoch.registered && !epoch.link.connected) {
      this.retire(epoch, new Error('mesh hub disconnected'))
      throw new Error('mesh hub disconnected')
    }
    try {
      const work = epoch.link.request(op, args, epoch.config.timeoutMs ?? 15000, { retries: 0 })
      const result = await raceAbort(work, epoch.abort.signal)
      this.assertEpoch(epoch)
      return result
    } catch (error) {
      if (!epoch.retired && !epoch.link.connected) this.retire(epoch, errorOf(error))
      throw error
    }
  }

  private async ensureRegistered(): Promise<Epoch> {
    if (this.disposed) throw new Error('mesh disposed')
    this.clearReconnect()
    const epoch = this.epoch ?? this.createEpoch()
    if (epoch.registration === undefined) {
      epoch.registration = (async () => {
        try {
          const result = await this.rpc(epoch, 'relay.register')
          if (!nodeName(result.nodeId)) throw new Error('invalid mesh registration response')
          this.assertEpoch(epoch)
          epoch.nodeId = result.nodeId
          epoch.registered = true
          this.failures = 0
          this.lastError = undefined
        } catch (error) { this.retire(epoch, errorOf(error)); throw error }
      })()
      void epoch.registration.catch(() => {})
    }
    await epoch.registration
    this.assertEpoch(epoch)
    return epoch
  }

  /** Return only transport bytes. The caller still authenticates its target pin. */
  async open(target: string): Promise<Socket> {
    this.refresh()
    if (!nodeName(target)) throw new Error('invalid mesh target identity')
    const epoch = await this.ensureRegistered()
    if (epoch.tunnels.size + epoch.pendingOpens >= MAX_TUNNELS) throw new Error('too many mesh tunnels')
    epoch.pendingOpens += 1
    let socket: RelaySocket | undefined
    try {
      const result = await this.rpc(epoch, 'relay.open', { target })
      this.assertEpoch(epoch)
      if (typeof result.tunnelId !== 'string' || !TUNNEL_ID.test(result.tunnelId) || epoch.tunnels.has(result.tunnelId)) {
        this.retire(epoch, new Error('invalid mesh open response'))
        throw new Error('invalid mesh open response')
      }
      socket = this.attach(epoch, result.tunnelId)
      const early = epoch.early.get(result.tunnelId)
      if (early !== undefined) {
        epoch.early.delete(result.tunnelId)
        for (const chunk of early.chunks) {
          epoch.earlyBytes -= chunk.bytes.length
          epoch.earlyFrames -= 1
          socket.receiveChunk(chunk.seq, chunk.bytes)
        }
        if (early.closed !== undefined) socket.remoteClosed(early.closed)
      }
      if (socket.destroyed) throw new Error('mesh tunnel closed before open completed')
      return socket.asSocket()
    } catch (error) { socket?.destroy(errorOf(error)); throw error }
    finally {
      epoch.pendingOpens -= 1
      if (epoch.pendingOpens === 0) { epoch.early.clear(); epoch.earlyBytes = 0; epoch.earlyFrames = 0 }
    }
  }

  private attach(epoch: Epoch, tunnelId: string): RelaySocket {
    const socket = new RelaySocket(tunnelId, { request: (op, args) => this.rpc(epoch, op, args) })
    epoch.tunnels.set(tunnelId, socket)
    socket.once('close', () => { if (epoch.tunnels.get(tunnelId) === socket) epoch.tunnels.delete(tunnelId) })
    return socket
  }

  private event(epoch: Epoch, frame: Record<string, unknown>): void {
    const { kind, tunnelId } = frame
    if (!['relay.offer', 'relay.data', 'relay.closed'].includes(String(kind))
      || typeof tunnelId !== 'string' || !TUNNEL_ID.test(tunnelId)) throw new Error('invalid mesh event')
    if (kind === 'relay.offer') {
      if (!nodeName(frame.from) || epoch.tunnels.has(tunnelId) || epoch.incoming.has(tunnelId)) throw new Error('invalid mesh offer')
      if (epoch.config.acceptInbound !== true || epoch.tunnels.size + epoch.pendingOpens >= MAX_TUNNELS) {
        this.closeOffered(epoch, tunnelId)
        return
      }
      // Reserve admission synchronously, before any asynchronous connect/accept.
      epoch.incoming.add(tunnelId)
      const relay = this.attach(epoch, tunnelId)
      void this.accept(epoch, relay).catch(() => { relay.destroy(new Error('mesh local target unavailable')) })
        .finally(() => { epoch.incoming.delete(tunnelId) })
      return
    }
    const socket = epoch.tunnels.get(tunnelId)
    if (socket !== undefined) {
      if (kind === 'relay.data') socket.receive(frame.seq, frame.dataB64)
      else socket.remoteClosed('relay tunnel closed')
      return
    }
    // A target can send after accept before relay.open's reply is resumed by the
    // source. Keep only a small bounded decoded backlog during that exact window.
    if (epoch.pendingOpens === 0) return // spent event from an already-closed tunnel
    let early = epoch.early.get(tunnelId)
    if (early === undefined) {
      if (epoch.early.size >= MAX_TUNNELS) throw new Error('too many early mesh tunnels')
      early = { chunks: [], next: 1 }
      epoch.early.set(tunnelId, early)
    }
    if (kind === 'relay.closed') { early.closed = 'relay tunnel closed'; return }
    if (early.closed !== undefined || !Number.isSafeInteger(frame.seq) || frame.seq !== early.next) throw new Error('invalid early mesh sequence')
    const bytes = decodeRelayData(frame.dataB64)
    if (epoch.earlyBytes + bytes.length > RELAY_RECEIVE_BYTES || epoch.earlyFrames >= MAX_EARLY_FRAMES) throw new Error('early mesh receive buffer exceeded')
    early.next += 1
    early.chunks.push({ seq: frame.seq as number, bytes })
    epoch.earlyBytes += bytes.length
    epoch.earlyFrames += 1
  }

  private closeOffered(epoch: Epoch, tunnelId: string): void {
    void this.rpc(epoch, 'relay.close', { tunnelId }).catch(() => {})
  }

  private async accept(epoch: Epoch, relay: RelaySocket): Promise<void> {
    // This side's own registration must have completed before accepting offers.
    await epoch.registration
    this.assertEpoch(epoch)
    if (relay.destroyed) return
    const local = this.dependencies.connectLocal?.(epoch.config.targetPort ?? 11325)
      ?? connect({ host: '127.0.0.1', port: epoch.config.targetPort ?? 11325 })
    epoch.locals.add(local)
    relay.once('close', () => { local.destroy() })
    local.on('error', () => { relay.destroy(new Error('mesh local target failed')) })
    local.once('close', () => { epoch.locals.delete(local); relay.destroy() })
    try {
      await this.waitLocal(epoch, local)
      this.assertEpoch(epoch)
      if (relay.destroyed) throw new Error('mesh offer closed')
      local.setNoDelay(true)
      local.setTimeout(0)
      // Install hub->local delivery before accept; hold local->hub greeting bytes
      // until accept ACK, because the hub does not admit pending-tunnel writes.
      relay.pipe(local)
      await this.rpc(epoch, 'relay.accept', { tunnelId: relay.tunnelId })
      this.assertEpoch(epoch)
      if (relay.destroyed || local.destroyed) throw new Error('mesh offer closed')
      local.pipe(relay)
    } catch (error) { local.destroy(); throw error }
  }

  private async waitLocal(epoch: Epoch, socket: Socket): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      let settled = false
      const finish = (error?: Error): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        socket.off('connect', connected); socket.off('error', failed); socket.off('close', closed)
        epoch.abort.signal.removeEventListener('abort', closed)
        if (error === undefined) resolve(); else reject(error)
      }
      const connected = (): void => finish()
      const failed = (): void => finish(new Error('mesh local target connect failed'))
      const closed = (): void => finish(new Error('mesh local target closed'))
      const timer = setTimeout(() => { finish(new Error('mesh local target connect timed out')); socket.destroy() }, Math.min(epoch.config.timeoutMs ?? 15000, 10000))
      timer.unref?.()
      socket.once('connect', connected); socket.once('error', failed); socket.once('close', closed)
      epoch.abort.signal.addEventListener('abort', closed, { once: true })
      if (socket.destroyed || epoch.abort.signal.aborted) closed()
      else if (!socket.connecting) connected()
    })
  }

  private retire(epoch: Epoch, error: Error, reconnect = true): void {
    if (epoch.retired) return
    epoch.retired = true
    if (this.epoch === epoch) this.epoch = undefined
    epoch.abort.abort()
    epoch.registered = false
    epoch.early.clear(); epoch.earlyBytes = 0; epoch.earlyFrames = 0
    for (const socket of epoch.tunnels.values()) socket.remoteClosed('mesh hub disconnected')
    epoch.tunnels.clear()
    for (const socket of epoch.locals) socket.destroy()
    epoch.locals.clear(); epoch.incoming.clear()
    epoch.link.dispose()
    this.lastError = error.message.slice(0, 240)
    if (reconnect) this.scheduleReconnect()
  }

  private scheduleReconnect(): void {
    if (this.disposed || this.invalidConfig || this.current.autoReconnect === false || !configured(this.current) || this.reconnectTimer !== undefined) return
    const min = this.current.reconnectMinMs ?? 1000, max = this.current.reconnectMaxMs ?? 30000
    const ceiling = Math.min(max, min * 2 ** Math.min(this.failures++, 10))
    const random = this.dependencies.random?.() ?? Math.random()
    const jitter = Number.isFinite(random) ? Math.max(0, Math.min(1, random)) : 0.5
    const delay = Math.max(min, Math.min(max, Math.floor(ceiling * (0.75 + jitter * 0.25))))
    this.reconnectTimer = setTimeout(() => { this.reconnectTimer = undefined; this.start() }, delay)
    this.reconnectTimer.unref?.()
  }
  private clearReconnect(): void {
    if (this.reconnectTimer !== undefined) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = undefined
  }

  /** No keys, pins, private config, or raw RPC payloads are exposed. */
  status(): Record<string, unknown> {
    this.refresh()
    const epoch = this.epoch
    return { configured: !this.invalidConfig && configured(this.current), connected: epoch?.link.connected === true,
      registered: epoch?.registered === true, nodeId: epoch?.nodeId ?? null, tunnels: epoch?.tunnels.size ?? 0,
      pendingOpens: epoch?.pendingOpens ?? 0, inbound: epoch?.incoming.size ?? 0,
      reconnectScheduled: this.reconnectTimer !== undefined, disposed: this.disposed,
      ...(this.lastError === undefined ? {} : { error: this.lastError }) }
  }

  /** Permanent: every timer, local dial, parked open and virtual stream is released. */
  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.clearReconnect()
    if (this.epoch !== undefined) this.retire(this.epoch, new Error('mesh disposed'), false)
  }
}

/** Cordis-owned registration; service removal also permanently retires transport. */
export class MeshService extends Service {
  static Config = Config
  private readonly node: MeshNode
  constructor(ctx: Context, config: Config | Volatile<Config> = {}) {
    super(ctx, 'dshRemoteMesh')
    const read = (): Config => isVolatile(config) ? config.get() : config
    this.node = new MeshNode(read, message => ctx.logger.info(message))
    ctx.on('loader/volatile-update', () => { this.node.refresh() })
    ctx.effect(() => () => { this.dispose() }, 'dsh-remote-mesh: close hub and tunnels')
  }
  open(target: string): Promise<Socket> { return this.node.open(target) }
  status(): Record<string, unknown> { return this.node.status() }
  dispose(): void { this.node.dispose() }
}
export default MeshService
