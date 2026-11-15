/** Opaque, bounded byte routing. The outer authenticated controller supplies all
 * identity; the inner DSHR2 handshake and RPC authority stay at the endpoints.
 * Nothing here decrypts, interprets, retries or replays a relayed byte stream. */
import { randomUUID } from 'node:crypto'
import type { Session } from './protocol.ts'
import { boundedInteger } from './network-guard.ts'

export type RelayOperation = 'relay.register' | 'relay.open' | 'relay.accept' | 'relay.write' | 'relay.close' | 'relay.status'
export interface RelayOwner {
  session: Pick<Session, 'send'>
  principal: string
  name: string
  multi: boolean
}
export interface RelayPolicy { targets: readonly string[] }
export interface RelayHubLimits {
  maxNodes?: number
  maxTunnels?: number
  maxTunnelsPerPrincipal?: number
  maxPendingBytes?: number
  maxPendingSends?: number
  openTimeoutMs?: number
  idleTimeoutMs?: number
  sendTimeoutMs?: number
  sweepIntervalMs?: number
}
export interface RelayHubOptions {
  /** Must synchronously revalidate the live profile and this exact operation. */
  authorize(owner: RelayOwner, op: RelayOperation): RelayPolicy
  limits?: RelayHubLimits
  now?: () => number
}
export const RELAY_MAX_BLOCK_BYTES = 48 * 1024
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u
const RESERVED = new Set(['rmt', '__proto__', 'constructor', 'prototype', '.', '..'])
function validName(name: unknown): name is string {
  return typeof name === 'string' && /^[A-Za-z0-9._-]{2,128}$/u.test(name) && !RESERVED.has(name.toLowerCase())
}
function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('relay: arguments must be an object')
  return value as Record<string, unknown>
}
function tunnelId(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new Error('relay: invalid tunnel id')
  return value
}
/** Check encoded length before allocating, and canonical padding bits afterward. */
function blockBytes(value: unknown): number {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4 * Math.ceil(RELAY_MAX_BLOCK_BYTES / 3)
    || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) throw new Error('relay: invalid or oversized canonical base64 block')
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length > RELAY_MAX_BLOCK_BYTES || bytes.toString('base64') !== value) throw new Error('relay: invalid or oversized canonical base64 block')
  return bytes.length
}
interface Holder {
  owner: RelayOwner
  session: RelayOwner['session']
  principal: string
  name: string
}
interface Tunnel {
  id: string
  source: Holder
  target: Holder
  state: 'opening' | 'open'
  deadline: number
  touched: number
  sourceSeq: number
  targetSeq: number
  resolve(value: { tunnelId: string }): void
  reject(error: Error): void
}
interface PendingSend {
  tunnelId: string
  session: RelayOwner['session']
  bytes: number
  cancel(error: Error): void
}

/** One live registration per name AND proven key, never transferred on reconnect. */
export class RelayHub {
  private readonly options: RelayHubOptions
  private readonly now: () => number
  private readonly limits: Required<RelayHubLimits>
  private readonly holders = new Map<RelayOwner['session'], Holder>()
  private readonly names = new Map<string, Holder>()
  private readonly principals = new Map<string, Holder>()
  private readonly tunnels = new Map<string, Tunnel>()
  private readonly pending = new Set<PendingSend>()
  private pendingBytes = 0
  private disposed = false
  private readonly timer: ReturnType<typeof setInterval>

  constructor(options: RelayHubOptions) {
    if (typeof options?.authorize !== 'function') throw new Error('relay: a live authorization callback is required')
    this.options = options
    this.now = options.now ?? Date.now
    const l = options.limits ?? {}
    this.limits = {
      maxNodes: boundedInteger(l.maxNodes, 128, 1, 128),
      maxTunnels: boundedInteger(l.maxTunnels, 128, 1, 128),
      maxTunnelsPerPrincipal: boundedInteger(l.maxTunnelsPerPrincipal, 16, 1, 16),
      maxPendingBytes: boundedInteger(l.maxPendingBytes, 1024 * 1024, 1, 1024 * 1024),
      maxPendingSends: boundedInteger(l.maxPendingSends, 128, 1, 128),
      openTimeoutMs: boundedInteger(l.openTimeoutMs, 15_000, 1, 15_000),
      idleTimeoutMs: boundedInteger(l.idleTimeoutMs, 600_000, 1, 600_000),
      sendTimeoutMs: boundedInteger(l.sendTimeoutMs, 15_000, 1, 15_000),
      sweepIntervalMs: boundedInteger(l.sweepIntervalMs, 250, 1, 1000),
    }
    this.timer = setInterval(() => this.sweep(), Math.min(this.limits.sweepIntervalMs, this.limits.openTimeoutMs, this.limits.idleTimeoutMs))
    this.timer.unref?.()
  }

  private active(): void { if (this.disposed) throw new Error('relay: hub is disposed') }
  private same(holder: Holder, owner: RelayOwner): boolean {
    return owner.session === holder.session && owner.principal === holder.principal && owner.name === holder.name && owner.multi === true
  }
  private policy(holder: Holder, op: RelayOperation): readonly string[] {
    try {
      if (!this.same(holder, holder.owner) || this.holders.get(holder.session) !== holder) throw new Error()
      const policy = this.options.authorize(holder.owner, op)
      if (!policy || !Array.isArray(policy.targets) || policy.targets.length > 64) throw new Error()
      const seen = new Set<string>()
      for (const target of policy.targets) {
        if (!validName(target) || seen.has(target.toLowerCase())) throw new Error()
        seen.add(target.toLowerCase())
      }
      return [...policy.targets]
    } catch {
      this.drop(holder, 'authorization revoked')
      throw new Error('relay: authorization denied')
    }
  }
  private owned(owner: RelayOwner, op: RelayOperation): Holder {
    this.active()
    const holder = this.holders.get(owner?.session)
    if (holder === undefined || !this.same(holder, owner)) throw new Error('relay: this authenticated session is not registered')
    this.policy(holder, op)
    return holder
  }
  private route(tunnel: Tunnel): void {
    const source = this.policy(tunnel.source, 'relay.open')
    const target = this.policy(tunnel.target, 'relay.accept')
    if (!source.includes(tunnel.target.name) || !target.includes(tunnel.source.name)) {
      this.finish(tunnel, 'route no longer authorized')
      throw new Error('relay: route requires both exact target allowlists')
    }
  }
  private expired(tunnel: Tunnel): boolean {
    const now = this.now()
    if (tunnel.state === 'opening' ? now >= tunnel.deadline : now - tunnel.touched >= this.limits.idleTimeoutMs) {
      this.finish(tunnel, tunnel.state === 'opening' ? 'accept deadline exceeded' : 'idle deadline exceeded')
      return true
    }
    return false
  }
  private member(owner: RelayOwner, args: Record<string, unknown>, op: RelayOperation): { holder: Holder, tunnel: Tunnel } {
    const holder = this.owned(owner, op)
    const tunnel = this.tunnels.get(tunnelId(args.tunnelId))
    if (tunnel === undefined || (tunnel.source !== holder && tunnel.target !== holder)) throw new Error('relay: tunnel is not owned by this registered session')
    if (this.expired(tunnel)) throw new Error('relay: tunnel deadline exceeded')
    this.route(tunnel)
    return { holder, tunnel }
  }

  register(owner: RelayOwner): { nodeId: string } {
    this.active()
    this.sweep()
    if (!owner || owner.multi !== true || !validName(owner.name) || typeof owner.principal !== 'string' || owner.principal.length === 0
      || owner.principal.length > 256 || !owner.session || typeof owner.session.send !== 'function') throw new Error('relay: a named, proven multi-controller identity is required')
    const current = this.holders.get(owner.session)
    if (current !== undefined) {
      if (!this.same(current, owner)) throw new Error('relay: registration identity cannot change')
      this.policy(current, 'relay.register')
      return { nodeId: current.name }
    }
    if (this.names.has(owner.name.toLowerCase()) || this.principals.has(owner.principal)) throw new Error('relay: a live node registration cannot be taken over')
    if (this.holders.size >= this.limits.maxNodes) throw new Error('relay: node registration budget exceeded')
    const holder: Holder = { owner, session: owner.session, principal: owner.principal, name: owner.name }
    this.holders.set(holder.session, holder)
    this.names.set(holder.name.toLowerCase(), holder)
    this.principals.set(holder.principal, holder)
    this.policy(holder, 'relay.register')
    return { nodeId: holder.name }
  }

  open(owner: RelayOwner, value: unknown): Promise<{ tunnelId: string }> {
    // Return a rejected Promise, not a synchronous throw, for the async API.
    try {
      this.sweep()
      const source = this.owned(owner, 'relay.open')
      const args = record(value)
      if (!validName(args.target)) throw new Error('relay: invalid target node')
      const target = this.names.get(args.target.toLowerCase())
      if (target === undefined || target.name !== args.target || target === source) throw new Error('relay: target is unavailable')
      const sourceTargets = this.policy(source, 'relay.open')
      const targetTargets = this.policy(target, 'relay.accept')
      if (!sourceTargets.includes(target.name) || !targetTargets.includes(source.name)) throw new Error('relay: route requires both exact target allowlists')
      if (this.tunnels.size >= this.limits.maxTunnels || [source, target].some(holder => this.count(holder) >= this.limits.maxTunnelsPerPrincipal)) {
        throw new Error('relay: tunnel budget exceeded')
      }
      let resolve!: Tunnel['resolve']; let reject!: Tunnel['reject']
      const result = new Promise<{ tunnelId: string }>((yes, no) => { resolve = yes; reject = no })
      // Cleanup may reject before the transport caller attaches its await.
      void result.catch(() => {})
      const now = this.now()
      const tunnel: Tunnel = { id: randomUUID(), source, target, state: 'opening', deadline: now + this.limits.openTimeoutMs,
        touched: now, sourceSeq: 0, targetSeq: 0, resolve, reject }
      this.tunnels.set(tunnel.id, tunnel)
      void this.send(target, { kind: 'relay.offer', tunnelId: tunnel.id, from: source.name }, tunnel.id)
        .catch(() => this.finish(tunnel, 'offer delivery failed'))
      return result
    } catch (error) { return Promise.reject(error) }
  }

  async accept(owner: RelayOwner, value: unknown): Promise<{ accepted: true }> {
    const { holder, tunnel } = this.member(owner, record(value), 'relay.accept')
    if (holder !== tunnel.target || tunnel.state !== 'opening') throw new Error('relay: only the offered target may accept once')
    tunnel.state = 'open'
    tunnel.touched = this.now()
    tunnel.resolve({ tunnelId: tunnel.id })
    return { accepted: true }
  }

  async write(owner: RelayOwner, value: unknown): Promise<{ written: true }> {
    const args = record(value)
    const { holder, tunnel } = this.member(owner, args, 'relay.write')
    try {
      if (tunnel.state !== 'open') throw new Error('relay: tunnel is not accepted')
      const key = holder === tunnel.source ? 'sourceSeq' : 'targetSeq'
      if (!Number.isSafeInteger(args.seq) || (args.seq as number) < 1 || tunnel[key] >= Number.MAX_SAFE_INTEGER || args.seq !== tunnel[key] + 1) {
        throw new Error('relay: sequence must increase by exactly one')
      }
      blockBytes(args.dataB64)
      // Admission and sequence commitment precede the first await. Session.send
      // preserves this order and supplies bounded socket backpressure.
      tunnel[key] = args.seq as number
      tunnel.touched = this.now()
      const destination = holder === tunnel.source ? tunnel.target : tunnel.source
      await this.send(destination, { kind: 'relay.data', tunnelId: tunnel.id, seq: args.seq, dataB64: args.dataB64 }, tunnel.id)
      if (this.tunnels.get(tunnel.id) !== tunnel) throw new Error('relay: tunnel closed during write')
      this.route(tunnel)
      return { written: true }
    } catch (error) {
      this.finish(tunnel, 'write failed')
      throw error
    }
  }

  async close(owner: RelayOwner, value: unknown): Promise<{ closed: boolean }> {
    const holder = this.owned(owner, 'relay.close')
    const id = tunnelId(record(value).tunnelId)
    const tunnel = this.tunnels.get(id)
    if (tunnel === undefined) return { closed: false }
    if (tunnel.source !== holder && tunnel.target !== holder) throw new Error('relay: tunnel is not owned by this registered session')
    this.finish(tunnel, 'closed by endpoint')
    return { closed: true }
  }

  status(owner: RelayOwner): Record<string, unknown> {
    this.sweep()
    const holder = this.owned(owner, 'relay.status')
    const allowed = this.policy(holder, 'relay.open')
    const targets: string[] = []
    for (const candidate of this.holders.values()) {
      if (candidate === holder || !allowed.includes(candidate.name)) continue
      try { if (this.policy(candidate, 'relay.accept').includes(holder.name)) targets.push(candidate.name) } catch { /* fail closed */ }
    }
    return { nodeId: holder.name, targets: targets.sort(), tunnels: [...this.tunnels.values()]
      .filter(tunnel => tunnel.source === holder || tunnel.target === holder)
      .map(tunnel => ({ tunnelId: tunnel.id, target: tunnel.source === holder ? tunnel.target.name : tunnel.source.name, state: tunnel.state })) }
  }

  /** Transport lifetime is session-local, not a same-key reconnect's lifetime. */
  detach(session: RelayOwner['session']): void {
    const holder = this.holders.get(session)
    if (holder !== undefined) this.drop(holder, 'endpoint disconnected')
  }
  revoke(principal: string): void {
    const holder = this.principals.get(principal)
    if (holder !== undefined) this.drop(holder, 'authorization revoked')
  }
  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    clearInterval(this.timer)
    for (const tunnel of this.tunnels.values()) this.finish(tunnel, 'hub disposed')
    this.holders.clear(); this.names.clear(); this.principals.clear()
    for (const pending of this.pending) pending.cancel(new Error('relay: hub disposed'))
  }

  private count(holder: Holder): number {
    let count = 0
    for (const tunnel of this.tunnels.values()) if (tunnel.source.principal === holder.principal || tunnel.target.principal === holder.principal) count++
    return count
  }
  private drop(holder: Holder, reason: string): void {
    if (this.holders.get(holder.session) !== holder) return
    this.holders.delete(holder.session)
    this.names.delete(holder.name.toLowerCase())
    this.principals.delete(holder.principal)
    for (const tunnel of this.tunnels.values()) if (tunnel.source === holder || tunnel.target === holder) this.finish(tunnel, reason)
    for (const pending of this.pending) if (pending.session === holder.session) pending.cancel(new Error('relay: endpoint disconnected'))
  }
  private finish(tunnel: Tunnel, reason: string): void {
    if (this.tunnels.get(tunnel.id) !== tunnel) return
    this.tunnels.delete(tunnel.id)
    tunnel.reject(new Error(`relay: ${reason}`))
    for (const pending of this.pending) if (pending.tunnelId === tunnel.id) pending.cancel(new Error(`relay: ${reason}`))
    for (const holder of [tunnel.source, tunnel.target]) {
      if (this.holders.get(holder.session) !== holder) continue
      void this.send(holder, { kind: 'relay.closed', tunnelId: tunnel.id, reason }, tunnel.id).catch(() => {})
    }
  }
  private sweep(): void {
    if (this.disposed) return
    for (const holder of this.holders.values()) { try { this.policy(holder, 'relay.register') } catch { /* cleanup in policy */ } }
    for (const tunnel of this.tunnels.values()) {
      if (this.expired(tunnel)) continue
      try { this.route(tunnel) } catch { this.finish(tunnel, 'authorization revoked') }
    }
  }
  private send(holder: Holder, event: Record<string, unknown>, id: string): Promise<void> {
    const bytes = Buffer.byteLength(JSON.stringify(event), 'utf8')
    if (this.pending.size >= this.limits.maxPendingSends || this.pendingBytes + bytes > this.limits.maxPendingBytes) return Promise.reject(new Error('relay: pending send budget exceeded'))
    let resolve!: () => void; let reject!: (error: Error) => void
    const result = new Promise<void>((yes, no) => { resolve = yes; reject = no })
    let finished = false
    const settle = (error?: Error): void => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      if (error === undefined) resolve(); else reject(error)
    }
    const pending: PendingSend = { tunnelId: id, session: holder.session, bytes, cancel: error => settle(error) }
    // Reservations survive a cancelled waiter until Session.send settles. A
    // hung transport cannot regain a budget by rapidly opening/closing tunnels.
    const release = (): void => { if (this.pending.delete(pending)) this.pendingBytes -= bytes }
    const timer = setTimeout(() => settle(new Error('relay: send deadline exceeded')), this.limits.sendTimeoutMs)
    timer.unref?.()
    this.pending.add(pending); this.pendingBytes += bytes
    try {
      Promise.resolve(holder.session.send(event)).then(() => { release(); settle() }, () => { release(); settle(new Error('relay: event delivery failed')) })
    } catch { release(); settle(new Error('relay: event delivery failed')) }
    return result
  }
}
