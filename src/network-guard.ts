/** Bounded inbound admission and envelope checks. No runtime or filesystem state. */
export interface NetworkSettings {
  maxConnections?: number
  maxPendingHandshakes?: number
  maxConnectionsPerAddress?: number
  maxHandshakesPerMinute?: number
  maxTrackedAddresses?: number
  maxHandshakeFailures?: number
  lockoutSeconds?: number
  handshakeTimeoutMs?: number
  maxInFlightPerPrincipal?: number
  maxSessionMs?: number
}

/** Invalid tuning values never disable a security budget. */
export function boundedInteger(value: unknown, fallback: number, min: number, max: number): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(min, Math.min(max, Math.trunc(value))) : fallback
}

export function networkLimits(settings: NetworkSettings) {
  return {
    maxConnections: boundedInteger(settings.maxConnections, 64, 1, 1024),
    maxPendingHandshakes: boundedInteger(settings.maxPendingHandshakes, 8, 1, 128),
    maxConnectionsPerAddress: boundedInteger(settings.maxConnectionsPerAddress, 16, 1, 256),
    maxHandshakesPerMinute: boundedInteger(settings.maxHandshakesPerMinute, 120, 1, 6000),
    maxTrackedAddresses: boundedInteger(settings.maxTrackedAddresses, 1024, 16, 65536),
    maxHandshakeFailures: boundedInteger(settings.maxHandshakeFailures, 8, 1, 100),
    lockoutMs: boundedInteger(settings.lockoutSeconds, 900, 1, 86400) * 1000,
    handshakeTimeoutMs: boundedInteger(settings.handshakeTimeoutMs, 15000, 50, 60000),
    maxInFlightPerPrincipal: boundedInteger(settings.maxInFlightPerPrincipal, 16, 1, 128),
    maxSessionMs: boundedInteger(settings.maxSessionMs, 3600000, 100, 3600000),
  }
}

type AddressBudget = { tokens: number, refilled: number, lastSeen: number, failures: number, firstFailure: number, lockedUntil: number }
export interface AdmissionLease {
  authenticated(): void
  failed(): void
  release(): void
}

/** Each connection consumes a slot until close, even before any bytes arrive. */
export class NetworkGuard {
  private readonly read: () => NetworkSettings
  private readonly now: () => number
  private readonly addresses = new Map<string, AddressBudget>()
  private readonly live = new Map<string, number>()
  private active = 0
  private pending = 0

  constructor(read: () => NetworkSettings, now: () => number = Date.now) {
    this.read = read
    this.now = now
  }

  private trim(max: number, now: number): void {
    for (const [address, budget] of this.addresses) {
      if (!this.live.has(address) && budget.lockedUntil <= now && now - budget.lastSeen > 60_000) this.addresses.delete(address)
    }
    while (this.addresses.size >= max) {
      const oldest = [...this.addresses].find(([address, budget]) => !this.live.has(address) && budget.lockedUntil <= now)
      if (oldest === undefined) break
      this.addresses.delete(oldest[0])
    }
  }

  admit(address: string): AdmissionLease | undefined {
    const limits = networkLimits(this.read())
    if (this.active >= limits.maxConnections || this.pending >= limits.maxPendingHandshakes
      || (this.live.get(address) ?? 0) >= limits.maxConnectionsPerAddress) return undefined
    const now = this.now()
    let budget = this.addresses.get(address)
    if (budget === undefined) {
      this.trim(limits.maxTrackedAddresses, now)
      if (this.addresses.size >= limits.maxTrackedAddresses) return undefined
      budget = { tokens: limits.maxHandshakesPerMinute, refilled: now, lastSeen: now, failures: 0, firstFailure: now, lockedUntil: 0 }
      this.addresses.set(address, budget)
    }
    budget.tokens = Math.min(limits.maxHandshakesPerMinute, budget.tokens + Math.max(0, now - budget.refilled) * limits.maxHandshakesPerMinute / 60_000)
    budget.refilled = now
    budget.lastSeen = now
    if (budget.lockedUntil > now || budget.tokens < 1) return undefined
    budget.tokens -= 1
    this.active += 1
    this.pending += 1
    this.live.set(address, (this.live.get(address) ?? 0) + 1)
    let waiting = true
    let released = false
    const authenticated = (): void => {
      if (released || !waiting) return
      waiting = false
      this.pending -= 1
      // Success does not erase a shared source's attack history: many controllers
      // may legitimately share one tunnel address.
    }
    return {
      authenticated,
      failed: () => {
        if (released || !waiting) return
        const current = this.now()
        if (current - budget.firstFailure >= limits.lockoutMs) { budget.failures = 0; budget.firstFailure = current }
        budget.failures += 1
        if (budget.failures >= limits.maxHandshakeFailures) {
          budget.lockedUntil = current + limits.lockoutMs
          budget.failures = 0
          budget.firstFailure = current
        }
        authenticated()
      },
      release: () => {
        if (released) return
        authenticated()
        released = true
        this.active -= 1
        const remaining = (this.live.get(address) ?? 1) - 1
        if (remaining <= 0) this.live.delete(address)
        else this.live.set(address, remaining)
      },
    }
  }

  /** Finite diagnostics, useful for deterministic resource-budget assertions. */
  snapshot() { return { active: this.active, pending: this.pending, addresses: this.addresses.size } }
}

export type RequestEnvelope = { type: 'request', request: Record<string, unknown>, id: number, op: string }
  | { type: 'answer', request: Record<string, unknown>, qid: string }

/** Reject ambiguous control envelopes before they can dispatch any operation. */
export function validateRequestEnvelope(value: unknown, lastId: number): RequestEnvelope {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('request must be a JSON object')
  const request = value as Record<string, unknown>
  if (request.kind === 'answer' || (!Object.hasOwn(request, 'op') && Object.hasOwn(request, 'kind'))) {
    if (request.kind !== 'answer' || Object.hasOwn(request, 'id') || Object.hasOwn(request, 'op')
      || typeof request.qid !== 'string' || !/^[A-Za-z0-9-]{1,128}$/.test(request.qid)
      || !Object.hasOwn(request, 'answer')) throw new Error('invalid answer envelope')
    return { type: 'answer', request, qid: request.qid }
  }
  if (!Number.isSafeInteger(request.id) || (request.id as number) <= lastId || (request.id as number) <= 0) {
    throw new Error('request id must be a strictly increasing positive safe integer')
  }
  if (typeof request.op !== 'string' || !/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/.test(request.op)
    || request.op.length > 64) throw new Error('invalid request operation')
  return { type: 'request', request, id: request.id as number, op: request.op }
}

/** Race a cooperative lifetime without leaking abort listeners or waiters. */
export async function withAuthorization<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted()
  let abort: () => void = () => {}
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => reject(signal.reason instanceof Error ? signal.reason : new Error('authorization revoked'))
    signal.addEventListener('abort', abort, { once: true })
  })
  try { return await Promise.race([promise, cancelled]) }
  finally { signal.removeEventListener('abort', abort) }
}

/** Empty means no time restriction; a malformed nonempty date fails closed. */
export function expirationTime(value: unknown): number | undefined {
  if (value === undefined || value === '') return undefined
  const match = typeof value === 'string'
    ? /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?([Zz]|[+-]\d{2}:\d{2})$/.exec(value) : null
  if (match === null) throw new Error('validUntil must be an RFC3339 timestamp with a time zone')
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const zone = match[7] as string
  const calendar = new Date(0)
  calendar.setUTCFullYear(year as number, (month as number) - 1, day)
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() + 1 !== month || calendar.getUTCDate() !== day
    || (hour as number) > 23 || (minute as number) > 59 || (second as number) > 59 || zone === '-00:00'
    || (zone.length > 1 && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4, 6)) > 59))) throw new Error('validUntil is invalid')
  const parsed = Date.parse(value as string)
  if (!Number.isFinite(parsed)) throw new Error('validUntil is invalid')
  return parsed
}

/** Exact operation allowlists restrict the ordinary ceiling; never wildcard. */
export function allowedOperations(value: unknown): readonly string[] {
  if (value === undefined) return []
  if (!Array.isArray(value) || value.length > 64 || value.some(op => typeof op !== 'string'
    || op.length > 64 || !/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/.test(op))) throw new Error('allowedOps must contain at most 64 exact operation names')
  return [...new Set(value as string[])].sort()
}
