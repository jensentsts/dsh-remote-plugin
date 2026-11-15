/**
 * A reusable authenticated link to one peer endpoint.
 *
 * Extracted from the client plugin so the peer filesystem provider can share the
 * exact same connect / handshake / retry behaviour: a dropped connection is not
 * an error the caller should see — `request()` reconnects once and replays,
 * because a tunnel that idles out is normal.
 *
 * ## Why this is a multiplexer and not a send/recv pair
 *
 * The socket is ONE ordered, encrypted stream whose receive counter advances per
 * message. Two callers running `send()` then `recv()` on it concurrently is not
 * merely racy, it is corrupting: both would read from the same `ByteReader`,
 * both would bump the shared `recvCounter`, and the AES-GCM counter would no
 * longer match what the peer sealed with — so the stream fails authentication
 * and the connection dies. That is exactly what "peer closed the link" was.
 *
 * So every reply is routed by the `id` the request carried (the peer echoes it),
 * one loop owns the reader, and a request waits on its own promise. Concurrency
 * is therefore safe, and a long-running request no longer blocks the others.
 *
 * @module dsh-remote/link
 */

import type { Socket } from 'node:net'
import type { Session } from './protocol.ts'
import { HandshakeError, HANDSHAKE_TIMEOUT_MS, clientHandshake, rawPublic } from './protocol.ts'
import { createHash } from 'node:crypto'
import { resolvePeerPublicKey, resolvePrivateKey, text } from './keys.ts'

/** Optional key selector, before the unchanged mutually authenticated DSHR2 handshake. */
export const KEY_SELECTOR_MAGIC = Buffer.from('DSHP1', 'ascii')
export const KEY_SELECTOR_ACK = Buffer.from('DSHA1', 'ascii')
export const KEY_SELECTOR_DENIED = Buffer.from('DSHD1', 'ascii')

/**
 * Read a pre-handshake field without installing a competing flowing reader.
 * Any bytes after it stay buffered for the protocol's single ByteReader.
 */
export async function readHandshakeField(socket: Socket, bytes: number): Promise<Buffer | null> {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 4096) throw new HandshakeError('invalid handshake field size')
  return await new Promise((resolve, reject) => {
    let settled = false
    const finish = (value: Buffer | null, error?: Error): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.off('readable', readable)
      socket.off('end', ended)
      socket.off('close', ended)
      socket.off('error', failed)
      if (error !== undefined) reject(error)
      else resolve(value)
    }
    const readable = (): void => {
      const data = socket.read(bytes) as Buffer | null
      if (data !== null) finish(data)
      else if (socket.destroyed || socket.readableEnded) finish(null)
    }
    const ended = (): void => { finish(null) }
    const failed = (error: Error): void => { finish(null, error) }
    const timer = setTimeout(() => {
      finish(null, new HandshakeError('key selector timed out'))
    }, HANDSHAKE_TIMEOUT_MS)
    timer.unref?.()
    socket.on('readable', readable)
    socket.once('end', ended)
    socket.once('close', ended)
    socket.once('error', failed)
    readable()
  })
}

/** A peer's refusal is not a transport fault and must never be replayed. */
class PeerResponseError extends Error {}
class RequestTimeoutError extends Error {}

/** Only observational operations may be replayed after an ambiguous disconnect. */
const REPLAY_SAFE_OPS = new Set([
  'ping', 'sysinfo', 'fs.read', 'fs.list', 'fs.stat', 'fs.hash', 'fs.get',
  'journal.read', 'caps.list', 'references.list', 'agent.events', 'agent.sessions',
  'agent.presets', 'usage.read',
])
const MAX_PENDING_REQUESTS = 256
const MAX_TIMER_MS = 2_147_483_647

function boundedTimeout(value: unknown, fallback: number, maximum = MAX_TIMER_MS): number {
  const number = value === undefined ? fallback : value
  if (typeof number !== 'number' || !Number.isSafeInteger(number) || number < 1 || number > maximum) {
    throw new HandshakeError(`invalid timeout: expected an integer from 1 to ${maximum} ms`)
  }
  return number
}

/**
 * Everything needed to reach one peer. The client plugin's `Config` is a
 * superset, so a peer profile and the plugin's own settings share this shape.
 */
export interface EndpointConfig {
  /** Peer host — whatever address reaches the other machine. No default, on purpose. */
  host?: string
  /** Peer port. Required, alongside `host`. */
  port?: number
  /** Inline X25519 private key (PEM / 64 hex / base64); wins over the file. */
  privateKey?: string
  /** File holding this side's private key; also where a generated one lands. */
  privateKeyFile?: string
  /** Generate and persist a keypair when none exists yet (default true). */
  autoGenerateKey?: boolean
  /** Inline pinned X25519 public key of the peer; wins over the file. */
  peerPublicKey?: string
  /** File holding the peer's pinned public key. */
  peerPublicKeyFile?: string
  /** Per-request socket timeout in milliseconds (default 120000). */
  timeoutMs?: number
  /** Permit one explicit compatibility retry against pre-selector servers. Off by default. */
  allowLegacyHandshake?: boolean
  /** Reauthenticate this connection after this many milliseconds (default 1 hour). */
  maxSessionMs?: number
  /** Connect through the configured mesh node instead of a direct endpoint. */
  relayTarget?: string
}

/** One caller parked on a request id. */
interface Waiter {
  resolve: (reply: Record<string, unknown>) => void
  reject: (error: Error) => void
  timer: ReturnType<typeof setTimeout>
  session: Session
}

/** One request/response exchange over an authenticated link. */
export class LinkClient {
  private session: Session | undefined
  private dialing: Promise<Session> | undefined
  private generation = 0
  private counter = 0
  private readonly connecting = new Set<Socket>()
  private readonly admitted = new Map<Session, { config: string; identity: string; pin: string; expiresAt: number }>()
  private expiryTimer: ReturnType<typeof setTimeout> | undefined
  private disposed = false
  private readonly waiting = new Map<number, Waiter>()
  /** Handler for frames the PEER initiates (anything carrying a `kind`). */
  private eventHandler: ((frame: Record<string, unknown>) => void) | undefined
  private disconnectHandler: ((error: Error) => void) | undefined
  private readonly socketFactory?: (config: EndpointConfig) => Promise<Socket>

  // Plain fields rather than constructor parameter properties: this plugin is
  // loaded as raw TS by a harness that strips types in Node's strip-only mode,
  // where parameter properties are a hard load error.
  private readonly read: () => EndpointConfig
  private readonly log: (message: string) => void
  private readonly label: string

  /**
   * @param read - live accessor for the endpoint; re-read on every dial so a
   *   settings change takes effect without reloading the module.
   * @param log - one-line logger for connect/failure notices.
   * @param label - prefix used in log messages and errors (usually the plugin
   *   name, or `peer <name>` for a federated endpoint).
   */
  constructor(
    read: () => EndpointConfig,
    log: (message: string) => void,
    label: string = 'dsh-remote',
    socketFactory?: (config: EndpointConfig) => Promise<Socket>,
  ) {
    this.read = read
    this.log = log
    this.label = label
    this.socketFactory = socketFactory
  }

  /** Open a fresh authenticated session. */
  private async dial(): Promise<Session> {
    const { connect } = await import('node:net')
    const config = this.read()
    const host = text(config.host)
    const port = config.port ?? 0
    const timeout = boundedTimeout(config.timeoutMs, 120_000, 600_000)
    const maxSessionMs = boundedTimeout(config.maxSessionMs, 3_600_000, 3_600_000)
    if (maxSessionMs < 100) throw new HandshakeError('maximum session lifetime must be at least 100 ms')
    const routed = text(config.relayTarget)
    if (config.relayTarget !== undefined && config.relayTarget !== '' && routed === undefined) throw new HandshakeError('invalid relay target identity')
    if (routed !== undefined && (!/^[A-Za-z0-9._-]{2,128}$/u.test(routed)
      || ['rmt', '.', '..', '__proto__', 'constructor', 'prototype'].includes(routed.toLowerCase()))) throw new HandshakeError('invalid relay target identity')
    if (routed !== undefined && this.socketFactory === undefined) throw new HandshakeError('mesh transport is unavailable; enable the mesh plugin before using relayTarget')
    if (routed === undefined && (host === undefined || /[\u0000-\u0020\u007f]/u.test(host) || !Number.isInteger(port) || port < 1 || port > 65_535)) {
      throw new HandshakeError(
        `${this.label}: set \`host\` and \`port\` to the peer's reachable endpoint. `
        + 'Fill them in — for example the host:port your frp tunnel hands out.',
      )
    }

    // Resolve once: the compatibility attempt must use the exact same pins.
    let identity: ReturnType<typeof resolvePrivateKey>
    let pinned: ReturnType<typeof resolvePeerPublicKey>
    try {
      identity = resolvePrivateKey(config, 'client.key')
      pinned = resolvePeerPublicKey(config, 'server.pub')
    } catch (error) { throw new HandshakeError(`${this.label}: invalid key configuration (${error instanceof Error ? error.message : 'unavailable'})`) }
    const open = async (): Promise<Socket> => {
      if (this.disposed) throw new HandshakeError(`${this.label}: link disposed`)
      if (routed !== undefined) {
        const startedGeneration = this.generation
        let expired = false
        let timer: ReturnType<typeof setTimeout> | undefined
        const pending = this.socketFactory!(config).then(socket => {
          if (expired || this.disposed || startedGeneration !== this.generation) { socket.destroy(); throw new HandshakeError('mesh dial was cancelled') }
          this.connecting.add(socket)
          socket.once('close', () => { this.connecting.delete(socket) })
          socket.setNoDelay(true)
          socket.setTimeout(0)
          return socket
        })
        try {
          return await Promise.race([pending, new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => { expired = true; reject(new HandshakeError('mesh dial timed out')) }, timeout)
          })])
        } finally { if (timer !== undefined) clearTimeout(timer) }
      }
      const socket = connect({ host: host!, port })
      this.connecting.add(socket)
      socket.once('close', () => { this.connecting.delete(socket) })
      try {
        await new Promise<void>((resolve, reject) => {
          const clean = (): void => { clearTimeout(timer); socket.off('connect', connected); socket.off('error', failed); socket.off('close', closed) }
          const connected = (): void => { clean(); resolve() }
          const failed = (error: Error): void => { clean(); reject(error) }
          const closed = (): void => { clean(); reject(new HandshakeError(`${this.label}: connection closed while dialing`)) }
          const timer = setTimeout(() => {
            clean(); socket.destroy()
            reject(new Error(`${this.label}: connect to ${host}:${port} timed out after ${timeout} ms`))
          }, timeout)
          socket.once('connect', connected)
          socket.once('error', failed)
          socket.once('close', closed)
        })
        socket.setNoDelay(true)
        socket.setTimeout(0)
        return socket
      } catch (error) {
        socket.destroy()
        throw error
      }
    }

    let socket = await open()
    // One absolute budget covers selector, compatibility reconnect and proof.
    let authenticationTimedOut = false
    const authenticationDeadline = setTimeout(() => {
      authenticationTimedOut = true
      socket.destroy()
    }, HANDSHAKE_TIMEOUT_MS)
    authenticationDeadline.unref?.()
    try {
      // Padding makes even an old server's fixed-length HELLO reader reject the
      // selector promptly. No application frame is sent before authentication.
      socket.write(Buffer.concat([KEY_SELECTOR_MAGIC, rawPublic(identity.publicKey), Buffer.alloc(32)]))
      const ack = await readHandshakeField(socket, KEY_SELECTOR_ACK.length)
      if (ack !== null && ack.equals(KEY_SELECTOR_DENIED)) {
        throw new HandshakeError('server refused the selected client key')
      }
      if (ack === null || !ack.equals(KEY_SELECTOR_ACK)) {
        if (authenticationTimedOut || config.allowLegacyHandshake !== true) {
          throw new HandshakeError('peer did not acknowledge key selection; legacy handshake is disabled')
        }
        // Explicit compatibility only, never after an authenticated proof failure.
        socket.destroy()
        socket = await open()
      }
      if (authenticationTimedOut) throw new HandshakeError('authentication deadline exceeded')
      const session = await clientHandshake(socket, identity.key, pinned)
      if (authenticationTimedOut) { session.close(); throw new HandshakeError('authentication deadline exceeded') }
      this.connecting.delete(socket)
      this.admitted.set(session, {
        config: this.configurationId(config), identity: this.keyId(identity.publicKey), pin: this.keyId(pinned), expiresAt: Date.now() + maxSessionMs,
      })
      this.log(`${this.label}: authenticated with ${routed === undefined ? `${host}:${port}` : `mesh node ${routed}`}`)
      return session
    } catch (error) {
      socket.destroy()
      if (authenticationTimedOut) throw new HandshakeError('authentication deadline exceeded')
      throw error
    } finally { clearTimeout(authenticationDeadline) }
  }

  private keyId(key: Parameters<typeof rawPublic>[0]): string {
    return createHash('sha256').update(rawPublic(key)).digest('hex')
  }

  private configurationId(config: EndpointConfig): string {
    return createHash('sha256').update(JSON.stringify([
      config.host, config.port, config.privateKey, config.privateKeyFile, config.autoGenerateKey,
      config.peerPublicKey, config.peerPublicKeyFile, config.allowLegacyHandshake === true,
      config.maxSessionMs ?? 3_600_000, config.relayTarget ?? '',
    ])).digest('hex')
  }

  /** Revalidate live pins, including files, before reusing a channel. */
  private validateSession(session: Session): void {
    const admitted = this.admitted.get(session)
    const current = this.read()
    try {
      if (admitted === undefined || Date.now() >= admitted.expiresAt
        || this.configurationId(current) !== admitted.config
        || this.keyId(resolvePeerPublicKey(current, 'server.pub')) !== admitted.pin
        || this.keyId(resolvePrivateKey({ ...current, autoGenerateKey: false }, 'client.key').publicKey) !== admitted.identity) {
        throw new HandshakeError(`${this.label}: authenticated peer identity changed or connection expired`)
      }
    } catch (error) {
      const failure = error instanceof HandshakeError ? error : new HandshakeError(`${this.label}: peer identity is no longer valid`)
      this.failSession(session, failure)
      throw failure
    }
  }

  private async ensure(): Promise<Session> {
    if (this.disposed) throw new HandshakeError(`${this.label}: link disposed`)
    if (this.session !== undefined) { this.validateSession(this.session); return this.session }
    if (this.dialing === undefined) {
      const generation = this.generation
      const dialing = this.dial()
        .then((session) => {
          if (generation !== this.generation) {
            session.close()
            throw new Error(`${this.label}: link closed while connecting`)
          }
          this.validateSession(session)
          this.session = session
          const admitted = this.admitted.get(session)!
          this.expiryTimer = setTimeout(() => this.failSession(session, new HandshakeError(`${this.label}: authenticated connection lifetime expired`)), Math.max(1, admitted.expiresAt - Date.now()))
          this.expiryTimer.unref?.()
          this.startPump(session)
          return session
        })
        .finally(() => { if (this.dialing === dialing) this.dialing = undefined })
      this.dialing = dialing
    }
    return this.dialing
  }

  /**
   * Own the session's reader for as long as it lives.
   *
   * Exactly one loop may call `recv()`: it is the only place the receive counter
   * advances, and routing by id is what lets callers run concurrently.
   * @param session - the freshly established session.
   */
  private startPump(session: Session): void {
    void (async () => {
      try {
        for (;;) {
          const reply = await session.recv()
          if (reply === null) throw new Error('peer closed the link')
          if (this.session !== session) return
          this.validateSession(session)
          this.settle(reply)
        }
      } catch (error) {
        // An obsolete pump must not fail callers parked on a replacement link.
        this.failSession(session, error instanceof Error ? error : new Error(String(error)))
      }
    })()
  }

  /** Hand one inbound frame to whoever it belongs to. */
  private settle(reply: Record<string, unknown>): void {
    // A frame carrying a `kind` was initiated by the PEER rather than answering a
    // request of ours, so it has no request id to route by.
    if (!Object.hasOwn(reply, 'id') && Object.hasOwn(reply, 'kind')) {
      if (typeof reply.kind !== 'string' || !['ask', 'note', 'interrupt', 'caps.changed', 'relay.offer', 'relay.data', 'relay.closed'].includes(reply.kind)
        || Object.hasOwn(reply, 'op')) throw new HandshakeError('invalid peer event envelope')
      this.eventHandler?.(reply)
      return
    }
    const id = typeof reply.id === 'number' ? reply.id : undefined
    if (id === undefined || !Number.isSafeInteger(id) || id <= 0 || typeof reply.ok !== 'boolean') throw new HandshakeError('invalid peer response envelope')
    const waiter = this.waiting.get(id)
    // A reply nobody waits for any more (its caller already timed out) is spent:
    // drop it rather than letting it land on a later request.
    if (waiter === undefined) return
    this.waiting.delete(id)
    clearTimeout(waiter.timer)
    if (reply.ok !== true) {
      // Carry the peer's typed code (FS_STALE_VERSION, ...) so the caller can
      // map it back onto the same FsError the local backend would have raised.
      const failure = new PeerResponseError(String(reply.error ?? 'peer reported failure'))
      if (typeof reply.code === 'string') {
        (failure as unknown as { peerCode: string }).peerCode = reply.code
      }
      waiter.reject(failure)
      return
    }
    waiter.resolve(reply)
  }

  /** Fail only the callers from one connection generation. */
  private failSession(session: Session, error: Error): void {
    for (const [id, waiter] of this.waiting) {
      if (waiter.session !== session) continue
      this.waiting.delete(id)
      clearTimeout(waiter.timer)
      waiter.reject(error)
    }
    this.admitted.delete(session)
    session.close()
    if (this.session === session) {
      if (this.expiryTimer !== undefined) clearTimeout(this.expiryTimer)
      this.expiryTimer = undefined
      this.session = undefined
      try { this.disconnectHandler?.(error) } catch { /* notification cannot resurrect or break the retired connection */ }
    }
  }

  /** Fail every parked caller and drop the session they were waiting on. */
  private failAll(error: Error): void {
    const parked = [...this.waiting.values()]
    this.waiting.clear()
    for (const waiter of parked) {
      clearTimeout(waiter.timer)
      waiter.reject(error)
    }
    this.drop()
  }

  /** Drop the current session so the next request redials. */
  private drop(): void {
    if (this.expiryTimer !== undefined) clearTimeout(this.expiryTimer)
    this.expiryTimer = undefined
    if (this.session !== undefined) this.failSession(this.session, new HandshakeError(`${this.label}: link closed`))
  }

  /** Withdraw one waiter without settling it (the write itself failed). */
  private withdraw(id: number): void {
    const waiter = this.waiting.get(id)
    if (waiter === undefined) return
    this.waiting.delete(id)
    clearTimeout(waiter.timer)
  }

  /**
   * Send one request and return its result. Only allowlisted observations may
   * retry once after transport failure. Concurrent callers use distinct ids.
   * @param op - the server-side operation name.
   * @param args - its arguments.
   * @param timeoutMs - override for the peer-side operation timeout.
   * @param options - `retries` (default 1) permits a single observation retry;
   *   0 disables it. Mutating operations are never replayed regardless of this
   *   option because their body may already have run before a lost reply.
   * @returns the peer's result object.
   */
  async request(
    op: string,
    args: Record<string, unknown> = {},
    timeoutMs?: number,
    options: { retries?: number } = {},
  ): Promise<Record<string, unknown>> {
    if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/u.test(op) || op.length > 64) throw new HandshakeError('invalid remote operation name')
    if (args === null || typeof args !== 'object' || Array.isArray(args)) throw new HandshakeError('request arguments must be a JSON object')
    const generation = this.generation
    const timeout = boundedTimeout(timeoutMs ?? this.read().timeoutMs, 120_000)
    const retries = options.retries ?? 1
    if (!Number.isInteger(retries) || retries < 0 || retries > 1) throw new HandshakeError('retries must be 0 or 1')
    const attempts = REPLAY_SAFE_OPS.has(op) ? retries + 1 : 1
    let lastError: unknown
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await this.exchange(op, args, timeout)
      } catch (error) {
        lastError = error
        if (generation !== this.generation || attempt === attempts || error instanceof PeerResponseError
          || error instanceof RequestTimeoutError || error instanceof HandshakeError) break
        this.log(`${this.label}: ${op} failed (${error instanceof Error ? error.message : String(error)}); reconnecting`)
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError))
  }

  /** One attempt: park on the id, send, await that id's reply. */
  private async exchange(
    op: string,
    args: Record<string, unknown>,
    timeout: number,
  ): Promise<Record<string, unknown>> {
    const session = await this.ensure()
    if (this.waiting.size >= MAX_PENDING_REQUESTS) throw new HandshakeError('too many pending remote requests')
    if (this.counter >= Number.MAX_SAFE_INTEGER) { this.failSession(session, new HandshakeError('request sequence exhausted')); throw new HandshakeError('request sequence exhausted') }
    this.counter += 1
    const id = this.counter
    const reply = new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting.delete(id)
        reject(new RequestTimeoutError(`${this.label}: ${op} timed out after ${timeout} ms`))
      }, timeout)
      this.waiting.set(id, { resolve, reject, timer, session })
    })
    // Drain a concurrent pump rejection even if send() itself throws first.
    void reply.catch(() => {})
    try {
      await session.send({ ...args, id, op })
    } catch (error) {
      this.withdraw(id)
      this.failSession(session, error instanceof Error ? error : new Error(String(error)))
      throw error
    }
    return await reply
  }

  /** True while a session is believed live. */
  get connected(): boolean {
    return this.session !== undefined
  }

  /**
   * Register the handler for frames the peer initiates.
   *
   * One handler, because there is one connection: the peer's questions (and
   * anything else it pushes) arrive here, and the caller fans them out.
   * @param handler - called with every frame that carries a `kind`.
   */
  onEvent(handler: (frame: Record<string, unknown>) => void): void {
    this.eventHandler = handler
  }

  /** Observe loss of the active authenticated channel, once per generation. */
  onDisconnect(handler: (error: Error) => void): void {
    this.disconnectHandler = handler
  }

  /**
   * Send a frame that expects no reply. Used to answer a peer-initiated frame,
   * which by definition has no request id to be answered by.
   * @param payload - the frame to send.
   */
  async notify(payload: Record<string, unknown>): Promise<void> {
    const session = await this.ensure()
    await session.send(payload)
  }

  /** Number of requests currently awaiting a reply. */
  get inFlight(): number {
    return this.waiting.size
  }

  /** Close the session and let it die. */
  close(): void {
    this.generation += 1
    this.dialing = undefined
    for (const socket of this.connecting) socket.destroy()
    this.connecting.clear()
    this.failAll(new HandshakeError(`${this.label}: link closed`))
  }

  /** Permanently retire a transport so old closures cannot resurrect old trust. */
  dispose(): void {
    this.disposed = true
    this.close()
  }
}
