/** A bounded opaque byte stream over one already-registered hub connection. */
import { Duplex } from 'node:stream'
import type { Socket } from 'node:net'

export const RELAY_CHUNK_BYTES = 48 * 1024
export const RELAY_RECEIVE_BYTES = 1024 * 1024

/** This adapter must stay pinned to one hub connection; it must never redial. */
export interface RelaySocketChannel {
  request(op: string, args: Record<string, unknown>): Promise<Record<string, unknown>>
}

export interface RelaySocketOptions {
  /** A smaller limit is useful for isolated tests; it cannot exceed the hard cap. */
  maxReceiveBytes?: number
}

/** Decode only canonical RFC 4648 base64, before allocating an inbound chunk. */
export function decodeRelayData(value: unknown): Buffer {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(RELAY_CHUNK_BYTES / 3)
    || value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new Error('invalid relay base64')
  }
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length > RELAY_CHUNK_BYTES || bytes.toString('base64') !== value) throw new Error('invalid relay base64')
  return bytes
}

function failure(error: unknown): Error {
  return error instanceof Error ? error : new Error('relay request failed')
}

/**
 * Socket-compatible Duplex for the existing DSHR2 handshake/Session. This layer
 * does not inspect, authenticate, decrypt or execute the bytes it transports.
 * Writable callbacks complete only after every <=48 KiB write RPC is acknowledged.
 * There is no half-close operation in the relay wire protocol: end closes the tunnel.
 */
export class RelaySocket extends Duplex {
  readonly tunnelId: string
  readonly connecting = false
  readonly pending = false
  readonly remoteAddress = 'relay'
  readonly remoteFamily = 'relay'
  readonly localAddress = undefined
  readonly localPort = undefined
  readonly remotePort = undefined
  bytesRead = 0
  bytesWritten = 0
  private readonly channel: RelaySocketChannel
  private readonly maxReceiveBytes: number
  private readonly cancellation = new AbortController()
  private nextSend = 1
  private nextReceive = 1
  private peerClosed = false
  private timeoutMs = 0
  private timeoutTimer: ReturnType<typeof setTimeout> | undefined
  private referenced = true

  constructor(tunnelId: string, channel: RelaySocketChannel, options: RelaySocketOptions = {}) {
    super({ readableHighWaterMark: RELAY_CHUNK_BYTES, writableHighWaterMark: RELAY_CHUNK_BYTES,
      allowHalfOpen: false, autoDestroy: true })
    const limit = options.maxReceiveBytes ?? RELAY_RECEIVE_BYTES
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > RELAY_RECEIVE_BYTES) throw new Error('invalid relay receive limit')
    this.tunnelId = tunnelId
    this.channel = channel
    this.maxReceiveBytes = limit
    // A pre-return offer or failed handshake can close before a caller attaches
    // its listeners. Still emit errors normally, but never create an unhandled one.
    this.on('error', () => {})
  }

  /** A narrow cast at the transport boundary; no native socket internals are used. */
  asSocket(): Socket { return this as unknown as Socket }

  /** Admission is synchronous: a slow consumer can retain at most 1 MiB. */
  receive(seq: unknown, dataB64: unknown): boolean {
    if (this.destroyed || this.peerClosed) return false
    try { return this.receiveChunk(seq, decodeRelayData(dataB64)) }
    catch (error) { this.destroy(failure(error)); return false }
  }

  /** Adopt an already canonical-decoded mesh race-buffer chunk without copying it. */
  receiveChunk(seq: unknown, bytes: Buffer): boolean {
    if (this.destroyed || this.peerClosed) return false
    try {
      if (!Number.isSafeInteger(seq) || seq !== this.nextReceive || this.nextReceive > Number.MAX_SAFE_INTEGER) {
        throw new Error('invalid relay receive sequence')
      }
      if (!Buffer.isBuffer(bytes) || bytes.length > RELAY_CHUNK_BYTES) throw new Error('invalid relay chunk')
      if (this.readableLength + bytes.length > this.maxReceiveBytes) throw new Error('relay receive buffer exceeded')
      this.nextReceive += 1
      this.bytesRead += bytes.length
      this.activity()
      if (bytes.length !== 0) this.push(bytes)
      return true
    } catch (error) { this.destroy(failure(error)); return false }
  }

  /** Remote/epoch closure must not echo another close or resurrect the channel. */
  remoteClosed(reason = 'relay tunnel closed'): void {
    if (this.destroyed) return
    this.peerClosed = true
    this.push(null)
    this.destroy(new Error(reason))
  }

  override _read(): void { /* Inbound events push directly into the bounded stream. */ }

  override _write(chunk: Buffer | string, encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding)
    void (async () => {
      for (let offset = 0; offset < bytes.length; offset += RELAY_CHUNK_BYTES) {
        if (this.destroyed || this.peerClosed || this.cancellation.signal.aborted) throw new Error('relay tunnel closed during write')
        if (!Number.isSafeInteger(this.nextSend)) throw new Error('relay send sequence exhausted')
        const block = bytes.subarray(offset, offset + RELAY_CHUNK_BYTES)
        const seq = this.nextSend++
        const reply = await this.untilClosed(this.channel.request('relay.write', {
          tunnelId: this.tunnelId, seq, dataB64: block.toString('base64'),
        }))
        if (reply.written !== true) throw new Error('invalid relay write acknowledgement')
        this.bytesWritten += block.length
        this.activity()
      }
    })().then(() => callback(), error => callback(failure(error)))
  }

  private async untilClosed<T>(work: Promise<T>): Promise<T> {
    const signal = this.cancellation.signal
    if (signal.aborted) { void work.catch(() => {}); throw new Error('relay tunnel closed during write') }
    let abort: (() => void) | undefined
    try {
      return await Promise.race([work, new Promise<never>((_resolve, reject) => {
        abort = () => reject(new Error('relay tunnel closed during write'))
        signal.addEventListener('abort', abort, { once: true })
      })])
    } finally { if (abort !== undefined) signal.removeEventListener('abort', abort) }
  }

  override _final(callback: (error?: Error | null) => void): void {
    callback()
    this.destroy()
  }

  override _destroy(error: Error | null, callback: (error: Error | null) => void): void {
    this.cancellation.abort()
    this.clearIdleTimer()
    if (!this.peerClosed) {
      this.peerClosed = true
      // Do not park destruction on a remote acknowledgement. The epoch's request
      // owner supplies a finite timeout and disposes every waiter on disconnect.
      try { void this.channel.request('relay.close', { tunnelId: this.tunnelId }).catch(() => {}) } catch {}
    }
    callback(error)
  }

  /** Native Socket compatibility used by LinkClient, ByteReader and Session. */
  setNoDelay(_noDelay = true): this { return this }
  setKeepAlive(_enable = false, _initialDelay = 0): this { return this }
  setTimeout(timeout: number, callback?: () => void): this {
    if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 2_147_483_647) throw new RangeError('invalid socket timeout')
    if (callback !== undefined) this.once('timeout', callback)
    this.timeoutMs = timeout
    this.activity()
    return this
  }
  ref(): this { this.referenced = true; this.timeoutTimer?.ref?.(); return this }
  unref(): this { this.referenced = false; this.timeoutTimer?.unref?.(); return this }
  address(): Record<string, never> { return {} }
  resetAndDestroy(): this { this.destroy(); return this }
  destroySoon(): void { this.end() }
  get bufferSize(): number { return this.writableLength }
  get readyState(): string {
    if (this.destroyed) return 'closed'
    if (!this.readable) return 'writeOnly'
    if (!this.writable) return 'readOnly'
    return 'open'
  }

  private clearIdleTimer(): void {
    if (this.timeoutTimer !== undefined) clearTimeout(this.timeoutTimer)
    this.timeoutTimer = undefined
  }
  private activity(): void {
    this.clearIdleTimer()
    if (this.timeoutMs === 0 || this.destroyed) return
    this.timeoutTimer = setTimeout(() => {
      this.timeoutTimer = undefined
      this.emit('timeout')
    }, this.timeoutMs)
    if (!this.referenced) this.timeoutTimer.unref?.()
  }
}
