/**
 * Wire protocol for the DSH remote link — mutual X25519 + AES-256-GCM.
 *
 * This is a TypeScript port of the Python reference implementation that was
 * already exercised end to end, so the two halves keep the same wire format:
 *
 *   handshake
 *     C -> S  HELLO    magic(5) | c_eph_pub(32) | c_nonce(32)
 *     S -> C  REPLY    magic(5) | s_eph_pub(32) | s_nonce(32) | tag_s(32)
 *     C -> S  CONFIRM  tag_c(32)
 *
 *     ss   = ECDH(c_eph, s_eph) || ECDH(c_eph, s_static) || ECDH(c_static, s_eph)
 *     key  = HKDF-SHA256(ikm = ss, salt = c_nonce || s_nonce, info = "dshr2", 32)
 *     kC2S = HKDF(ikm = key, salt = 0^32, info = "dshr2 c2s", 32)
 *     kS2C = HKDF(ikm = key, salt = 0^32, info = "dshr2 s2c", 32)
 *     transcript = magic || c_eph_pub || s_eph_pub || c_nonce || s_nonce
 *     tag_s = HMAC(key, "dshr2 server" || transcript)
 *     tag_c = HMAC(key, "dshr2 client" || transcript)
 *
 *   frames
 *     uint32 big-endian length | AES-256-GCM ciphertext+tag
 *     nonce = 00000000 || counter(uint64 BE), aad = direction || counter
 *
 * Why the pieces are here:
 *
 * - **Mutual authentication.** Each side holds a static X25519 key and pins the
 *   other's public key. `tag_s` can only be produced by someone holding the
 *   server's static private key (it is required for the ECDH(c_eph, s_static)
 *   leg); `tag_c` proves the same about the client. Comparing them is what makes
 *   an interloper on the tunnel fail instead of silently connecting.
 * - **Forward secrecy.** Session keys come from fresh ephemeral pairs, so a
 *   later static-key compromise does not open recorded sessions.
 * - **Replay/reorder resistance.** The counter is inside the AEAD's additional
 *   data and must advance by exactly one, so a captured frame cannot be replayed
 *   and a dropped one cannot be skipped.
 *
 * Only Node builtins are used, so the package has no install surface.
 *
 * @module dsh-remote/protocol
 */

import { KeyObject, createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes, timingSafeEqual } from 'node:crypto'
import type { Socket } from 'node:net'
import { TextDecoder } from 'node:util'

/** Protocol magic; also the marker that distinguishes these frames from any other listener. */
export const MAGIC = Buffer.from('DSHR2', 'ascii')
const INFO = Buffer.from('dshr2', 'ascii')
const DIR_C2S = Buffer.from('C2S', 'ascii')
const DIR_S2C = Buffer.from('S2C', 'ascii')

/** Bytes of nonce each side contributes to the salt. */
export const NONCE_LEN = 32
/** Bytes of an authentication tag. */
export const TAG_LEN = 32
/** Refuse a declared frame larger than this. */
export const MAX_FRAME = 256 * 1024 * 1024
/** Default ciphertext body cap, including its 16-byte authentication tag. */
export const DEFAULT_MAX_FRAME_BYTES = 32 * 1024 * 1024
/** Total deadline once the first byte of a frame is received. Idle is unlimited. */
export const DEFAULT_FRAME_TIMEOUT_MS = 30_000
/** Abort the complete DSHR2 handshake, not each of its fields separately. */
export const HANDSHAKE_TIMEOUT_MS = 15_000
/** Stop before Number precision could repeat an AEAD nonce. */
export const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER
const MAX_TIMER_MS = 2_147_483_647

const ZERO_SALT = Buffer.alloc(32)

/** Raised when the peer fails to authenticate, or speaks something else. */
export class HandshakeError extends Error { override name = 'HandshakeError' }

// ---------------------------------------------------------------- primitives

function hmac(key: Buffer, data: Buffer): Buffer {
  return createHmac('sha256', key).update(data).digest()
}

/**
 * HKDF-SHA256 (extract then expand), matching the reference implementation
 * byte for byte.
 * @param ikm - input keying material.
 * @param salt - extract salt.
 * @param info - expand context.
 * @param length - output length in bytes.
 * @returns the derived key.
 */
export function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  if (!Buffer.isBuffer(ikm) || !Buffer.isBuffer(salt) || !Buffer.isBuffer(info)
    || !Number.isSafeInteger(length) || length < 1 || length > 255 * 32) throw new HandshakeError('invalid HKDF parameters')
  const prk = hmac(salt, ikm)
  const blocks: Buffer[] = []
  // Annotated: `Buffer.alloc` is inferred as the narrower `Buffer<ArrayBuffer>`,
  // which `hmac`'s `Buffer<ArrayBufferLike>` return cannot be assigned to.
  let block: Buffer = Buffer.alloc(0)
  let counter = 1
  let total = 0
  while (total < length) {
    block = hmac(prk, Buffer.concat([block, info, Buffer.from([counter])]))
    blocks.push(block)
    total += block.length
    counter += 1
  }
  return Buffer.concat(blocks).subarray(0, length)
}

function deriveSessionKey(shared: Buffer, cNonce: Buffer, sNonce: Buffer): Buffer {
  return hkdf(shared, Buffer.concat([cNonce, sNonce]), INFO, 32)
}

function handshakeTag(key: Buffer, who: Buffer, transcript: Buffer): Buffer {
  return hmac(key, Buffer.concat([who, transcript]))
}

// ------------------------------------------------------------------ key codec

/**
 * The raw 32-byte public key of an X25519 KeyObject.
 *
 * An X25519 SubjectPublicKeyInfo DER ends with the key itself, which avoids
 * pulling in an ASN.1 dependency just to read it back.
 * @param key - the public key.
 * @returns the 32 raw bytes.
 */
function requireKey(key: KeyObject, role: 'public' | 'private'): void {
  if (!(key instanceof KeyObject) || key.type !== role || key.asymmetricKeyType !== 'x25519') throw new HandshakeError(`expected an X25519 ${role} key`)
}

export function rawPublic(key: KeyObject): Buffer {
  requireKey(key, 'public')
  const der = key.export({ type: 'spki', format: 'der' })
  const prefix = Buffer.from('302a300506032b656e032100', 'hex')
  if (der.length !== prefix.length + 32 || !der.subarray(0, prefix.length).equals(prefix)) throw new HandshakeError('invalid X25519 public key encoding')
  return Buffer.from(der.subarray(prefix.length))
}

/**
 * Wrap 32 raw bytes as an X25519 public KeyObject.
 * @param raw - the 32-byte public key.
 * @returns the key object.
 */
export function publicFromRaw(raw: Buffer): KeyObject {
  if (!Buffer.isBuffer(raw) || raw.length !== 32) throw new HandshakeError('X25519 public key must be exactly 32 bytes')
  const prefix = Buffer.from('302a300506032b656e032100', 'hex')
  try { return createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' }) }
  catch { throw new HandshakeError('invalid X25519 public key encoding') }
}

/**
 * Full SHA-256 fingerprint of a public key, without truncating its identity.
 * @param key - the public key.
 * @returns `SHA256:` followed by all 64 lowercase hexadecimal characters.
 */
export function fingerprint(key: KeyObject): string {
  const digest = createHash('sha256').update(rawPublic(key)).digest('hex')
  return `SHA256:${digest}`
}

/** Generate a fresh X25519 keypair. */
export function generateKeyPair(): { privateKey: KeyObject, publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync('x25519')
  return { privateKey, publicKey }
}

/**
 * Parse a private key from PEM, or from 32 raw bytes given as hex or base64.
 * @param text - the encoded key.
 * @returns the private key object.
 */
export function parsePrivateKey(text: string): KeyObject {
  try {
    const trimmed = keyText(text)
    let key: KeyObject
    if (trimmed.startsWith('-----BEGIN')) {
      if (!/^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PRIVATE KEY-----$/u.test(trimmed)) throw new HandshakeError('expected one unencrypted PKCS8 private key')
      key = createPrivateKey(trimmed)
    } else {
      const raw = decodeRaw(trimmed, 'private')
      const prefix = Buffer.from('302e020100300506032b656e04220420', 'hex')
      key = createPrivateKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'pkcs8' })
    }
    requireKey(key, 'private')
    return key
  } catch { throw new HandshakeError('invalid X25519 private key; expected PKCS8 PEM, 64 hex characters or canonical base64 of 32 bytes') }
}

/**
 * Parse a public key from PEM, or from 32 raw bytes given as hex or base64.
 * @param text - the encoded key.
 * @returns the public key object.
 */
export function parsePublicKey(text: string): KeyObject {
  try {
    const trimmed = keyText(text)
    let key: KeyObject
    if (trimmed.startsWith('-----BEGIN')) {
      if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PUBLIC KEY-----$/u.test(trimmed)) throw new HandshakeError('expected one SPKI public key')
      key = createPublicKey(trimmed)
    } else key = publicFromRaw(decodeRaw(trimmed, 'public'))
    requireKey(key, 'public')
    return key
  } catch { throw new HandshakeError('invalid X25519 public key; expected SPKI PEM, 64 hex characters or canonical base64 of 32 bytes') }
}

function keyText(text: string): string {
  if (typeof text !== 'string' || text.length > 8192 || text.trim() === '') throw new HandshakeError('invalid key text')
  return text.trim()
}

/** Node's base64 decoder is permissive; exact re-encoding rejects hidden junk. */
function decodeRaw(text: string, what: string): Buffer {
  if (/^[0-9a-fA-F]{64}$/u.test(text)) return Buffer.from(text, 'hex')
  if (/^[A-Za-z0-9+/]{43}=$/u.test(text)) {
    const decoded = Buffer.from(text, 'base64')
    if (decoded.length === 32 && decoded.toString('base64') === text) return decoded
  }
  throw new HandshakeError(`invalid canonical X25519 ${what} key encoding`)
}

/** Serialize a private key as PKCS#8 PEM. */
export function privateToPem(key: KeyObject): string {
  requireKey(key, 'private')
  return key.export({ type: 'pkcs8', format: 'pem' }).toString()
}

/** Serialize a public key as SPKI PEM. */
export function publicToPem(key: KeyObject): string {
  requireKey(key, 'public')
  return key.export({ type: 'spki', format: 'pem' }).toString()
}

// ------------------------------------------------------------------ socket i/o

const closingSockets = new WeakMap<Socket, () => void>()
/** A write callback may fail just before Node emits its asynchronous error. */
function destroySocket(socket: Socket, alreadyClosed = false): void {
  if (!alreadyClosed && !closingSockets.has(socket)) {
    const ignore = (): void => {}
    const cleanup = (): void => {
      socket.off('error', ignore); socket.off('close', cleanup); closingSockets.delete(socket)
    }
    closingSockets.set(socket, cleanup)
    socket.on('error', ignore)
    socket.once('close', cleanup)
  }
  socket.destroy()
  if (alreadyClosed) closingSockets.get(socket)?.()
}

/** Exact reads over the socket's bounded paused stream, with one active owner. */
export class ByteReader {
  private ended = false
  private disposed = false
  private busy = false
  private failure: HandshakeError | undefined
  private waiting: (() => void) | undefined
  private readonly sock: Socket
  private readonly finish = (): void => { this.ended = true; this.waiting?.() }
  private readonly failed = (): void => { this.failure = new HandshakeError('socket read failed'); this.finish() }

  constructor(sock: Socket) {
    this.sock = sock
    sock.pause()
    sock.on('end', this.finish)
    sock.on('close', this.finish)
    sock.on('error', this.failed)
  }

  /** Detach every owned listener and release any pending reader immediately. */
  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.ended = true
    this.sock.off('end', this.finish)
    this.sock.off('close', this.finish)
    this.sock.off('error', this.failed)
    this.waiting?.()
  }

  private async readable(deadline: number): Promise<void> {
    if (deadline !== 0 && deadline <= Date.now()) throw new HandshakeError('socket read deadline exceeded')
    await new Promise<void>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined
      let settled = false
      const finish = (error?: Error): void => {
        if (settled) return
        settled = true
        if (timer !== undefined) clearTimeout(timer)
        this.sock.off('readable', wake)
        this.waiting = undefined
        if (error === undefined) resolve()
        else reject(error)
      }
      const wake = (): void => { finish() }
      this.waiting = wake
      this.sock.once('readable', wake)
      if (deadline !== 0) timer = setTimeout(() => finish(new HandshakeError('socket read deadline exceeded')), Math.max(1, deadline - Date.now()))
      if (this.ended || this.disposed || this.sock.destroyed || this.sock.readableEnded || this.sock.readableLength !== 0) wake()
    })
  }

  /**
   * Read exactly n bytes; null means EOF before any byte, never a partial read.
   * timeoutMs=0 allows idle waits. A frame header may defer a positive deadline
   * until its first byte; body reads never defer. No flowing data listener or
   * application-owned backlog is installed, so TCP backpressure remains active.
   */
  async read(n: number, timeoutMs = 0, options: { startTimeoutOnData?: boolean; onFirstByte?: () => void } = {}): Promise<Buffer | null> {
    if (!Number.isSafeInteger(n) || n < 0 || n > MAX_FRAME || !Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > MAX_TIMER_MS) throw new HandshakeError('invalid socket read parameters')
    if (this.busy) throw new HandshakeError('concurrent socket reads are not allowed')
    if (n === 0) return Buffer.alloc(0)
    if (this.disposed) throw new HandshakeError('socket reader is closed')
    this.busy = true
    let deadline = timeoutMs > 0 && options.startTimeoutOnData !== true ? Date.now() + timeoutMs : 0
    // Allocate only the requested bounded field, never concatenate its backlog.
    const output = Buffer.allocUnsafe(n)
    let offset = 0
    try {
      while (offset < n) {
        if (this.disposed) {
          if (offset === 0 && this.sock.readableEnded && this.failure === undefined) return null
          throw new HandshakeError('socket reader is closed')
        }
        if (this.failure !== undefined) throw this.failure
        if (deadline !== 0 && Date.now() >= deadline) throw new HandshakeError('socket read deadline exceeded')
        const available = this.sock.readableLength
        if (available > 0) {
          const chunk = this.sock.read(Math.min(n - offset, available, 64 * 1024)) as Buffer | null
          if (chunk !== null) {
            if (offset === 0) {
              if (deadline === 0 && timeoutMs > 0) deadline = Date.now() + timeoutMs
              options.onFirstByte?.()
            }
            chunk.copy(output, offset)
            offset += chunk.length
            continue
          }
        }
        if (this.ended || this.sock.destroyed || this.sock.readableEnded) {
          if (offset === 0) { this.dispose(); return null }
          throw new HandshakeError('peer truncated a socket field')
        }
        await this.readable(deadline)
      }
      return output
    } catch (error) {
      destroySocket(this.sock)
      this.dispose()
      throw error instanceof HandshakeError ? error : new HandshakeError('socket read failed')
    } finally { this.busy = false }
  }
}

function seal(key: Buffer, counter: number, direction: Buffer, plaintext: Buffer): Buffer {
  const counterBuf = Buffer.alloc(8)
  counterBuf.writeBigUInt64BE(BigInt(counter))
  const nonce = Buffer.concat([Buffer.alloc(4), counterBuf])
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.concat([direction, counterBuf]))
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

function open(key: Buffer, counter: number, direction: Buffer, body: Buffer): Buffer {
  const counterBuf = Buffer.alloc(8)
  counterBuf.writeBigUInt64BE(BigInt(counter))
  const nonce = Buffer.concat([Buffer.alloc(4), counterBuf])
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(Buffer.concat([direction, counterBuf]))
  decipher.setAuthTag(body.subarray(body.length - 16))
  return Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()])
}

export interface SessionOptions {
  /** Ciphertext body bytes, including its tag; default 32 MiB, hard cap 256 MiB. */
  maxFrameBytes?: number
  /** Positive total frame/write deadline; idle before any header is unlimited. */
  frameTimeoutMs?: number
  /** Active and queued wire bytes; default twice maxFrameBytes plus headers. */
  maxQueuedBytes?: number
  /** Active and queued writes; default 64, hard cap 1024. */
  maxPendingSends?: number
}

function sessionOptions(options: SessionOptions): Required<SessionOptions> {
  const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES
  const output = { maxFrameBytes, frameTimeoutMs: options.frameTimeoutMs ?? DEFAULT_FRAME_TIMEOUT_MS,
    maxQueuedBytes: options.maxQueuedBytes ?? 2 * (maxFrameBytes + 4), maxPendingSends: options.maxPendingSends ?? 64 }
  for (const [value, minimum, maximum] of [[output.maxFrameBytes, 18, MAX_FRAME], [output.frameTimeoutMs, 1, MAX_TIMER_MS],
    [output.maxQueuedBytes, 22, 2 * (MAX_FRAME + 4)], [output.maxPendingSends, 1, 1024]]) {
    if (!Number.isSafeInteger(value) || value! < minimum! || value! > maximum!) throw new HandshakeError('invalid encrypted session limits')
  }
  return output
}

function jsonRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Honor both callback completion and stream backpressure, with no orphan waits. */
async function writeSocket(socket: Socket, frame: Buffer, timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let finished = false
    let returned = false
    let callbackDone = false
    let drained = false
    const finish = (error?: Error): void => {
      if (finished) return
      if (error === undefined && (!returned || !callbackDone || !drained)) return
      finished = true
      clearTimeout(timer)
      socket.off('drain', drain)
      socket.off('close', closed)
      socket.off('error', failed)
      if (error === undefined) resolve()
      else reject(error)
    }
    const drain = (): void => { drained = true; finish() }
    const closed = (): void => finish(new HandshakeError('socket closed during write'))
    const failed = (): void => finish(new HandshakeError('socket write failed'))
    const timer = setTimeout(() => {
      finish(new HandshakeError('socket write deadline exceeded'))
      destroySocket(socket)
    }, timeoutMs)
    socket.on('drain', drain)
    socket.once('close', closed)
    socket.once('error', failed)
    if (socket.destroyed || !socket.writable) { closed(); return }
    try {
      const accepted = socket.write(frame, error => {
        callbackDone = true
        if (error !== undefined && error !== null) failed()
        else finish()
      })
      returned = true
      if (accepted) drained = true
      finish()
    } catch { failed() }
  })
}

interface PendingSend { plaintext: Buffer; bytes: number; resolve(): void; reject(error: HandshakeError): void }

/** Authenticated, bounded and ordered DSHR2 channel; the wire format is unchanged. */
export class Session {
  private sendCounter = 0
  private recvCounter = 0
  private readonly sendKey: Buffer
  private readonly recvKey: Buffer
  private readonly sendDir: Buffer
  private readonly recvDir: Buffer
  private readonly limits: Required<SessionOptions>
  private readonly queue: PendingSend[] = []
  private queuedBytes = 0
  private pendingSends = 0
  private sending = false
  private receiving = false
  private failure: HandshakeError | undefined
  private readonly onClose = (): void => { this.terminate(new HandshakeError('encrypted session closed'), true) }
  private readonly onError = (): void => { this.terminate(new HandshakeError('encrypted socket failed')) }
  bytesSent = 0
  bytesReceived = 0
  readonly socket: Socket
  private readonly reader: ByteReader

  constructor(socket: Socket, reader: ByteReader, key: Buffer, initiator: boolean, options: SessionOptions = {}) {
    if (!Buffer.isBuffer(key) || key.length !== 32 || typeof initiator !== 'boolean') throw new HandshakeError('invalid encrypted session parameters')
    this.limits = sessionOptions(options)
    this.socket = socket
    this.reader = reader
    const kC2S = hkdf(key, ZERO_SALT, Buffer.concat([INFO, Buffer.from(' c2s')]), 32)
    const kS2C = hkdf(key, ZERO_SALT, Buffer.concat([INFO, Buffer.from(' s2c')]), 32)
    this.sendKey = initiator ? kC2S : kS2C
    this.recvKey = initiator ? kS2C : kC2S
    this.sendDir = initiator ? DIR_C2S : DIR_S2C
    this.recvDir = initiator ? DIR_S2C : DIR_C2S
    socket.once('close', this.onClose)
    socket.on('error', this.onError)
  }

  private terminate(error: HandshakeError, alreadyClosed = false): HandshakeError {
    if (this.failure !== undefined) return this.failure
    this.failure = error
    for (const item of this.queue.splice(0)) {
      this.pendingSends--; this.queuedBytes -= item.bytes
      item.plaintext.fill(0)
      item.reject(error)
    }
    this.socket.off('close', this.onClose)
    this.socket.off('error', this.onError)
    this.reader.dispose()
    destroySocket(this.socket, alreadyClosed)
    this.sendKey.fill(0); this.recvKey.fill(0)
    return error
  }

  /** Serialize immediately, but admit only a bounded count/byte queue. */
  async send(payload: unknown): Promise<void> {
    if (this.failure !== undefined) throw this.failure
    if (this.pendingSends >= this.limits.maxPendingSends) throw new HandshakeError('encrypted send queue is full')
    if (!jsonRecord(payload)) throw new HandshakeError('encrypted messages must be JSON records')
    let serialized: string
    try {
      serialized = JSON.stringify(payload)
      if (typeof serialized !== 'string') throw new Error()
    } catch { throw new HandshakeError('encrypted message is not serializable JSON') }
    const bytes = Buffer.byteLength(serialized, 'utf8') + 20
    if (bytes - 4 > this.limits.maxFrameBytes) throw new HandshakeError('encrypted message exceeds frame limit')
    if (bytes + this.queuedBytes > this.limits.maxQueuedBytes) throw new HandshakeError('encrypted send byte queue is full')
    try { if (!jsonRecord(JSON.parse(serialized))) throw new Error() }
    catch { throw new HandshakeError('encrypted messages must serialize to JSON records') }
    await new Promise<void>((resolve, reject) => {
      this.queue.push({ plaintext: Buffer.from(serialized, 'utf8'), bytes, resolve, reject })
      this.queuedBytes += bytes; this.pendingSends++
      void this.flush()
    })
  }

  private async flush(): Promise<void> {
    if (this.sending) return
    this.sending = true
    try {
      while (this.queue.length !== 0 && this.failure === undefined) {
        const item = this.queue.shift()!
        try {
          if (!Number.isSafeInteger(this.sendCounter) || this.sendCounter < 0 || this.sendCounter >= MAX_SEQUENCE) throw new HandshakeError('encrypted send sequence exhausted')
          const next = this.sendCounter + 1
          const body = seal(this.sendKey, next, this.sendDir, item.plaintext)
          const frame = Buffer.allocUnsafe(body.length + 4)
          frame.writeUInt32BE(body.length, 0); body.copy(frame, 4)
          this.sendCounter = next
          await writeSocket(this.socket, frame, this.limits.frameTimeoutMs)
          if (this.failure !== undefined) throw this.failure
          this.bytesSent += frame.length
          item.resolve()
        } catch (error) {
          item.reject(this.terminate(error instanceof HandshakeError ? error : new HandshakeError('encrypted send failed')))
        } finally {
          this.pendingSends--; this.queuedBytes -= item.bytes
          item.plaintext.fill(0)
        }
      }
    } finally { this.sending = false }
  }

  /** Receive one record. Only EOF before a new header is a clean null result. */
  async recv(timeoutMs = 0): Promise<Record<string, unknown> | null> {
    if (this.failure !== undefined) throw this.failure
    if (this.receiving) throw new HandshakeError('concurrent encrypted receives are not allowed')
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > MAX_TIMER_MS) throw new HandshakeError('invalid receive deadline')
    this.receiving = true
    const total = timeoutMs === 0 ? this.limits.frameTimeoutMs : Math.min(timeoutMs, this.limits.frameTimeoutMs)
    let deadline = timeoutMs === 0 ? 0 : Date.now() + total
    try {
      if (!Number.isSafeInteger(this.recvCounter) || this.recvCounter < 0 || this.recvCounter >= MAX_SEQUENCE) throw new HandshakeError('encrypted receive sequence exhausted')
      const header = await this.reader.read(4, total, { startTimeoutOnData: timeoutMs === 0,
        onFirstByte: () => { if (deadline === 0) deadline = Date.now() + total } })
      if (header === null) { this.close(); return null }
      const length = header.readUInt32BE(0)
      if (length < 18 || length > this.limits.maxFrameBytes) throw new HandshakeError('encrypted frame length exceeds allowed bounds')
      const remaining = deadline - Date.now()
      if (remaining <= 0) throw new HandshakeError('encrypted frame deadline exceeded')
      const body = await this.reader.read(length, remaining)
      if (body === null) throw new HandshakeError('peer truncated an encrypted frame')
      const next = this.recvCounter + 1
      const plaintext = open(this.recvKey, next, this.recvDir, body)
      let payload: unknown
      try { payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)) }
      finally { plaintext.fill(0) }
      if (!jsonRecord(payload)) throw new HandshakeError('encrypted message is not a JSON record')
      this.recvCounter = next
      this.bytesReceived += 4 + length
      return payload
    } catch (error) {
      throw this.terminate(error instanceof HandshakeError ? error : new HandshakeError('encrypted frame authentication or JSON parsing failed'))
    } finally { this.receiving = false }
  }

  /** Fail queued work, release listeners and destroy the underlying socket. */
  close(): void { this.terminate(new HandshakeError('encrypted session closed')) }
}

// ------------------------------------------------------------------- handshake

function ecdh(privateKey: KeyObject, publicKey: KeyObject): Buffer {
  requireKey(privateKey, 'private'); requireKey(publicKey, 'public')
  try { return diffieHellman({ privateKey, publicKey }) }
  catch { throw new HandshakeError('X25519 key agreement failed') }
}

function handshakeRemaining(deadline: number): number {
  const remaining = deadline - Date.now()
  if (remaining <= 0) throw new HandshakeError('DSHR2 handshake deadline exceeded')
  return remaining
}

function transcriptOf(cEphPub: Buffer, sEphPub: Buffer, cNonce: Buffer, sNonce: Buffer): Buffer {
  return Buffer.concat([MAGIC, cEphPub, sEphPub, cNonce, sNonce])
}

/**
 * Initiator half of the handshake.
 * @param socket - a connected socket (the raw public key of the client, `c_static`).
 * @param clientKey - this side's static private key.
 * @param serverKey - the pinned static public key of the peer.
 * @returns an established session.
 * @throws HandshakeError when the peer cannot prove it holds the pinned key.
 */
export async function clientHandshake(
  socket: Socket,
  clientKey: KeyObject,
  serverKey: KeyObject,
  options: SessionOptions = {},
): Promise<Session> {
  const reader = new ByteReader(socket)
  const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS
  let key: Buffer | undefined
  try {
    requireKey(clientKey, 'private'); requireKey(serverKey, 'public'); sessionOptions(options)
    const eph = generateKeyPair()
    const cEphRaw = rawPublic(eph.publicKey)
    const cNonce = randomBytes(NONCE_LEN)
    await writeSocket(socket, Buffer.concat([MAGIC, cEphRaw, cNonce]), handshakeRemaining(deadline))
    const reply = await reader.read(MAGIC.length + 32 + NONCE_LEN + TAG_LEN, handshakeRemaining(deadline))
    if (reply === null) throw new HandshakeError('peer closed during handshake')
    if (!reply.subarray(0, MAGIC.length).equals(MAGIC)) throw new HandshakeError('peer did not answer with the protocol magic')
    const sEphRaw = reply.subarray(MAGIC.length, MAGIC.length + 32)
    const sNonce = reply.subarray(MAGIC.length + 32, MAGIC.length + 32 + NONCE_LEN)
    const tagS = reply.subarray(reply.length - TAG_LEN)
    const shared = Buffer.concat([
      ecdh(eph.privateKey, publicFromRaw(sEphRaw)), ecdh(eph.privateKey, serverKey), ecdh(clientKey, publicFromRaw(sEphRaw)),
    ])
    try { key = deriveSessionKey(shared, cNonce, sNonce) } finally { shared.fill(0) }
    const transcript = transcriptOf(cEphRaw, sEphRaw, cNonce, sNonce)
    const expected = handshakeTag(key, Buffer.from('dshr2 server'), transcript)
    if (!timingSafeEqual(tagS, expected)) throw new HandshakeError('server authentication FAILED — wrong pinned server key, or a man-in-the-middle on the tunnel')
    await writeSocket(socket, handshakeTag(key, Buffer.from('dshr2 client'), transcript), handshakeRemaining(deadline))
    return new Session(socket, reader, key, true, options)
  } catch (error) {
    destroySocket(socket); reader.dispose()
    throw error instanceof HandshakeError ? error : new HandshakeError('DSHR2 client handshake failed')
  } finally { key?.fill(0) }
}

/**
 * Responder half of the handshake.
 * @param socket - an accepted socket.
 * @param serverKey - this side's static private key.
 * @param clientKey - the pinned static public key of the peer.
 * @returns an established session.
 * @throws HandshakeError when the peer cannot prove it holds the pinned key.
 */
export async function serverHandshake(
  socket: Socket,
  serverKey: KeyObject,
  clientKey: KeyObject,
  options: SessionOptions = {},
): Promise<Session> {
  const reader = new ByteReader(socket)
  const deadline = Date.now() + HANDSHAKE_TIMEOUT_MS
  let key: Buffer | undefined
  try {
    requireKey(serverKey, 'private'); requireKey(clientKey, 'public'); sessionOptions(options)
    const hello = await reader.read(MAGIC.length + 32 + NONCE_LEN, handshakeRemaining(deadline))
    if (hello === null) throw new HandshakeError('peer closed during handshake')
    if (!hello.subarray(0, MAGIC.length).equals(MAGIC)) throw new HandshakeError('peer did not speak the protocol magic')
    const cEphRaw = hello.subarray(MAGIC.length, MAGIC.length + 32)
    const cNonce = hello.subarray(MAGIC.length + 32)
    const eph = generateKeyPair()
    const sEphRaw = rawPublic(eph.publicKey)
    const sNonce = randomBytes(NONCE_LEN)
    const shared = Buffer.concat([
      ecdh(eph.privateKey, publicFromRaw(cEphRaw)), ecdh(serverKey, publicFromRaw(cEphRaw)), ecdh(eph.privateKey, clientKey),
    ])
    try { key = deriveSessionKey(shared, cNonce, sNonce) } finally { shared.fill(0) }
    const transcript = transcriptOf(cEphRaw, sEphRaw, cNonce, sNonce)
    await writeSocket(socket, Buffer.concat([MAGIC, sEphRaw, sNonce, handshakeTag(key, Buffer.from('dshr2 server'), transcript)]), handshakeRemaining(deadline))
    const tagC = await reader.read(TAG_LEN, handshakeRemaining(deadline))
    if (tagC === null) throw new HandshakeError('peer closed before confirming')
    const expected = handshakeTag(key, Buffer.from('dshr2 client'), transcript)
    if (!timingSafeEqual(tagC, expected)) throw new HandshakeError('client authentication FAILED — unknown client key')
    return new Session(socket, reader, key, false, options)
  } catch (error) {
    destroySocket(socket); reader.dispose()
    throw error instanceof HandshakeError ? error : new HandshakeError('DSHR2 server handshake failed')
  } finally { key?.fill(0) }
}
