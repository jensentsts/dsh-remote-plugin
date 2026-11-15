/**
 * The **fast path** for moving file bytes to/from the controlled machine.
 *
 * Why this exists at all: the original `fs.read` / `fs.write` ops send the whole
 * file as one base64 JSON frame. Over a real tunnel (measured: frp, ~78 ms RTT,
 * ~2.6 Mbit/s) that measured 0.11–0.46 MiB/s for 4–8 MiB files — an 8 MiB file
 * took 73 seconds, and reads were no better. Three costs compound there:
 * base64 inflates every byte by a third, one huge frame cannot be pipelined, and
 * text/code compresses 3–5× while base64'd text does not get smaller at all.
 *
 * This module is a different transfer, not a different behaviour: a resumable
 * upload begun with a size + sha256, written block by block (each independently
 * gzipped), verified against the hash, and committed atomically with `rename`.
 * Reads are served as bounded, individually-compressed blocks. The old ops stay
 * byte-for-byte unchanged, and a controller only takes this path when the peer's
 * `sysinfo.ops` advertises the new op — so an old peer still works.
 *
 * Deliberately pure Node: no `@deepseek-ai/*` imports. The controlled machine
 * loads plugin sources directly under Node's strip-only TypeScript mode, and a
 * test can import this file without a harness. The typed errors below mirror
 * `FsError`'s wire contract (`.name === 'FsError'`, `.code` matching
 * `/^FS_[A-Z_]+$/`) without importing the harness package that owns the class.
 *
 * @module dsh-remote/transfer-server
 */

import { createHash, randomUUID } from 'node:crypto'
import { mkdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { open, readFile, stat } from 'node:fs/promises'
import { dirname } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'
import { decodeTransferBlock } from './transfer-codec.ts'

/** Wire encoding of one block. */
export type TransferEncoding = 'gzip' | 'raw'

/** Smallest block a caller may ask for; also the floor of `transferMaxChunkBytes`. */
export const MIN_CHUNK_BYTES = 64 * 1024

/** Largest block this half will accept or serve in one frame. */
export const MAX_CHUNK_BYTES = 8 * 1024 * 1024

/** Default block size for an upload. */
export const DEFAULT_CHUNK_BYTES = 1024 * 1024

/** How often idle uploads are swept. */
const SWEEP_INTERVAL_MS = 60_000

/**
 * The configured limits this registry reads live.
 *
 * Every field is read through the caller's `read()` on each operation rather
 * than captured once, so a settings change applies to the next block instead of
 * the next restart.
 */
export interface TransferLimits {
  /** Largest single file an upload may declare (default 1 GiB). */
  transferMaxBytes: number
  /** Largest block `fs.get` will serve (default 8 MiB). */
  transferMaxChunkBytes: number
  /** How many uploads may be in flight at once (default 8). */
  transferMaxActive: number
  /** How long an upload may sit idle before it is discarded (default 10 min). */
  transferUploadTtlMs: number
  /** Largest original file whose text is returned as `before` (default 1 MiB). */
  transferBeforeMaxBytes: number
}

/** Minimal logger shape; the harness logger satisfies it structurally. */
export interface TransferLogger {
  debug(message: string): void
  warn(message: string): void
}

/** What the registry needs from its host. */
export interface TransferServerOptions {
  /** Live configuration reader (limits may change while uploads are open). */
  read: () => TransferLimits
  /** The DSH home this half runs under. Diagnostics only; never a path base. */
  home?: string
  /** Optional logger; the registry never throws because logging failed. */
  log?: TransferLogger
}

/** Stable codes this module raises; a subset of the harness `FsErrorCode`. */
export type TransferErrorCode =
  | 'FS_NOT_FOUND'
  | 'FS_NOT_REGULAR_FILE'
  | 'FS_NOT_OBSERVED'
  | 'FS_STALE_VERSION'
  | 'FS_IO_ERROR'

/**
 * A typed failure on the wire.
 *
 * The server's dispatcher reports `error.code` whenever it matches
 * `/^FS_[A-Z_]+$/`, so this is indistinguishable from a harness `FsError` to a
 * controller — which is the point: the controller branches on the code, never
 * on the class or the message.
 */
export class TransferFsError extends Error {
  readonly code: TransferErrorCode

  constructor(message: string, code: TransferErrorCode) {
    super(message)
    this.name = 'FsError'
    this.code = code
  }
}

/** One in-flight upload: the intent captured at `begin` plus its progress. */
interface UploadRecord {
  uploadId: string
  /** Final path, exactly as the controller asked for it. */
  path: string
  /** Staging file NEXT TO the target, so the commit rename stays on one volume. */
  tempPath: string
  /** Declared final size in bytes. */
  size: number
  /** Lowercase sha256 of the final bytes. */
  sha256: string
  chunkSize: number
  /** Default wire encoding; a block may still say `raw`/`gzip` explicitly. */
  encoding: TransferEncoding
  createOnly: boolean
  /** Version token the target must still have at commit time. */
  expectedVersion: string | undefined
  /** Decoded byte count per block index ever accepted (idempotent rewrites). */
  chunks: Map<number, number>
  /** Bytes accounted for; approximate by design, the commit hash is the truth. */
  received: number
  lastActive: number
}

/** The op handlers the server half wires into its op table. */
export interface TransferServer {
  /** `fs.put.begin` */
  begin(args: Record<string, unknown>): Promise<Record<string, unknown>>
  /** `fs.put.chunk` */
  chunk(args: Record<string, unknown>): Promise<Record<string, unknown>>
  /** `fs.put.commit` */
  commit(args: Record<string, unknown>): Promise<Record<string, unknown>>
  /** `fs.put.abort` */
  abort(args: Record<string, unknown>): Promise<Record<string, unknown>>
  /** `fs.get` */
  get(args: Record<string, unknown>): Promise<Record<string, unknown>>
  /** Abort every upload and delete its staging file; safe to call twice. */
  dispose(): void
}

/** The version token of a file, matching the existing `fs.write` guard. */
function versionOf(info: { mtimeMs: number, size: number }): string {
  return `${info.mtimeMs}:${info.size}`
}

/** Clamp a possibly-junk number into an inclusive range. */
function clamp(value: number, low: number, high: number): number {
  return Math.min(Math.max(value, low), high)
}

/** Read one limit, falling back when the configured value is unusable. */
function limitOf(value: unknown, fallback: number): number {
  const numeric = Number(value)
  if (!Number.isFinite(numeric) || numeric < 0) return fallback
  return Math.floor(numeric)
}

/** Require a non-empty string argument. */
function stringArg(op: string, value: unknown, field: string): string {
  if (typeof value !== 'string' || value === '') {
    throw new Error(`${op}: ${field} is required`)
  }
  return value
}

/** Parse a wire encoding, falling back to `fallback` when omitted. */
function encodingOf(op: string, value: unknown, fallback: TransferEncoding): TransferEncoding {
  if (value === undefined) return fallback
  if (value === 'gzip' || value === 'raw') return value
  throw new Error(`${op}: encoding must be "gzip" or "raw"`)
}

/** Build the registry. One instance per server half; `dispose` must be called. */
export function createTransferServer(options: TransferServerOptions): TransferServer {
  /** Uploads by the id `begin` handed out. */
  const uploads = new Map<string, UploadRecord>()

  const limit = (key: keyof TransferLimits, fallback: number): number => {
    try {
      return limitOf(options.read()[key], fallback)
    } catch {
      return fallback
    }
  }

  const log = (level: 'debug' | 'warn', message: string): void => {
    try {
      options.log?.[level](message)
    } catch {
      // Logging is diagnostics; it must never break a transfer.
    }
  }

  /**
   * Drop bookkeeping and the staging file.
   *
   * Best effort by construction: a staging file that is already gone (abort,
   * TTL sweep, a failed `unlink` from another path) is not an error.
   */
  const forget = (upload: UploadRecord): void => {
    uploads.delete(upload.uploadId)
    try {
      unlinkSync(upload.tempPath)
    } catch {
      // already gone (or never created) — nothing to clean.
    }
  }

  /** Streaming sha256 and byte count; never loads the file into memory. */
  const digestOf = async (path: string): Promise<{ hash: string, bytes: number }> => {
    const handle = await open(path, 'r')
    try {
      const hash = createHash('sha256')
      const buffer = Buffer.allocUnsafe(1024 * 1024)
      let position = 0
      let total = 0
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position)
        if (bytesRead === 0) break
        hash.update(buffer.subarray(0, bytesRead))
        position += bytesRead
        total += bytesRead
      }
      return { hash: hash.digest('hex'), bytes: total }
    } finally {
      await handle.close()
    }
  }

  /**
   * Discard an upload and translate a failure into one clean error.
   *
   * Every commit failure path goes through here: after a refused commit the
   * staging file is gone and the id is dead, so a controller must restart the
   * file from `begin` rather than retrying a commit that can never succeed.
   */
  const failCommit = (upload: UploadRecord, message: string, code?: TransferErrorCode): never => {
    forget(upload)
    throw code === undefined ? new Error(message) : new TransferFsError(message, code)
  }

  // ----------------------------------------------------------------- begin
  const begin = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const path = stringArg('fs.put.begin', args.path, 'path')
    const maxBytes = limit('transferMaxBytes', 1024 * 1024 * 1024)
    const declared = Number(args.size)
    if (!Number.isSafeInteger(declared) || declared < 0) {
      throw new Error('fs.put.begin: size must be a non-negative safe integer')
    }
    if (declared > maxBytes) {
      throw new Error(`fs.put.begin: size ${declared} exceeds transferMaxBytes (${maxBytes})`)
    }

    const sha256 = String(args.sha256 ?? '').toLowerCase()
    if (!/^[0-9a-f]{64}$/u.test(sha256)) {
      throw new Error('fs.put.begin: sha256 must be 64 hexadecimal characters')
    }

    // Clamp rather than reject: the controller picks a block size from what it
    // measured, and this half's job is to bound the memory one block can cost.
    let chunkSize = DEFAULT_CHUNK_BYTES
    if (args.chunkSize !== undefined) {
      const asked = Number(args.chunkSize)
      if (Number.isFinite(asked)) chunkSize = Math.floor(clamp(asked, MIN_CHUNK_BYTES, MAX_CHUNK_BYTES))
    }
    const encoding = encodingOf('fs.put.begin', args.encoding, 'gzip')
    const createOnly = args.createOnly === true
    const expectedVersion = typeof args.expectedVersion === 'string' && args.expectedVersion !== ''
      ? args.expectedVersion
      : undefined

    const maxActive = Math.max(1, limit('transferMaxActive', 8))
    if (uploads.size >= maxActive) {
      throw new Error('fs.put.begin: too many active transfers')
    }

    // The staging file MUST live next to the target: `rename` is the atomic
    // commit, and a cross-volume rename degrades to copy+delete (or fails).
    mkdirSync(dirname(path), { recursive: true })
    const uploadId = randomUUID()
    const tempPath = `${path}.${uploadId}.dshremote-upload`
    writeFileSync(tempPath, Buffer.alloc(0), { flag: 'wx', mode: 0o600 })

    const upload: UploadRecord = {
      uploadId,
      path,
      tempPath,
      size: declared,
      sha256,
      chunkSize,
      encoding,
      createOnly,
      expectedVersion,
      chunks: new Map(),
      received: 0,
      lastActive: Date.now(),
    }
    uploads.set(uploadId, upload)
    log('debug', `dsh-remote-transfer: begin ${uploadId} ${path} (${declared} bytes, ${chunkSize}-byte ${encoding} blocks)`)
    return { uploadId, chunkSize, size: declared }
  }

  // ----------------------------------------------------------------- chunk
  const chunk = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const uploadId = stringArg('fs.put.chunk', args.uploadId, 'uploadId')
    const upload = uploads.get(uploadId)
    // Unknown/expired id is its own answer: the controller abandons the file and
    // restarts it, rather than retrying a block that can never land.
    if (upload === undefined) throw new Error('fs.put.chunk: unknown uploadId')

    const index = Number(args.index)
    const blockCount = Math.ceil(upload.size / upload.chunkSize)
    if (!Number.isSafeInteger(index) || index < 0 || index >= blockCount) {
      throw new Error(`fs.put.chunk: index must be an integer in 0..${Math.max(0, blockCount - 1)}`)
    }
    if (typeof args.dataB64 !== 'string') {
      throw new Error('fs.put.chunk: dataB64 must be a base64 string')
    }

    // Only the LAST block is short; every other block is exactly chunkSize.
    const expected = Math.min(upload.chunkSize, upload.size - index * upload.chunkSize)
    const encoding = encodingOf('fs.put.chunk', args.encoding, upload.encoding)
    const wire = decodeTransferBlock(args.dataB64, expected)

    let data: Buffer
    if (encoding === 'gzip') {
      try {
        // `maxOutputLength` is the zip-bomb fence: the decompressor stops one
        // byte past what this block could possibly be, before allocating more.
        data = gunzipSync(wire, { maxOutputLength: expected + 1 })
      } catch {
        throw new Error(`fs.put.chunk: block ${index} is not valid gzip`)
      }
      if (data.length !== expected) {
        throw new Error(`fs.put.chunk: block ${index} inflated to ${data.length} bytes, expected ${expected}`)
      }
    } else {
      data = wire
      if (data.length !== expected) {
        throw new Error(`fs.put.chunk: block ${index} is ${data.length} bytes, expected ${expected}`)
      }
    }

    // Positional write: blocks may arrive out of order and be re-sent; a repeat
    // rewrites the same offset with the same bytes, so it is idempotent.
    const handle = await open(upload.tempPath, 'r+')
    try {
      const { bytesWritten } = await handle.write(data, 0, data.length, index * upload.chunkSize)
      if (bytesWritten !== data.length) {
        throw new Error(`fs.put.chunk: short write for block ${index} (${bytesWritten}/${data.length})`)
      }
    } finally {
      await handle.close()
    }

    if (uploads.get(uploadId) !== upload) throw new Error('fs.put.chunk: upload was aborted')
    const previous = upload.chunks.get(index)
    if (previous === undefined) {
      upload.chunks.set(index, expected)
      upload.received += expected
    }
    upload.lastActive = Date.now()
    return { uploadId, index, received: expected }
  }

  // ---------------------------------------------------------------- commit
  const commit = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const uploadId = stringArg('fs.put.commit', args.uploadId, 'uploadId')
    const upload = uploads.get(uploadId)
    if (upload === undefined) throw new Error('fs.put.commit: unknown uploadId')

    let tempInfo
    try {
      tempInfo = await stat(upload.tempPath)
    } catch {
      return failCommit(upload, `fs.put.commit: staging file for ${upload.path} is gone`)
    }
    if (!tempInfo.isFile()) {
      return failCommit(upload, `fs.put.commit: staging path for ${upload.path} is not a regular file`)
    }
    if (tempInfo.size !== upload.size) {
      return failCommit(
        upload,
        `fs.put.commit: ${upload.path} is ${tempInfo.size} bytes, expected ${upload.size}`,
      )
    }

    // Streaming hash: a 1 GiB commit must not allocate 1 GiB (plus its hex) here.
    let digest
    try {
      digest = await digestOf(upload.tempPath)
    } catch (error) {
      return failCommit(upload, `fs.put.commit: could not read the staged bytes: ${messageOf(error)}`)
    }
    if (digest.bytes !== upload.size) {
      return failCommit(upload, `fs.put.commit: staged ${digest.bytes} bytes, expected ${upload.size}`)
    }
    if (digest.hash !== upload.sha256) {
      return failCommit(upload, `fs.put.commit: sha256 mismatch for ${upload.path} (got ${digest.hash})`)
    }

    // The guards are evaluated HERE, not at begin: the target may have changed
    // while the bytes were in flight, and "has it changed?" is only meaningful
    // at the instant the write would land.
    const existing = await stat(upload.path).catch(() => undefined)
    const beforeBytes = existing === undefined ? 0 : existing.size
    if (upload.createOnly && existing !== undefined) {
      return failCommit(
        upload,
        `cannot overwrite existing "${upload.path}" without reading it first`,
        'FS_NOT_OBSERVED',
      )
    }
    if (upload.expectedVersion !== undefined) {
      if (existing === undefined) {
        return failCommit(upload, `cannot write "${upload.path}": file no longer exists`, 'FS_STALE_VERSION')
      }
      if (versionOf(existing) !== upload.expectedVersion) {
        return failCommit(upload, `cannot write "${upload.path}": file changed since it was read`, 'FS_STALE_VERSION')
      }
    }

    // `before` feeds the controller's diff. Bounded on purpose: a 40 MiB text
    // file must not be embedded in one frame just to say "it was replaced".
    const beforeMax = limit('transferBeforeMaxBytes', 1024 * 1024)
    let before: string | null = null
    if (existing !== undefined && existing.isFile() && existing.size <= beforeMax) {
      before = await readFile(upload.path).then(bytes => bytes.toString('utf8')).catch(() => null)
    }

    try {
      renameSync(upload.tempPath, upload.path)
    } catch (error) {
      return failCommit(upload, `fs.put.commit: could not replace "${upload.path}": ${messageOf(error)}`)
    }
    uploads.delete(uploadId)

    // Same token `fs.write` returns and `fs.stat` reports, so a controller can
    // chain a guarded edit straight onto a committed transfer.
    const after = await stat(upload.path).catch(() => undefined)
    const version = after === undefined ? versionOf(tempInfo) : versionOf(after)
    log('debug', `dsh-remote-transfer: commit ${uploadId} ${upload.path} (${digest.bytes} bytes, sha256 ${digest.hash.slice(0, 12)})`)
    return {
      uploadId,
      size: upload.size,
      sha256: digest.hash,
      created: existing === undefined,
      version,
      path: upload.path,
      before,
      beforeBytes,
    }
  }

  // ----------------------------------------------------------------- abort
  const abort = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const uploadId = String(args.uploadId ?? '')
    const upload = uploadId === '' ? undefined : uploads.get(uploadId)
    if (upload === undefined) return { uploadId, aborted: false }
    forget(upload)
    log('debug', `dsh-remote-transfer: abort ${uploadId} ${upload.path}`)
    return { uploadId, aborted: true }
  }

  // ------------------------------------------------------------------- get
  const get = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const path = stringArg('fs.get', args.path, 'path')

    const rawOffset = args.offset === undefined ? 0 : Number(args.offset)
    if (!Number.isSafeInteger(rawOffset) || rawOffset < 0) {
      throw new Error('fs.get: offset must be a non-negative safe integer')
    }
    const offset = rawOffset

    const maxChunk = Math.max(1, limit('transferMaxChunkBytes', MAX_CHUNK_BYTES))
    const askedLength = args.length === undefined ? maxChunk : Number(args.length)
    const length = Number.isFinite(askedLength) ? clamp(Math.floor(askedLength), 1, maxChunk) : maxChunk
    const encoding = encodingOf('fs.get', args.encoding, 'raw')

    let info
    try {
      info = await stat(path)
    } catch (error) {
      const code = (error as { code?: unknown }).code
      if (code === 'ENOENT') throw new TransferFsError(`cannot read "${path}": not found`, 'FS_NOT_FOUND')
      throw new TransferFsError(`cannot read "${path}": ${messageOf(error)}`, 'FS_IO_ERROR')
    }
    if (!info.isFile()) {
      throw new TransferFsError(`cannot read "${path}": not a regular file`, 'FS_NOT_REGULAR_FILE')
    }

    const size = info.size
    if (offset >= size) {
      return { dataB64: '', encoding: 'raw', offset, bytes: 0, size, eof: true }
    }

    const want = Math.min(length, size - offset)
    let data = Buffer.alloc(want)
    const handle = await open(path, 'r')
    try {
      let filled = 0
      while (filled < want) {
        const { bytesRead } = await handle.read(data, filled, want - filled, offset + filled)
        if (bytesRead === 0) break
        filled += bytesRead
      }
      // A concurrent truncation can shorten the read; report what was actually
      // read rather than padding, and let `eof` describe that smaller read.
      if (filled < want) data = data.subarray(0, filled)
    } finally {
      await handle.close()
    }

    let payload = data
    let wire: TransferEncoding = 'raw'
    if (encoding === 'gzip') {
      // Compression is only worth a wire encoding when it actually pays: gzip
      // has ~20 bytes of framing, and incompressible bytes can grow slightly.
      const packed = gzipSync(data)
      if (packed.length < Math.floor(data.length * 0.95)) {
        payload = packed
        wire = 'gzip'
      }
    }
    return {
      dataB64: payload.toString('base64'),
      encoding: wire,
      offset,
      bytes: data.length,
      size,
      eof: offset + data.length >= size,
    }
  }

  /** Discard uploads idle longer than the configured TTL. */
  const sweep = (): void => {
    const ttl = Math.max(0, limit('transferUploadTtlMs', 600_000))
    const now = Date.now()
    for (const upload of [...uploads.values()]) {
      if (now - upload.lastActive <= ttl) continue
      forget(upload)
      log('debug', `dsh-remote-transfer: expired ${upload.uploadId} ${upload.path}`)
    }
  }

  const sweeper = setInterval(sweep, SWEEP_INTERVAL_MS)
  // A transfer registry must never be the reason the process stays alive.
  sweeper.unref()

  return {
    begin,
    chunk,
    commit,
    abort,
    get,
    dispose(): void {
      clearInterval(sweeper)
      for (const upload of [...uploads.values()]) forget(upload)
      uploads.clear()
    },
  }
}

/** Best-effort message from an unknown thrown value. */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
