/**
 * Fast file transfer for the **controller** half.
 *
 * The plain `fs.write` / `fs.read` ops send one whole file per request, so a
 * multi-megabyte payload over a slow tunnel pays for base64 inflation, one giant
 * frame and a single socket timeout. This module implements the client side of
 * the chunked protocol the controlled half advertises (`fs.put.*` / `fs.get`):
 *
 *   - split the payload into independently addressed chunks,
 *   - gzip each chunk when that clearly pays off (text/code: 3–5x),
 *   - keep a small number of chunk requests in flight,
 *   - checksum the whole payload end-to-end with sha256,
 *   - retry a failed chunk a couple of times, then abort the upload,
 *   - stream local files instead of holding them in memory.
 *
 * It is deliberately free of DSH imports: everything goes through a tiny
 * {@link TransferRequest} function with the shape of `link.request`, which keeps
 * this logic unit-testable with an in-memory fake peer.
 *
 * Wire contract (authoritative, shared with `transfer-server.ts`):
 *
 * - `fs.put.begin { path, size, sha256, chunkSize?, encoding?, createOnly?, expectedVersion? }`
 *   → `{ uploadId, chunkSize, size }`
 * - `fs.put.chunk { uploadId, index, dataB64, encoding }`
 *   → `{ uploadId, index, received }`; chunks may arrive out of order,
 *   duplicated or concurrently and cover exactly
 *   `[index * chunkSize, min((index + 1) * chunkSize, size))` **decoded**.
 * - `fs.put.commit { uploadId }`
 *   → `{ uploadId, size, sha256, created, version, path, before, beforeBytes }`
 * - `fs.put.abort { uploadId }` → `{ aborted }` (best effort, failure ignored)
 * - `fs.get { path, offset, length, encoding? }`
 *   → `{ dataB64, encoding, offset, bytes, size, eof }`; `bytes` is the
 *   **decoded** length of this chunk and the response may fall back to `raw`.
 *
 * An older peer does not advertise these ops at all; callers must gate on
 * {@link supportsFastTransfer} (see {@link createOpProbe}) and keep the legacy
 * single-frame path as the fallback.
 *
 * @module dsh-remote/transfer-client
 */

import { createHash, randomBytes } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, open, rename, rm, stat } from 'node:fs/promises'
import type { FileHandle } from 'node:fs/promises'
import { dirname } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'
import { decodeTransferBlock } from './transfer-codec.ts'

// ---------------------------------------------------------------------------
// Contract types
// ---------------------------------------------------------------------------

/** A request function with the shape of `LinkClient#request`. */
export interface TransferRequest {
  (op: string, args: Record<string, unknown>, timeoutMs?: number): Promise<Record<string, unknown>>
}

/** Knobs shared by upload and download. */
export interface TransferOptions {
  /** Chunk size in bytes before compression (default 1 MiB, clamped 64 KiB..8 MiB). */
  chunkSize?: number
  /** Maximum chunk requests in flight (default 4, clamped 1..8). */
  concurrency?: number
  /** gzip each chunk when it pays off (default true). */
  compression?: boolean
  /** Per-chunk request timeout (default 600_000 ms). */
  timeoutMs?: number
  /** Local cancellation: stop dispatching and abort the remote side. */
  signal?: AbortSignal
  /** Called after every finished chunk with progress over the decoded payload. */
  onProgress?: (doneBytes: number, totalBytes: number) => void
}

/** Upload-only options. */
export interface UploadOptions extends TransferOptions {
  /** Refuse to overwrite a file that already exists on the peer. */
  createOnly?: boolean
  /** Refuse the write unless the peer file still has this version. */
  expectedVersion?: string
}

/** Download-to-buffer options. */
export interface DownloadOptions extends TransferOptions {
  /** Refuse to download a file larger than this. */
  maxBytes?: number
}

/** Download-to-file options. */
export interface DownloadFileOptions extends TransferOptions {
  /** Replace an existing local file (default true); false refuses up front. */
  overwrite?: boolean
}

/** Result of a fast upload. */
export interface UploadResult {
  uploadId: string
  /** Payload size in bytes (decoded). */
  bytes: number
  /** sha256 of the whole payload, 64 hex chars. */
  sha256: string
  created: boolean
  version: string | null
  path: string
  before: string | null
  beforeBytes: number
  chunkSize: number
  /** Wall-clock time of the whole transfer, including `begin` and `commit`. */
  durationMs: number
  /** Effective throughput in **megabits per second** (as the field name says). */
  rateMbps: number
}

/** Result of a download to memory. */
export interface DownloadBufferResult {
  data: Uint8Array
  size: number
  sha256: string
}

/** Result of a download to a local file. */
export interface DownloadFileResult {
  bytes: number
  sha256: string
  size: number
  durationMs: number
  rateMbps: number
}

/** One planned chunk: a half-open decoded byte range. */
export interface ChunkPlan {
  index: number
  offset: number
  length: number
}

// ---------------------------------------------------------------------------
// Tuning constants and small helpers
// ---------------------------------------------------------------------------

/** 1 MiB: big enough to amortise a ~78 ms RTT, small enough to retry cheaply. */
const DEFAULT_CHUNK_BYTES = 1024 * 1024
const MIN_CHUNK_BYTES = 64 * 1024
const MAX_CHUNK_BYTES = 8 * 1024 * 1024
const DEFAULT_CONCURRENCY = 4
const MAX_CONCURRENCY = 8
const DEFAULT_TIMEOUT_MS = 600_000
/** A chunk request is attempted once plus at most this many retries. */
const MAX_RETRIES = 2
/** Exponential-ish micro backoff; deliberately short, the tunnel is the cost. */
const RETRY_DELAYS_MS = [50, 150] as const
/** gzip is used only when it shrinks the chunk below this fraction. */
const COMPRESSION_RATIO = 0.95
/** Capability probe cache lifetime (matches the client's usage probe choice). */
const DEFAULT_PROBE_TTL_MS = 10 * 60_000

/** The exact op set a peer must advertise for the fast path to be usable. */
export const TRANSFER_OPS = [
  'fs.put.begin',
  'fs.put.chunk',
  'fs.put.commit',
  'fs.put.abort',
  'fs.get',
] as const

/** Does `sysinfo.ops` advertise every op the fast path needs? */
export function supportsFastTransfer(ops: readonly string[]): boolean {
  return TRANSFER_OPS.every(op => ops.includes(op))
}

/** An `AbortError`-shaped rejection, which callers can recognise by `name`. */
function abortError(): Error {
  const error = new Error('transfer aborted')
  error.name = 'AbortError'
  return error
}

/** True for a cancellation raised here (never for a peer or filesystem error). */
export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError'
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw abortError()
}

/**
 * Settle with `work`, but reject with an `AbortError` as soon as `signal` fires.
 *
 * The in-flight request itself is not cancelleable (the link has no per-request
 * abort), so this stops the *pipeline* immediately; any reply that arrives later
 * is routed to a request nobody waits for and is dropped by the link.
 */
function abortable<T>(work: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return work
  if (signal.aborted === true) return Promise.reject(abortError())
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => { reject(abortError()) }
    signal.addEventListener('abort', onAbort, { once: true })
    work.then(
      (value) => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort)
        reject(error instanceof Error ? error : new Error(String(error)))
      },
    )
  })
}

/** Cancellable short sleep used between retries. */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal === undefined) return new Promise(resolve => setTimeout(resolve, ms))
  throwIfAborted(signal)
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = (): void => {
      clearTimeout(timer)
      reject(abortError())
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

/** Clamp a requested chunk size into the range the protocol allows. */
function resolveChunkSize(chunkSize: number | undefined): number {
  if (chunkSize === undefined || !Number.isFinite(chunkSize)) return DEFAULT_CHUNK_BYTES
  return Math.min(MAX_CHUNK_BYTES, Math.max(MIN_CHUNK_BYTES, Math.floor(chunkSize)))
}

/** Clamp the parallelism knob. */
function resolveConcurrency(concurrency: number | undefined): number {
  if (concurrency === undefined || !Number.isFinite(concurrency)) return DEFAULT_CONCURRENCY
  return Math.min(MAX_CONCURRENCY, Math.max(1, Math.floor(concurrency)))
}

function resolveTimeout(timeoutMs: number | undefined): number {
  if (timeoutMs === undefined || !Number.isFinite(timeoutMs) || timeoutMs <= 0) return DEFAULT_TIMEOUT_MS
  return Math.floor(timeoutMs)
}

/** Mbit/s, from bytes over a wall-clock span. */
function rateMbpsOf(bytes: number, durationMs: number): number {
  if (bytes <= 0 || durationMs <= 0) return 0
  return Math.round((bytes * 8) / 1e6 / (durationMs / 1000) * 100) / 100
}

function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex')
}

function isMissingFile(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT'
}

/** A local error carrying the peer's typed code, same shape as `link.request`. */
function transferError(message: string, peerCode?: string): Error {
  const error = new Error(message)
  if (peerCode !== undefined) (error as Error & { peerCode?: string }).peerCode = peerCode
  return error
}

// ---------------------------------------------------------------------------
// Pure planning / compression helpers (unit-tested directly)
// ---------------------------------------------------------------------------

/**
 * Split a payload into the chunks the protocol addresses by index.
 *
 * `chunkSize` is clamped to 64 KiB..8 MiB, and `size` is truncated to an
 * integer byte count. An empty (or non-positive) payload yields no chunks: the
 * upload becomes a bare `begin` + `commit`.
 */
export function planChunks(size: number, chunkSize: number): ChunkPlan[] {
  const total = Number.isFinite(size) && size > 0 ? Math.floor(size) : 0
  return planChunksWithStep(total, resolveChunkSize(chunkSize))
}

/** {@link planChunks} with an already-resolved step (the peer may pick it). */
function planChunksWithStep(total: number, step: number): ChunkPlan[] {
  const chunks: ChunkPlan[] = []
  if (total <= 0) return chunks
  const safeStep = Math.max(1, Math.floor(step))
  for (let offset = 0, index = 0; offset < total; offset += safeStep, index += 1) {
    chunks.push({ index, offset, length: Math.min(safeStep, total - offset) })
  }
  return chunks
}

/**
 * gzip a chunk when that is clearly worth it, otherwise leave it raw.
 *
 * The 5% margin stops "barely smaller" from paying the decompression cost on the
 * peer; it also means random (already compressed) data stays raw, which is why
 * the wire format carries the encoding per chunk.
 */
export function compressChunk(
  raw: Uint8Array,
  compression: boolean,
): { data: Uint8Array, encoding: 'gzip' | 'raw' } {
  if (!compression || raw.length === 0) return { data: raw, encoding: 'raw' }
  let gzipped: Uint8Array
  try {
    gzipped = gzipSync(raw)
  } catch {
    // zlib can refuse pathological inputs; sending the chunk raw is always valid.
    return { data: raw, encoding: 'raw' }
  }
  if (gzipped.length >= raw.length * COMPRESSION_RATIO) return { data: raw, encoding: 'raw' }
  return { data: gzipped, encoding: 'gzip' }
}

/**
 * Build a cached `sysinfo.ops` capability probe.
 *
 * The peer is asked once and the answer is trusted for `ttlMs` (default ten
 * minutes), so a peer without the fast path neither logs "unknown op" on every
 * write nor costs a round trip each time. A **failed** probe is not cached: a
 * tunnel that is down for a moment must not disable the fast path for ten
 * minutes. Failures resolve to `false` (the safe, legacy-path answer).
 */
export function createOpProbe(
  request: TransferRequest,
  ttlMs: number = DEFAULT_PROBE_TTL_MS,
): () => Promise<boolean> {
  let cached: { at: number, supported: boolean } | undefined
  let pending: Promise<boolean> | undefined
  return async (): Promise<boolean> => {
    const hit = cached
    if (hit !== undefined && Date.now() - hit.at < ttlMs) return hit.supported
    if (pending !== undefined) return await pending
    const started = (async (): Promise<boolean> => {
      try {
        const info = await request('sysinfo', {}, 30_000)
        const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
        const supported = supportsFastTransfer(ops)
        cached = { at: Date.now(), supported }
        return supported
      } catch {
        return false
      }
    })()
    pending = started
    try {
      return await started
    } finally {
      if (pending === started) pending = undefined
    }
  }
}

// ---------------------------------------------------------------------------
// Shared plumbing: retrying requests and a bounded worker pool
// ---------------------------------------------------------------------------

/**
 * One idempotent chunk request, retried at most {@link MAX_RETRIES} times.
 *
 * Only `fs.put.chunk` / `fs.get` go through here: they are idempotent by
 * contract (duplicate chunks are tolerated, gets are stateless). Cancellation
 * is never retried.
 */
async function requestChunk(
  request: TransferRequest,
  op: string,
  args: Record<string, unknown>,
  options: TransferOptions,
): Promise<Record<string, unknown>> {
  const timeoutMs = resolveTimeout(options.timeoutMs)
  let lastError: unknown
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    throwIfAborted(options.signal)
    try {
      return await abortable(request(op, args, timeoutMs), options.signal)
    } catch (error) {
      lastError = error
      if (isAbortError(error)) throw error
      if (attempt === MAX_RETRIES) break
      await sleep(RETRY_DELAYS_MS[attempt] ?? 150, options.signal)
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError))
}

/**
 * Run `worker` for indexes `0..total-1`, at most `concurrency` at a time.
 *
 * The first failure stops new dispatches; workers already in flight are awaited
 * so no request is left dangling behind the thrown error. That bounded tail is
 * what keeps the memory ceiling at `concurrency * chunkSize`.
 */
async function runPool(
  total: number,
  concurrency: number,
  worker: (index: number) => Promise<void>,
): Promise<void> {
  if (total <= 0) return
  const lanes = Math.min(total, Math.max(1, concurrency))
  let next = 0
  let failed = false
  let failure: unknown
  const lane = async (): Promise<void> => {
    for (;;) {
      if (failed) return
      const index = next
      next += 1
      if (index >= total) return
      try {
        await worker(index)
      } catch (error) {
        if (!failed) {
          failed = true
          failure = error
        }
        return
      }
    }
  }
  await Promise.all(Array.from({ length: lanes }, () => lane()))
  if (failed) throw failure instanceof Error ? failure : new Error(String(failure))
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

/** A decoded payload source that can be read in ranges (memory or file). */
interface UploadSource {
  size: number
  sha256: string
  read(offset: number, length: number): Promise<Uint8Array>
}

/** Best-effort cleanup of a half-finished upload. Never throws. */
async function abortUpload(request: TransferRequest, uploadId: string): Promise<void> {
  try {
    await request('fs.put.abort', { uploadId }, 30_000)
  } catch {
    // The contract makes abort advisory: an expired upload is already gone and a
    // downed link has nothing to talk to. Either way the local call must not fail
    // because cleanup did.
  }
}

/** Shared implementation behind {@link uploadBuffer} and {@link uploadFile}. */
async function uploadSource(
  request: TransferRequest,
  remotePath: string,
  source: UploadSource,
  options: UploadOptions,
): Promise<UploadResult> {
  const startedAt = Date.now()
  const signal = options.signal
  throwIfAborted(signal)
  const compression = options.compression !== false
  const timeoutMs = resolveTimeout(options.timeoutMs)
  const requestedChunkSize = resolveChunkSize(options.chunkSize)

  const beginArgs: Record<string, unknown> = {
    path: remotePath,
    size: source.size,
    sha256: source.sha256,
    chunkSize: requestedChunkSize,
    encoding: compression ? 'gzip' : 'raw',
    ...(options.createOnly === true ? { createOnly: true } : {}),
    ...(options.expectedVersion === undefined ? {} : { expectedVersion: options.expectedVersion }),
  }
  const begun = await abortable(request('fs.put.begin', beginArgs, timeoutMs), signal)
  const uploadId = typeof begun.uploadId === 'string' && begun.uploadId !== '' ? begun.uploadId : undefined
  if (uploadId === undefined) throw new Error('transfer: fs.put.begin returned no uploadId')

  // The peer may adjust the chunk size; indexes are addressed on the agreedsize,
  // so every later request MUST use the value from `begin`.
  const proposed = Number(begun.chunkSize)
  const chunkSize = Number.isFinite(proposed) && proposed > 0
    ? Math.floor(proposed)
    : requestedChunkSize
  const chunks = planChunksWithStep(source.size, chunkSize)
  const total = source.size
  let doneBytes = 0
  let committed = false
  /**
   * How far the upload got when it failed; copied onto the error as
   * `transferPhase` so callers can tell "nothing was written" (safe to fall back
   * to the legacy single-frame write) from "commit was attempted, outcome
   * unknown" (must not be blindly replayed).
   */
  let phase: 'begin' | 'chunk' | 'commit' | 'done' = 'begin'

  try {
    phase = 'chunk'
    await runPool(chunks.length, resolveConcurrency(options.concurrency), async (index) => {
      const chunk = chunks[index]
      if (chunk === undefined) return
      throwIfAborted(signal)
      const raw = await source.read(chunk.offset, chunk.length)
      if (raw.length !== chunk.length) {
        throw new Error('transfer: local file changed size while uploading')
      }
      const packed = compressChunk(raw, compression)
      await requestChunk(request, 'fs.put.chunk', {
        uploadId,
        index: chunk.index,
        dataB64: Buffer.from(packed.data).toString('base64'),
        encoding: packed.encoding,
      }, options)
      doneBytes += raw.length
      try {
        options.onProgress?.(doneBytes, total)
      } catch {
        // A progress listener must never be able to fail a transfer.
      }
    })

    phase = 'commit'
    const commit = await abortable(request('fs.put.commit', { uploadId }, timeoutMs), signal)
    committed = true
    phase = 'done'
    const remoteSha = typeof commit.sha256 === 'string' ? commit.sha256.toLowerCase() : ''
    if (remoteSha !== '' && remoteSha !== source.sha256) {
      throw new Error('transfer: checksum mismatch')
    }
    const remoteSize = Number(commit.size)
    if (Number.isFinite(remoteSize) && remoteSize !== source.size) {
      throw new Error('transfer: size mismatch after commit')
    }
    const durationMs = Math.max(0, Date.now() - startedAt)
    return {
      uploadId,
      bytes: source.size,
      sha256: source.sha256,
      created: commit.created === true,
      version: typeof commit.version === 'string' ? commit.version : null,
      path: typeof commit.path === 'string' ? commit.path : remotePath,
      before: typeof commit.before === 'string' ? commit.before : null,
      beforeBytes: Number.isFinite(Number(commit.beforeBytes)) ? Number(commit.beforeBytes) : 0,
      chunkSize,
      durationMs,
      rateMbps: rateMbpsOf(source.size, durationMs),
    }
  } catch (error) {
    // Any failure before commit leaves a temporary upload on the peer. A failed
    // commit may already have cleaned it, in which case abort is a harmless no-op.
    if (!committed) await abortUpload(request, uploadId)
    if (error instanceof Error) {
      (error as Error & { transferPhase?: string }).transferPhase = phase
    }
    throw error
  }
}

/**
 * Upload an in-memory payload.
 *
 * The whole payload is hashed before the first request so the peer can validate
 * the assembled file against a value the client computed, not the reverse.
 */
export async function uploadBuffer(
  request: TransferRequest,
  remotePath: string,
  data: Uint8Array,
  options: UploadOptions = {},
): Promise<UploadResult> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  return await uploadSource(request, remotePath, {
    size: bytes.length,
    sha256: sha256Hex(bytes),
    read: async (offset, length) => bytes.subarray(offset, offset + length),
  }, options)
}

/** Stream a local file's sha256, never holding the file in memory. */
async function hashFile(path: string, signal?: AbortSignal): Promise<string> {
  const hash = createHash('sha256')
  const stream = createReadStream(path)
  try {
    for await (const chunk of stream) {
      throwIfAborted(signal)
      hash.update(chunk as Buffer)
    }
  } finally {
    stream.destroy()
  }
  return hash.digest('hex')
}

/**
 * Upload a local file, streaming it in ranges.
 *
 * Two sequential passes (hash, then upload) keep the memory ceiling at
 * `concurrency * chunkSize` even for a very large source. The file is read with
 * positioned reads, so chunks can be requested in parallel and out of order.
 */
export async function uploadFile(
  request: TransferRequest,
  localPath: string,
  remotePath: string,
  options: UploadOptions = {},
): Promise<UploadResult> {
  throwIfAborted(options.signal)
  const info = await stat(localPath)
  if (!info.isFile()) throw new Error(`transfer: "${localPath}" is not a regular file`)
  const sha256 = await hashFile(localPath, options.signal)
  const handle: FileHandle = await open(localPath, 'r')
  try {
    return await uploadSource(request, remotePath, {
      size: info.size,
      sha256,
      read: async (offset, length) => {
        const buffer = Buffer.allocUnsafe(length)
        let filled = 0
        while (filled < length) {
          const { bytesRead } = await handle.read(buffer, filled, length - filled, offset + filled)
          if (bytesRead === 0) break
          filled += bytesRead
        }
        if (filled !== length) throw new Error('transfer: local file changed size while uploading')
        return buffer.subarray(0, filled)
      },
    }, options)
  } finally {
    await handle.close().catch(() => { /* already closed or never opened */ })
  }
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

/** Where a download writes its decoded chunks. */
interface DownloadSink {
  write(offset: number, data: Uint8Array): Promise<void>
}

/** One fetched chunk plus the peer's EOF flag. */
interface FetchedChunk {
  data: Uint8Array
  eof: boolean
}

/** Ask the peer for the file size (the plan needs it before the first get). */
async function remoteSizeOf(
  request: TransferRequest,
  remotePath: string,
  options: TransferOptions,
  maxBytes?: number,
): Promise<number> {
  const timeoutMs = resolveTimeout(options.timeoutMs)
  const info = await abortable(request('fs.stat', { path: remotePath }, timeoutMs), options.signal)
  if (info.exists !== true) {
    throw transferError(`cannot read "${remotePath}": not found`, 'FS_NOT_FOUND')
  }
  if (info.isDir === true) {
    throw transferError(`cannot read "${remotePath}": not a regular file`, 'FS_NOT_REGULAR_FILE')
  }
  const size = Number(info.size)
  if (!Number.isFinite(size) || size < 0) throw new Error(`transfer: peer reported an invalid size for "${remotePath}"`)
  if (maxBytes !== undefined && Number.isFinite(maxBytes) && size > maxBytes) {
    throw transferError(
      `cannot read "${remotePath}": file exceeds ${maxBytes} bytes`,
      'FS_TOO_LARGE',
    )
  }
  throwIfAborted(options.signal)
  return Math.floor(size)
}

/**
 * Fetch one chunk and decode it.
 *
 * The peer decides the encoding per response (it falls back to `raw` when gzip
 * is not worthwhile), so the reply's own `encoding` wins over what was asked.
 */
async function fetchChunk(
  request: TransferRequest,
  remotePath: string,
  chunk: ChunkPlan,
  options: TransferOptions,
): Promise<FetchedChunk> {
  const compression = options.compression !== false
  const reply = await requestChunk(request, 'fs.get', {
    path: remotePath,
    offset: chunk.offset,
    length: chunk.length,
    encoding: compression ? 'gzip' : 'raw',
  }, options)

  const encoded = decodeTransferBlock(reply.dataB64, chunk.length)
  if (reply.encoding !== 'gzip' && reply.encoding !== 'raw') throw new Error('transfer: unknown chunk encoding')
  const encoding = reply.encoding
  let data: Uint8Array
  if (encoding === 'gzip') {
    try {
      data = new Uint8Array(gunzipSync(encoded, { maxOutputLength: chunk.length + 1 }))
    } catch {
      throw new Error('transfer: corrupt gzip chunk from peer')
    }
  } else {
    data = new Uint8Array(encoded)
  }

  const declaredBytes = Number(reply.bytes)
  if (Number.isFinite(declaredBytes) && declaredBytes !== data.length) {
    throw new Error(`transfer: chunk ${chunk.index} size mismatch (${data.length} != ${declaredBytes})`)
  }
  if (data.length > chunk.length) {
    throw new Error(`transfer: chunk ${chunk.index} is longer than requested`)
  }
  const replyOffset = Number(reply.offset)
  if (Number.isFinite(replyOffset) && replyOffset !== chunk.offset) {
    throw new Error(`transfer: chunk ${chunk.index} offset mismatch`)
  }
  return { data, eof: reply.eof === true }
}

/** Compare the downloaded payload against the peer's own sha256. */
async function verifyRemoteHash(
  request: TransferRequest,
  remotePath: string,
  localSha: string,
  options: TransferOptions,
): Promise<void> {
  const reply = await abortable(
    request('fs.hash', { path: remotePath }, resolveTimeout(options.timeoutMs)),
    options.signal,
  )
  const remoteSha = typeof reply.hash === 'string' ? reply.hash.toLowerCase() : ''
  if (remoteSha === '') throw new Error('transfer: fs.hash returned no digest')
  if (remoteSha !== localSha) throw new Error('transfer: checksum mismatch')
}

/**
 * Download a remote file into memory.
 *
 * Chunks are fetched in parallel and reassembled by offset. The assembled bytes
 * are hashed locally and compared with `fs.hash` on the peer; a mismatch throws
 * and nothing is handed back.
 */
export async function downloadToBuffer(
  request: TransferRequest,
  remotePath: string,
  options: DownloadOptions = {},
): Promise<DownloadBufferResult> {
  const size = await remoteSizeOf(request, remotePath, options, options.maxBytes)
  const chunks = planChunks(size, options.chunkSize ?? DEFAULT_CHUNK_BYTES)
  const buffer = new Uint8Array(size)
  let effectiveSize = size
  let doneBytes = 0

  await runPool(chunks.length, resolveConcurrency(options.concurrency), async (index) => {
    const chunk = chunks[index]
    if (chunk === undefined) return
    throwIfAborted(options.signal)
    const fetched = await fetchChunk(request, remotePath, chunk, options)
    buffer.set(fetched.data, chunk.offset)
    // A shrinking file can end earlier than `fs.stat` said. Remember the earliest
    // real end so the result is trimmed to what was actually fetched.
    if (fetched.eof && fetched.data.length < chunk.length) {
      effectiveSize = Math.min(effectiveSize, chunk.offset + fetched.data.length)
    }
    doneBytes += fetched.data.length
    try {
      options.onProgress?.(doneBytes, size)
    } catch {
      // Progress listeners are advisory.
    }
  })

  const data = effectiveSize === size ? buffer : buffer.slice(0, effectiveSize)
  const sha256 = sha256Hex(data)
  await verifyRemoteHash(request, remotePath, sha256, options)
  return { data, size: effectiveSize, sha256 }
}

/** Write a decoded chunk into an open local file at its absolute offset. */
async function writeAt(handle: FileHandle, offset: number, data: Uint8Array): Promise<void> {
  let written = 0
  while (written < data.length) {
    const { bytesWritten } = await handle.write(data, written, data.length - written, offset + written)
    if (bytesWritten <= 0) throw new Error('transfer: local write made no progress')
    written += bytesWritten
  }
}

/**
 * Replace `target` with `temp`, tolerating the Windows failure modes of a rename
 * over an existing file.
 *
 * `fs.rename` normally replaces the destination atomically on both platforms,
 * but Windows can answer EPERM/EBUSY when another process holds the target open
 * (antivirus, editor). The fallback (remove, then rename) is not atomic but is
 * the only way forward there; it is last-resort and only for those codes.
 */
async function replaceFile(tempPath: string, targetPath: string): Promise<void> {
  try {
    await rename(tempPath, targetPath)
    return
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    const retryable = code === 'EEXIST' || code === 'EPERM' || code === 'EACCES' || code === 'EBUSY'
    if (!retryable) throw error
  }
  await rm(targetPath, { force: true })
  await rename(tempPath, targetPath)
}

/**
 * Download a remote file to a local path.
 *
 * The bytes land in `<localPath>.<random>.dshremote-tmp` next to the target, are
 * verified against the peer's sha256, and are renamed into place only then. Any
 * failure or cancellation removes the temporary file, so a stopped download can
 * never leave a half-written file that looks complete.
 */
export async function downloadToFile(
  request: TransferRequest,
  remotePath: string,
  localPath: string,
  options: DownloadFileOptions = {},
): Promise<DownloadFileResult> {
  const startedAt = Date.now()
  throwIfAborted(options.signal)
  if (options.overwrite === false) {
    const existing = await stat(localPath).catch((error: unknown) => {
      if (isMissingFile(error)) return undefined
      throw error
    })
    if (existing !== undefined) {
      throw new Error(`transfer: refusing to overwrite existing "${localPath}"`)
    }
  }
  await mkdir(dirname(localPath), { recursive: true })
  const tempPath = `${localPath}.${randomBytes(6).toString('hex')}.dshremote-tmp`
  const handle = await open(tempPath, 'wx')
  let closed = false
  let renamed = false
  try {
    const size = await remoteSizeOf(request, remotePath, options)
    const chunks = planChunks(size, options.chunkSize ?? DEFAULT_CHUNK_BYTES)
    let effectiveSize = size
    let doneBytes = 0
    const sink: DownloadSink = {
      write: async (offset, data) => { await writeAt(handle, offset, data) },
    }
    await runPool(chunks.length, resolveConcurrency(options.concurrency), async (index) => {
      const chunk = chunks[index]
      if (chunk === undefined) return
      throwIfAborted(options.signal)
      const fetched = await fetchChunk(request, remotePath, chunk, options)
      // Do not write past the earliest known real end of a shrinking file.
      const writable = Math.max(0, Math.min(fetched.data.length, effectiveSize - chunk.offset))
      if (writable > 0) await sink.write(chunk.offset, fetched.data.subarray(0, writable))
      if (fetched.eof && fetched.data.length < chunk.length) {
        effectiveSize = Math.min(effectiveSize, chunk.offset + fetched.data.length)
      }
      doneBytes += fetched.data.length
      try {
        options.onProgress?.(doneBytes, size)
      } catch {
        // Progress listeners are advisory.
      }
    })

    if (effectiveSize < size) await handle.truncate(effectiveSize)
    await handle.close()
    closed = true
    throwIfAborted(options.signal)

    const sha256 = await hashFile(tempPath, options.signal)
    await verifyRemoteHash(request, remotePath, sha256, options)
    await replaceFile(tempPath, localPath)
    renamed = true
    const durationMs = Math.max(0, Date.now() - startedAt)
    return {
      bytes: effectiveSize,
      sha256,
      size: effectiveSize,
      durationMs,
      rateMbps: rateMbpsOf(effectiveSize, durationMs),
    }
  } finally {
    if (!closed) await handle.close().catch(() => { /* best effort */ })
    if (!renamed) await rm(tempPath, { force: true }).catch(() => { /* best effort */ })
  }
}
