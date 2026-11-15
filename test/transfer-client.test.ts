/**
 * Self-test for `src/transfer-client.ts` — the controller half of the chunked
 * fast-transfer path.
 *
 * Everything is exercised against a **fake peer**: an in-memory implementation of
 * the `fs.put.*` / `fs.get` / `fs.stat` / `fs.hash` wire contract from
 * `transfer-server.ts`. That is the point of the module's `TransferRequest`
 * indirection — the scheduling, compression, checksum, retry and local-file
 * safety logic runs for real, without a socket or a second harness.
 *
 * The fake deliberately misbehaves: out-of-order chunks, transient and permanent
 * failures, duplicated/retried indexes, compressed and raw responses, corrupt
 * gzip, and a lying `fs.hash`.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-plugins/dsh-remote/test/transfer-client.test.ts
 */

import { createHash, randomBytes } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'

import {
  TRANSFER_OPS,
  compressChunk,
  createOpProbe,
  downloadToBuffer,
  downloadToFile,
  isAbortError,
  planChunks,
  uploadBuffer,
  uploadFile,
} from '../src/transfer-client.ts'
import type { TransferRequest } from '../src/transfer-client.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

const sleep = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms))
const sha256 = (data: Uint8Array): string => createHash('sha256').update(data).digest('hex')
const utf8 = (text: string): Uint8Array => new Uint8Array(Buffer.from(text, 'utf8'))

// ---------------------------------------------------------------------------
// Fake peer: the server half's contract, in memory and able to misbehave
// ---------------------------------------------------------------------------

interface FakeUpload {
  path: string
  size: number
  sha256: string
  chunkSize: number
  data: Uint8Array
  createOnly: boolean
  expectedVersion: string | undefined
  committed: boolean
}

class FakePeer {
  /** Advertised ops; tests drop entries to simulate an older peer. */
  ops: string[] = [...TRANSFER_OPS]
  /** Remote files, by path. */
  files = new Map<string, Uint8Array>()
  uploads = new Map<string, FakeUpload>()
  abortedUploads: string[] = []
  /** Order in which chunk requests SUCCEEDED (retries included). */
  chunkOrder: number[] = []
  chunkAttempts = new Map<number, number>()
  maxChunksInFlight = 0
  /** Per-index artificial latency, to force out-of-order completion. */
  chunkDelayMs = new Map<number, number>()
  /** Per-index remaining injected failures (each fails one attempt). */
  failChunks = new Map<number, number>()
  failAllChunks = false
  /** Force the chunk size the peer announces, independent of the client's ask. */
  chunkSizeOverride: number | undefined
  sysinfoCalls = 0
  sysinfoFailures = 0
  hashOverrides = new Map<string, string>()
  corruptOffsets = new Set<number>()
  getDelayMs = 0
  statDelayMs = 0
  /** Encodings the peer chose for `fs.get` responses, in order. */
  responseEncodings: string[] = []

  private chunksInFlight = 0
  private counter = 0

  request: TransferRequest = async (op, args, _timeoutMs) => {
    switch (op) {
      case 'sysinfo': {
        this.sysinfoCalls += 1
        if (this.sysinfoFailures > 0) {
          this.sysinfoFailures -= 1
          throw new Error('injected sysinfo failure')
        }
        return { ok: true, ops: [...this.ops], build: 'r19' }
      }
      case 'fs.put.begin': return this.begin(args)
      case 'fs.put.chunk': return await this.chunk(args)
      case 'fs.put.commit': return this.commit(args)
      case 'fs.put.abort': return this.abort(args)
      case 'fs.get': return await this.get(args)
      case 'fs.stat': return await this.statOf(args)
      case 'fs.hash': return this.hashOf(args)
      default: throw new Error(`unknown op ${op}`)
    }
  }

  private begin(args: Record<string, unknown>): Record<string, unknown> {
    const path = String(args.path ?? '')
    const size = Number(args.size)
    const sha = String(args.sha256 ?? '')
    if (!/^[0-9a-f]{64}$/u.test(sha)) throw new Error('begin: bad sha256')
    if (!Number.isFinite(size) || size < 0) throw new Error('begin: bad size')
    const chunkSize = this.chunkSizeOverride ?? Number(args.chunkSize ?? 0)
    if (!Number.isFinite(chunkSize) || chunkSize <= 0) throw new Error('begin: bad chunkSize')
    this.counter += 1
    const uploadId = `up-${this.counter}`
    this.uploads.set(uploadId, {
      path,
      size,
      sha256: sha,
      chunkSize,
      data: new Uint8Array(size),
      createOnly: args.createOnly === true,
      expectedVersion: typeof args.expectedVersion === 'string' ? args.expectedVersion : undefined,
      committed: false,
    })
    return { uploadId, chunkSize, size }
  }

  private async chunk(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const index = Number(args.index)
    const uploadId = String(args.uploadId ?? '')
    this.chunkAttempts.set(index, (this.chunkAttempts.get(index) ?? 0) + 1)
    this.chunksInFlight += 1
    this.maxChunksInFlight = Math.max(this.maxChunksInFlight, this.chunksInFlight)
    try {
      const delay = this.chunkDelayMs.get(index)
      if (delay !== undefined) await sleep(delay)
      if (this.failAllChunks) throw new Error('injected permanent chunk failure')
      const remaining = this.failChunks.get(index) ?? 0
      if (remaining > 0) {
        this.failChunks.set(index, remaining - 1)
        throw new Error(`injected transient chunk failure ${index}`)
      }
      const upload = this.uploads.get(uploadId)
      if (upload === undefined) throw new Error('chunk: unknown uploadId')
      const raw = Buffer.from(String(args.dataB64 ?? ''), 'base64')
      const decoded = args.encoding === 'gzip' ? new Uint8Array(gunzipSync(raw)) : new Uint8Array(raw)
      const start = index * upload.chunkSize
      const expected = Math.min(upload.chunkSize, upload.size - start)
      if (decoded.length !== expected) {
        throw new Error(`chunk ${index}: decoded length ${decoded.length} != expected ${expected}`)
      }
      upload.data.set(decoded, start)
      this.chunkOrder.push(index)
      return { uploadId, index, received: decoded.length }
    } finally {
      this.chunksInFlight -= 1
    }
  }

  private commit(args: Record<string, unknown>): Record<string, unknown> {
    const uploadId = String(args.uploadId ?? '')
    const upload = this.uploads.get(uploadId)
    if (upload === undefined) throw new Error('commit: unknown uploadId')
    const actual = sha256(upload.data)
    if (actual !== upload.sha256) throw new Error('commit: checksum mismatch')
    if (upload.createOnly && this.files.has(upload.path)) throw new Error('commit: already exists')
    this.files.set(upload.path, upload.data)
    upload.committed = true
    return {
      uploadId,
      size: upload.size,
      sha256: actual,
      created: true,
      version: `v-${upload.size}`,
      path: upload.path,
      before: null,
      beforeBytes: 0,
    }
  }

  private abort(args: Record<string, unknown>): Record<string, unknown> {
    const uploadId = String(args.uploadId ?? '')
    this.abortedUploads.push(uploadId)
    this.uploads.delete(uploadId)
    return { aborted: true }
  }

  private async get(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.getDelayMs > 0) await sleep(this.getDelayMs)
    const path = String(args.path ?? '')
    const file = this.files.get(path)
    if (file === undefined) throw new Error(`get: no such file "${path}"`)
    const offset = Number(args.offset ?? 0)
    const length = Number(args.length ?? 0)
    const slice = file.subarray(offset, Math.min(offset + length, file.length))
    const gzipped = gzipSync(slice)
    const useGzip = args.encoding !== 'raw' && gzipped.length < slice.length * 0.95
    const encoding = useGzip ? 'gzip' : 'raw'
    this.responseEncodings.push(encoding)
    const isCorrupt = this.corruptOffsets.has(offset)
    // A corrupt gzip response: valid base64, invalid deflate stream.
    const dataB64 = isCorrupt
      ? Buffer.from('definitely not a gzip stream').toString('base64')
      : Buffer.from(useGzip ? gzipped : slice).toString('base64')
    return {
      dataB64,
      encoding: isCorrupt ? 'gzip' : encoding,
      offset,
      bytes: slice.length,
      size: file.length,
      eof: offset + slice.length >= file.length,
    }
  }

  private async statOf(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.statDelayMs > 0) await sleep(this.statDelayMs)
    const path = String(args.path ?? '')
    const file = this.files.get(path)
    if (file === undefined) return { exists: false }
    return { exists: true, isDir: false, size: file.length, mtimeMs: 0, version: `v-${file.length}` }
  }

  private hashOf(args: Record<string, unknown>): Record<string, unknown> {
    const path = String(args.path ?? '')
    const file = this.files.get(path)
    if (file === undefined) throw new Error(`hash: no such file "${path}"`)
    return {
      algo: 'sha256',
      hash: this.hashOverrides.get(path) ?? sha256(file),
      bytes: file.length,
    }
  }

  resetTransient(): void {
    this.chunkOrder = []
    this.chunkAttempts.clear()
    this.maxChunksInFlight = 0
    this.responseEncodings = []
  }
}

// ---------------------------------------------------------------------------
// 1. planChunks: the index <-> byte-range mapping
// ---------------------------------------------------------------------------

console.log('\n== 1. planChunks ==')
{
  check('0 bytes plans no chunks', planChunks(0, 1024).length === 0)
  check('negative size plans no chunks', planChunks(-5, 1024).length === 0)
  check('1 byte is one 1-byte chunk',
    JSON.stringify(planChunks(1, 1024)) === JSON.stringify([{ index: 0, offset: 0, length: 1 }]),
    JSON.stringify(planChunks(1, 1024)))

  const exact = planChunks(4 * 64 * 1024, 64 * 1024)
  check('exact division yields 4 equal chunks',
    exact.length === 4 && exact.every((chunk, i) => chunk.offset === i * 64 * 1024 && chunk.length === 64 * 1024),
    JSON.stringify(exact))

  const ragged = planChunks(100_000, 65_536)
  check('non-divisible size ends with the remainder',
    ragged.length === 2 && ragged[0]?.length === 65_536 && ragged[1]?.offset === 65_536 && ragged[1]?.length === 34_464,
    JSON.stringify(ragged))

  const clampedLow = planChunks(10, 1)
  check('a tiny chunkSize is clamped up to 64 KiB', clampedLow.length === 1 && clampedLow[0]?.length === 10,
    JSON.stringify(clampedLow))
  const clampedHigh = planChunks(200_000, 1)
  check('clamping is applied to the step (64 KiB)',
    clampedHigh.length === 4 && clampedHigh[0]?.length === 65_536, JSON.stringify(clampedHigh))
  check('a huge chunkSize is clamped down to 8 MiB',
    planChunks(9 * 1024 * 1024, 16 * 1024 * 1024).length === 2)
  check('chunk indexes are contiguous from zero',
    ragged.every((chunk, i) => chunk.index === i))
}

// ---------------------------------------------------------------------------
// 2. compressChunk: only gzip when it clearly pays off
// ---------------------------------------------------------------------------

console.log('\n== 2. compressChunk ==')
{
  const repetitive = utf8('abcdefgh '.repeat(20_000))
  const packed = compressChunk(repetitive, true)
  check('compressible data comes back gzipped', packed.encoding === 'gzip')
  check('and is much smaller', packed.data.length < repetitive.length / 2,
    `${packed.data.length} vs ${repetitive.length}`)
  check('and round-trips', Buffer.compare(Buffer.from(gunzipSync(packed.data)), Buffer.from(repetitive)) === 0)

  const noise = new Uint8Array(randomBytes(100_000))
  const raw = compressChunk(noise, true)
  check('incompressible data stays raw', raw.encoding === 'raw')
  check('and is byte-identical', Buffer.compare(Buffer.from(raw.data), Buffer.from(noise)) === 0)

  check('compression:false always stays raw', compressChunk(repetitive, false).encoding === 'raw')
  check('an empty chunk stays raw', compressChunk(new Uint8Array(0), true).encoding === 'raw')
}

// ---------------------------------------------------------------------------
// 3. upload: pipeline, out-of-order chunks, retries, abort, sha256
// ---------------------------------------------------------------------------

console.log('\n== 3. uploadBuffer ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  const data = new Uint8Array(randomBytes(3 * 4096))
  // Delay index 0 hard so 2 and 1 finish first: the peer must tolerate disorder.
  peer.chunkDelayMs.set(0, 60)
  peer.chunkDelayMs.set(1, 30)
  const result = await uploadBuffer(peer.request, '/remote/three.bin', data, { concurrency: 3 })

  check('all three chunks were sent', peer.chunkOrder.length === 3, JSON.stringify(peer.chunkOrder))
  check('chunks completed out of order', peer.chunkOrder.join(',') === '2,1,0', peer.chunkOrder.join(','))
  check('at most `concurrency` chunks were in flight', peer.maxChunksInFlight <= 3, String(peer.maxChunksInFlight))
  check('the assembled remote file matches', Buffer.compare(Buffer.from(peer.files.get('/remote/three.bin') ?? new Uint8Array()), Buffer.from(data)) === 0)
  check('the reported sha256 matches the payload', result.sha256 === sha256(data), result.sha256)
  check('the reported size is the payload size', result.bytes === data.length && result.rateMbps >= 0)
  check('the peer committed exactly one upload', peer.uploads.size === 1)
  check('begin/commit metadata is passed through', result.created === true && result.version !== null, JSON.stringify(result))
  check('a rate and a duration are reported', result.durationMs >= 0 && result.rateMbps >= 0)
}

console.log('\n== 3b. createOnly / expectedVersion are forwarded to begin ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  let seen: Record<string, unknown> | undefined
  const inner = peer.request
  peer.request = async (op, args, timeoutMs) => {
    if (op === 'fs.put.begin') seen = { ...args }
    return await inner(op, args, timeoutMs)
  }
  const data = new Uint8Array(randomBytes(100))
  await uploadBuffer(peer.request, '/remote/new.txt', data, { createOnly: true, expectedVersion: 'v-7' })
  check('createOnly reaches fs.put.begin', seen?.createOnly === true, JSON.stringify(seen))
  check('expectedVersion reaches fs.put.begin', seen?.expectedVersion === 'v-7', JSON.stringify(seen))
  check('sha256 and size are sent up front',
    typeof seen?.sha256 === 'string' && String(seen.sha256).length === 64 && seen?.size === 100,
    JSON.stringify(seen))
}

console.log('\n== 3c. a transiently failing chunk is retried, then succeeds ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  peer.failChunks.set(1, 1)
  const data = new Uint8Array(randomBytes(2 * 4096))
  const result = await uploadBuffer(peer.request, '/remote/retry.bin', data)
  check('the failed chunk was attempted twice', peer.chunkAttempts.get(1) === 2, String(peer.chunkAttempts.get(1)))
  check('the upload still completed correctly', result.sha256 === sha256(data))
  check('the peer file matches', Buffer.compare(Buffer.from(peer.files.get('/remote/retry.bin') ?? new Uint8Array()), Buffer.from(data)) === 0)
}

console.log('\n== 3d. a permanently failing chunk aborts the upload and throws ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  peer.failAllChunks = true
  const data = new Uint8Array(randomBytes(2 * 4096))
  let thrown: unknown
  try {
    await uploadBuffer(peer.request, '/remote/never.bin', data)
  } catch (error) {
    thrown = error
  }
  check('the upload rejects', thrown instanceof Error, String(thrown))
  check('the failure is tagged as a chunk-phase failure',
    (thrown as { transferPhase?: string } | undefined)?.transferPhase === 'chunk',
    String((thrown as { transferPhase?: string } | undefined)?.transferPhase))
  check('the failing chunk was retried the full budget', peer.chunkAttempts.get(0) === 3, String(peer.chunkAttempts.get(0)))
  check('the temporary upload was aborted once', peer.abortedUploads.length === 1, JSON.stringify(peer.abortedUploads))
  check('nothing was committed to the target', !peer.files.has('/remote/never.bin'))
}

console.log('\n== 3e. empty payload: begin + commit only ==')
{
  const peer = new FakePeer()
  const result = await uploadBuffer(peer.request, '/remote/empty.txt', new Uint8Array(0))
  check('no chunk requests were sent', peer.chunkAttempts.size === 0)
  check('an empty file was committed', peer.files.get('/remote/empty.txt')?.length === 0)
  check('its sha256 is the empty digest',
    result.sha256 === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', result.sha256)
}

console.log('\n== 3f. an aborted signal rejects with AbortError and aborts the peer ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  peer.chunkDelayMs.set(0, 100)
  const data = new Uint8Array(randomBytes(2 * 4096))
  const controller = new AbortController()
  const pending = uploadBuffer(peer.request, '/remote/cancelled.bin', data, { signal: controller.signal })
  setTimeout(() => { controller.abort() }, 15)
  let thrown: unknown
  try {
    await pending
  } catch (error) {
    thrown = error
  }
  check('the failure is an AbortError', isAbortError(thrown), thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : String(thrown))
  check('the temporary upload was aborted', peer.abortedUploads.length === 1, JSON.stringify(peer.abortedUploads))
  check('nothing was committed', !peer.files.has('/remote/cancelled.bin'))
}

console.log('\n== 3g. a failed commit is tagged ambiguous (callers must not replay it) ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  const inner = peer.request
  peer.request = async (op, args, timeoutMs) => {
    if (op === 'fs.put.commit') throw new Error('injected commit failure')
    return await inner(op, args, timeoutMs)
  }
  const data = new Uint8Array(randomBytes(4096))
  let thrown: unknown
  try {
    await uploadBuffer(peer.request, '/remote/ambiguous.bin', data)
  } catch (error) {
    thrown = error
  }
  check('the upload rejects', thrown instanceof Error, String(thrown))
  check('the failure is tagged as commit-phase',
    (thrown as { transferPhase?: string } | undefined)?.transferPhase === 'commit',
    String((thrown as { transferPhase?: string } | undefined)?.transferPhase))
  check('the staging upload was aborted best-effort', peer.abortedUploads.length === 1,
    JSON.stringify(peer.abortedUploads))
}

// ---------------------------------------------------------------------------
// 4. download: parallel chunks, mixed gzip/raw, sha256 verification
// ---------------------------------------------------------------------------

const mixedPayload = (): Uint8Array => {
  const data = new Uint8Array(200_000)
  data.set(utf8('A'.repeat(100_000)), 0)
  data.set(new Uint8Array(randomBytes(100_000)), 100_000)
  return data
}

console.log('\n== 4. downloadToBuffer ==')
{
  const peer = new FakePeer()
  const data = mixedPayload()
  peer.files.set('/remote/mixed.bin', data)
  const chunks: number[] = []
  const inner = peer.request
  peer.request = async (op, args, timeoutMs) => {
    if (op === 'fs.get') chunks.push(Number(args.offset))
    return await inner(op, args, timeoutMs)
  }
  const result = await downloadToBuffer(peer.request, '/remote/mixed.bin', {
    chunkSize: 64 * 1024,
    concurrency: 3,
  })
  check('the file came back byte-identical',
    Buffer.compare(Buffer.from(result.data), Buffer.from(data)) === 0, `${result.data.length} vs ${data.length}`)
  check('the local sha256 matches', result.sha256 === sha256(data), result.sha256)
  check('more than one chunk was requested', chunks.length > 1, String(chunks.length))
  check('chunk offsets cover the file',
    JSON.stringify([...chunks].sort((a, b) => a - b)) === JSON.stringify([0, 65_536, 131_072, 196_608].slice(0, chunks.length)),
    JSON.stringify(chunks))
  check('the peer used both gzip and raw responses',
    peer.responseEncodings.includes('gzip') && peer.responseEncodings.includes('raw'),
    JSON.stringify(peer.responseEncodings))
  check('result size is the full size', result.size === data.length, String(result.size))
}

console.log('\n== 4b. a sha256 mismatch fails the download ==')
{
  const peer = new FakePeer()
  const data = utf8('hello chunked world'.repeat(5000))
  peer.files.set('/remote/liar.txt', data)
  peer.hashOverrides.set('/remote/liar.txt', '0'.repeat(64))
  let thrown: unknown
  try {
    await downloadToBuffer(peer.request, '/remote/liar.txt')
  } catch (error) {
    thrown = error
  }
  check('the mismatch throws',
    thrown instanceof Error && /checksum mismatch/u.test(thrown.message),
    thrown instanceof Error ? thrown.message : String(thrown))
}

console.log('\n== 4c. missing remote file reports FS_NOT_FOUND ==')
{
  const peer = new FakePeer()
  let thrown: unknown
  try {
    await downloadToBuffer(peer.request, '/remote/nope.bin')
  } catch (error) {
    thrown = error
  }
  check('the missing file throws',
    thrown instanceof Error && /not found/u.test(thrown.message),
    thrown instanceof Error ? thrown.message : String(thrown))
  check('carrying the peer code style', (thrown as { peerCode?: string } | undefined)?.peerCode === 'FS_NOT_FOUND',
    String((thrown as { peerCode?: string } | undefined)?.peerCode))
}

console.log('\n== 4d. a corrupt gzip chunk is rejected (and retried) ==')
{
  const peer = new FakePeer()
  peer.files.set('/remote/corrupt.bin', utf8('x'.repeat(100_000)))
  peer.corruptOffsets.add(0)
  let thrown: unknown
  try {
    await downloadToBuffer(peer.request, '/remote/corrupt.bin', { chunkSize: 64 * 1024 })
  } catch (error) {
    thrown = error
  }
  check('the corrupt chunk throws', thrown instanceof Error && /corrupt gzip|checksum/u.test(thrown.message),
    thrown instanceof Error ? thrown.message : String(thrown))
}

// ---------------------------------------------------------------------------
// 5. downloadToFile: temp file, atomic rename, overwrite guard, cancellation
// ---------------------------------------------------------------------------

const fileNames = async (dir: string): Promise<string[]> => (await readdir(dir)).sort()

console.log('\n== 5. downloadToFile ==')
{
  const peer = new FakePeer()
  const dir = await mkdtemp(join(tmpdir(), 'dshr-dl-'))
  try {
    const data = mixedPayload()
    peer.files.set('/remote/mixed.bin', data)
    const target = join(dir, 'nested', 'mixed.bin')
    const result = await downloadToFile(peer.request, '/remote/mixed.bin', target, { chunkSize: 64 * 1024 })
    check('the target was written', Buffer.compare(await readFile(target), Buffer.from(data)) === 0)
    check('the reported size and sha are right', result.bytes === data.length && result.sha256 === sha256(data),
      `${result.bytes}/${result.sha256}`)
    check('no temporary file was left behind',
      (await fileNames(join(dir, 'nested'))).every(name => !name.endsWith('.dshremote-tmp')),
      JSON.stringify(await fileNames(join(dir, 'nested'))))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

console.log('\n== 5b. bytes land in a temp file first, then rename ==')
{
  const peer = new FakePeer()
  const dir = await mkdtemp(join(tmpdir(), 'dshr-tmp-'))
  try {
    peer.files.set('/remote/stream.bin', utf8('z'.repeat(120_000)))
    peer.getDelayMs = 40
    const target = join(dir, 'stream.bin')
    const pending = downloadToFile(peer.request, '/remote/stream.bin', target, { chunkSize: 64 * 1024 })
    await sleep(15)
    const during = await fileNames(dir)
    check('a temporary file exists during the download',
      during.some(name => name.endsWith('.dshremote-tmp')), JSON.stringify(during))
    check('the target does not exist yet', !during.includes('stream.bin'), JSON.stringify(during))
    await pending
    const after = await fileNames(dir)
    check('the target exists afterwards', after.includes('stream.bin'), JSON.stringify(after))
    check('the temporary file is gone afterwards',
      after.every(name => !name.endsWith('.dshremote-tmp')), JSON.stringify(after))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

console.log('\n== 5c. overwrite:false refuses an existing target ==')
{
  const peer = new FakePeer()
  const dir = await mkdtemp(join(tmpdir(), 'dshr-noover-'))
  try {
    peer.files.set('/remote/x.bin', utf8('remote content'))
    const target = join(dir, 'x.bin')
    await writeFile(target, 'local content')
    let thrown: unknown
    try {
      await downloadToFile(peer.request, '/remote/x.bin', target, { overwrite: false })
    } catch (error) {
      thrown = error
    }
    check('the write is refused', thrown instanceof Error && /refusing to overwrite/u.test(thrown.message),
      thrown instanceof Error ? thrown.message : String(thrown))
    check('the existing file is untouched', await readFile(target, 'utf8') === 'local content')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

console.log('\n== 5d. a checksum failure removes the temporary file ==')
{
  const peer = new FakePeer()
  const dir = await mkdtemp(join(tmpdir(), 'dshr-badhash-'))
  try {
    peer.files.set('/remote/bad.bin', utf8('wrong hash'.repeat(1000)))
    peer.hashOverrides.set('/remote/bad.bin', 'f'.repeat(64))
    const target = join(dir, 'bad.bin')
    let thrown: unknown
    try {
      await downloadToFile(peer.request, '/remote/bad.bin', target)
    } catch (error) {
      thrown = error
    }
    check('the download fails', thrown instanceof Error && /checksum mismatch/u.test(thrown.message),
      thrown instanceof Error ? thrown.message : String(thrown))
    check('the target was never created', !(await fileNames(dir)).includes('bad.bin'),
      JSON.stringify(await fileNames(dir)))
    check('no temporary file was left behind',
      (await fileNames(dir)).every(name => !name.endsWith('.dshremote-tmp')),
      JSON.stringify(await fileNames(dir)))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

console.log('\n== 5e. cancellation leaves no partial file ==')
{
  const peer = new FakePeer()
  const dir = await mkdtemp(join(tmpdir(), 'dshr-abort-'))
  try {
    peer.files.set('/remote/slow.bin', utf8('s'.repeat(200_000)))
    peer.getDelayMs = 80
    const target = join(dir, 'slow.bin')
    const controller = new AbortController()
    const pending = downloadToFile(peer.request, '/remote/slow.bin', target, {
      chunkSize: 64 * 1024,
      signal: controller.signal,
    })
    setTimeout(() => { controller.abort() }, 20)
    let thrown: unknown
    try {
      await pending
    } catch (error) {
      thrown = error
    }
    check('the failure is an AbortError', isAbortError(thrown),
      thrown instanceof Error ? `${thrown.name}: ${thrown.message}` : String(thrown))
    const names = await fileNames(dir)
    check('no target and no temporary file remain',
      names.length === 0, JSON.stringify(names))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

// ---------------------------------------------------------------------------
// 6. uploadFile: streamed local reads, correct sha256, empty file
// ---------------------------------------------------------------------------

console.log('\n== 6. uploadFile ==')
{
  const peer = new FakePeer()
  peer.chunkSizeOverride = 4096
  const dir = await mkdtemp(join(tmpdir(), 'dshr-up-'))
  try {
    const data = new Uint8Array(randomBytes(3 * 4096 + 17))
    const local = join(dir, 'source.bin')
    await writeFile(local, data)
    const result = await uploadFile(peer.request, local, '/remote/uploaded.bin', { concurrency: 2 })
    const remote = peer.files.get('/remote/uploaded.bin') ?? new Uint8Array()
    check('the remote copy is byte-identical', Buffer.compare(Buffer.from(remote), Buffer.from(data)) === 0)
    check('sha256 matches what the peer committed', result.sha256 === sha256(data), result.sha256)
    check('the size is the local file size', result.bytes === (await stat(local)).size, String(result.bytes))
    check('the last chunk is a short one', peer.chunkAttempts.has(3), JSON.stringify([...peer.chunkAttempts.keys()]))

    const emptyLocal = join(dir, 'empty.txt')
    await writeFile(emptyLocal, '')
    const emptyResult = await uploadFile(peer.request, emptyLocal, '/remote/empty-upload.txt')
    check('an empty local file commits an empty remote file',
      emptyResult.bytes === 0 && (peer.files.get('/remote/empty-upload.txt')?.length ?? -1) === 0,
      `${emptyResult.bytes}/${peer.files.get('/remote/empty-upload.txt')?.length}`)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

console.log('\n== 6b. a missing local file fails before touching the peer ==')
{
  const peer = new FakePeer()
  let thrown: unknown
  try {
    await uploadFile(peer.request, join(tmpdir(), 'dshr-does-not-exist-xyz.bin'), '/remote/x.bin')
  } catch (error) {
    thrown = error
  }
  check('the call rejects', thrown instanceof Error, String(thrown))
  check('and no begin was attempted', peer.uploads.size === 0)
}

// ---------------------------------------------------------------------------
// 7. createOpProbe: capability cache, TTL, failures not cached
// ---------------------------------------------------------------------------

console.log('\n== 7. createOpProbe ==')
{
  const peer = new FakePeer()
  const probe = createOpProbe(peer.request)
  check('a complete op set is supported', (await probe()) === true)
  check('the first probe asked sysinfo once', peer.sysinfoCalls === 1, String(peer.sysinfoCalls))
  check('a cached probe asks nothing more', (await probe()) === true && peer.sysinfoCalls === 1, String(peer.sysinfoCalls))

  peer.ops = ['fs.stat', 'fs.read']
  check('a cached answer outlives an ops change', (await probe()) === true && peer.sysinfoCalls === 1)

  const short = createOpProbe(peer.request, 20)
  check('a fresh probe sees the incomplete op set', (await short()) === false)
  const callsAfterFirst = peer.sysinfoCalls
  await sleep(35)
  check('the TTL expiry re-probes', (await short()) === false && peer.sysinfoCalls === callsAfterFirst + 1,
    `${peer.sysinfoCalls} vs ${callsAfterFirst}`)
}

console.log('\n== 7b. a failed probe is not cached ==')
{
  const peer = new FakePeer()
  peer.sysinfoFailures = 1
  const probe = createOpProbe(peer.request, 60_000)
  check('the failure answers false', (await probe()) === false)
  check('the next call retries sysinfo', peer.sysinfoCalls === 1, String(peer.sysinfoCalls))
  check('and succeeds once the peer answers', (await probe()) === true && peer.sysinfoCalls === 2, String(peer.sysinfoCalls))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
