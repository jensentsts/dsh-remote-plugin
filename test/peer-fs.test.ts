/**
 * Loopback verification for the peer-federated filesystem provider.
 *
 * The point of this test is that it needs **no real peer machine**: it stands up
 * a minimal server that speaks the same wire protocol and answers the `fs.*`
 * ops from a temp directory. So every claim about peer addressing can be
 * checked here, and only the cross-machine network path is left to an
 * integration run.
 *
 * It asserts the two halves that matter:
 *   1. peer paths read through the mount point, and
 *   2. with no peers declared — and for every local path — the provider behaves
 *      exactly like the backend it extends (the zero-regression requirement).
 *
 * Run from the harness checkout so `tsx` resolves the workspace imports:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/peer-fs.test.ts
 */

import { createServer } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gzipSync, gunzipSync } from 'node:zlib'

import { Context, Service } from '@deepseek-ai/cordis'
import { FsError } from '@deepseek-ai/dsh-fs'

import { generateKeyPair, privateToPem, publicToPem, serverHandshake } from '../src/protocol.ts'
import { FederatedFileSystem } from '../src/peer-fs.ts'
import { PeerRegistry } from '../src/peers.ts'

let failures = 0
let checks = 0

function check(label: string, condition: boolean, detail = ''): void {
  checks += 1
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}${detail === '' ? '' : ` — ${detail}`}`)
  }
}

function section(title: string): void {
  console.log(`\n== ${title} ==`)
}

/** Minimal `ctx.sandboxPolicy` stand-in: the fence is not what this test probes. */
class StubSandboxPolicy extends Service {
  readonly defaultMode = 'danger-full-access' as const
  constructor(ctx: Context) {
    super(ctx, 'sandboxPolicy')
  }

  resolve(): { mode: 'danger-full-access' } {
    return { mode: 'danger-full-access' }
  }
}

/**
 * State of the tiny fake peer: which ops it advertises, and the in-memory
 * staging table the chunked-upload ops use. Shared by every connection, because
 * one provider context opens one link but the test opens several contexts.
 */
interface FakePeerState {
  fast: boolean
  uploads: Map<string, {
    path: string
    size: number
    sha256: string
    chunkSize: number
    buffer: Buffer
    createOnly: boolean
    expectedVersion?: string
  }>
  seq: number
}

/**
 * A tiny wire-protocol server answering the file ops from a real directory.
 *
 * Deliberately not the full server plugin: this test is about the provider, and
 * a small peer keeps the failure surface small too. With `fast` it advertises
 * and implements the chunked `fs.put.*`/`fs.get` ops, which is what lets the
 * provider's fast path be exercised without a real machine.
 */
function startFakePeer(
  agentPrivate: ReturnType<typeof generateKeyPair>['privateKey'],
  clientPublic: ReturnType<typeof generateKeyPair>['publicKey'],
  options: { fast?: boolean } = {},
): Promise<{ port: number, close: () => void, ops: string[] }> {
  const ops: string[] = []
  const state: FakePeerState = { fast: options.fast === true, uploads: new Map(), seq: 0 }
  const server = createServer((socket: Socket) => {
    void (async () => {
      try {
        const session = await serverHandshake(socket, agentPrivate, clientPublic)
        for (;;) {
          const request = await session.recv(30_000)
          if (request === null) break
          const op = String(request.op)
          ops.push(op)
          const result = answer(op, String(request.path ?? ''), request, state)
          await session.send(
            result.__fail === true
              ? { id: request.id, ok: false, error: String(result.error), code: String(result.code) }
              : { id: request.id, ok: true, ...result },
          )
        }
      } catch {
        // The client closing between requests is the normal end of this loop.
      } finally {
        socket.destroy()
      }
    })()
  })
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo
      resolve({ port, close: () => server.close(), ops })
    })
  })
}

/** Answer one `fs.*` op from the real filesystem, in the server plugin's shape. */
function answer(op: string, path: string, request: Record<string, unknown>, state: FakePeerState): Record<string, unknown> {
  const nativePath = path.replace(/\//g, '\\')
  const fail = (error: string, code: string): Record<string, unknown> => ({ __fail: true, error, code })
  const versionOf = (target: string): string | undefined => {
    const info = statSyncSafe(target)
    return info === undefined ? undefined : `${Math.floor(info.mtimeMs)}:${info.size}`
  }
  if (op === 'sysinfo') {
    const base = ['ping', 'sysinfo', 'fs.read', 'fs.write', 'fs.edit', 'fs.list', 'fs.stat', 'fs.hash']
    const fast = ['fs.get', 'fs.put.begin', 'fs.put.chunk', 'fs.put.commit', 'fs.put.abort']
    return { pong: true, version: 'fake', pid: 1, build: state.fast ? 'r19' : 'r18', sessions: [], ops: state.fast ? [...base, ...fast] : base }
  }
  if (op === 'fs.hash') {
    const info = statSyncSafe(nativePath)
    if (info === undefined) return fail(`cannot hash "${nativePath}": not found`, 'FS_NOT_FOUND')
    return {
      algo: 'sha256',
      hash: createHash('sha256').update(readFileSync(nativePath)).digest('hex'),
      size: info.size,
    }
  }
  if (op === 'fs.get') {
    const info = statSyncSafe(nativePath)
    if (info === undefined) return fail(`cannot read "${nativePath}": not found`, 'FS_NOT_FOUND')
    if (info.isDirectory()) return fail(`cannot read "${nativePath}": not a regular file`, 'FS_NOT_REGULAR_FILE')
    const offset = Number(request.offset ?? 0)
    const length = Number(request.length ?? 1024 * 1024)
    const buf = readFileSync(nativePath)
    const window = buf.subarray(offset, offset + length)
    const wantsGzip = request.encoding === 'gzip'
    const gz = wantsGzip ? gzipSync(window, { level: 6 }) : undefined
    const useGzip = gz !== undefined && gz.length < window.length * 0.95
    return {
      offset,
      bytes: window.length,
      size: buf.length,
      eof: offset + window.length >= buf.length,
      encoding: useGzip ? 'gzip' : 'raw',
      dataB64: (useGzip ? gz! : window).toString('base64'),
    }
  }
  if (op === 'fs.put.begin') {
    const size = Number(request.size)
    const chunkSize = Math.max(64 * 1024, Math.min(Number(request.chunkSize ?? 1024 * 1024), 8 * 1024 * 1024))
    const uploadId = `u${++state.seq}`
    state.uploads.set(uploadId, {
      path: nativePath,
      size,
      sha256: String(request.sha256 ?? ''),
      chunkSize,
      buffer: Buffer.alloc(size),
      createOnly: request.createOnly === true,
      ...(typeof request.expectedVersion === 'string' ? { expectedVersion: request.expectedVersion } : {}),
    })
    return { uploadId, chunkSize, size }
  }
  if (op === 'fs.put.chunk') {
    const uploadId = String(request.uploadId ?? '')
    const upload = state.uploads.get(uploadId)
    if (upload === undefined) return fail(`fs.put.chunk: unknown uploadId ${uploadId}`, 'FS_IO_ERROR')
    const index = Number(request.index)
    const offset = index * upload.chunkSize
    const expected = Math.min(upload.chunkSize, upload.size - offset)
    const raw = Buffer.from(String(request.dataB64 ?? ''), 'base64')
    let data: Buffer
    try {
      data = request.encoding === 'gzip' ? gunzipSync(raw) : raw
    } catch {
      return fail('fs.put.chunk: bad gzip payload', 'FS_IO_ERROR')
    }
    if (data.length !== expected) return fail(`fs.put.chunk: length ${data.length} != ${expected}`, 'FS_IO_ERROR')
    data.copy(upload.buffer, offset)
    return { uploadId, index, received: data.length }
  }
  if (op === 'fs.put.commit') {
    const uploadId = String(request.uploadId ?? '')
    const upload = state.uploads.get(uploadId)
    if (upload === undefined) return fail(`fs.put.commit: unknown uploadId ${uploadId}`, 'FS_IO_ERROR')
    state.uploads.delete(uploadId)
    const exists = statSyncSafe(upload.path) !== undefined
    if (upload.createOnly && exists) return fail('cannot overwrite existing without reading it first', 'FS_NOT_OBSERVED')
    if (upload.expectedVersion !== undefined) {
      if (!exists) return fail('file no longer exists', 'FS_STALE_VERSION')
      if (versionOf(upload.path) !== upload.expectedVersion) return fail('file changed since it was read', 'FS_STALE_VERSION')
    }
    const sha256 = createHash('sha256').update(upload.buffer).digest('hex')
    if (upload.buffer.length !== upload.size || sha256 !== upload.sha256) {
      return fail('fs.put.commit: size/sha256 mismatch', 'FS_IO_ERROR')
    }
    const before = exists ? readFileSync(upload.path, 'utf8') : null
    writeFileSync(upload.path, upload.buffer)
    return { uploadId, size: upload.size, sha256, created: !exists, version: versionOf(upload.path), path: nativePath, before, beforeBytes: exists ? Buffer.byteLength(before ?? '', 'utf8') : 0 }
  }
  if (op === 'fs.put.abort') {
    const uploadId = String(request.uploadId ?? '')
    return { uploadId, aborted: state.uploads.delete(uploadId) }
  }
  if (op === 'fs.stat') {
    try {
      const stat = statSyncSafe(nativePath)
      if (stat === undefined) return { exists: false }
      return {
        exists: true,
        isDir: stat.isDirectory(),
        size: stat.size,
        mtimeMs: Math.floor(stat.mtimeMs),
        version: `${Math.floor(stat.mtimeMs)}:${stat.size}`,
      }
    } catch {
      return { exists: false }
    }
  }
  if (op === 'fs.list') {
    const entries = readdirSync(nativePath, { withFileTypes: true }).map(entry => {
      const stat = statSyncSafe(join(nativePath, entry.name))
      return { name: entry.name, isDir: entry.isDirectory(), size: stat?.size ?? null, mtimeMs: Math.floor(stat?.mtimeMs ?? 0) }
    })
    return { path: nativePath, count: entries.length, entries }
  }
  if (op === 'fs.read') {
    const offset = Number(request.offset ?? 0)
    const length = Number(request.length ?? 256 * 1024)
    const buf = readFileSync(nativePath)
    const window = buf.subarray(offset, offset + length)
    return {
      path: nativePath,
      offset,
      size: buf.length,
      bytes: window.length,
      eof: offset + window.length >= buf.length,
      dataB64: window.toString('base64'),
      text: window.toString('utf8'),
    }
  }

  if (op === 'fs.write') {
    const exists = statSyncSafe(nativePath) !== undefined
    if (request.createOnly === true && exists) {
      return fail('cannot overwrite existing without reading it first', 'FS_NOT_OBSERVED')
    }
    if (typeof request.expectedVersion === 'string') {
      if (!exists) return fail('file no longer exists', 'FS_STALE_VERSION')
      if (versionOf(nativePath) !== request.expectedVersion) {
        return fail('file changed since it was read', 'FS_STALE_VERSION')
      }
    }
    const before = exists ? readFileSync(nativePath, 'utf8') : null
    writeFileSync(nativePath, Buffer.from(String(request.dataB64 ?? ''), 'base64'))
    return { size: statSyncSafe(nativePath)?.size ?? 0, version: versionOf(nativePath), created: !exists, before }
  }
  if (op === 'fs.edit') {
    if (statSyncSafe(nativePath) === undefined) return fail('file changed since it was read', 'FS_STALE_VERSION')
    if (typeof request.expectedVersion === 'string' && versionOf(nativePath) !== request.expectedVersion) {
      return fail('file changed since it was read', 'FS_STALE_VERSION')
    }
    const text = readFileSync(nativePath, 'utf8')
    const oldString = String(request.oldString ?? '')
    const count = oldString === '' ? 0 : text.split(oldString).length - 1
    if (count === 0) return fail('the text to replace was not found', 'FS_EDIT_NOT_FOUND')
    if (count > 1 && request.replaceAll !== true) {
      return fail(`the text to replace appears ${count} times`, 'FS_AMBIGUOUS_EDIT')
    }
    const after = request.replaceAll === true
      ? text.split(oldString).join(String(request.newString ?? ''))
      : text.replace(oldString, String(request.newString ?? ''))
    writeFileSync(nativePath, after, 'utf8')
    return { version: versionOf(nativePath), before: text, after }
  }

  return fail(`unsupported op ${op}`, 'FS_IO_ERROR')
}

function statSyncSafe(path: string): { isDirectory: () => boolean, size: number, mtimeMs: number } | undefined {
  try {
    return statSync(path)
  } catch {
    return undefined
  }
}

async function main(): Promise<void> {
  const workspace = mkdtempSync(join(tmpdir(), 'peer-fs-'))
  mkdirSync(join(workspace, 'sub'))
  writeFileSync(join(workspace, 'hello.txt'), 'hello from the peer\nsecond line\n', 'utf8')
  writeFileSync(join(workspace, 'sub', 'nested.txt'), 'nested\n', 'utf8')
  const remoteRoot = workspace.replace(/\\/g, '/')

  const clientKeys = generateKeyPair()
  const agentKeys = generateKeyPair()
  const peer = await startFakePeer(agentKeys.privateKey, clientKeys.publicKey)

  const peerProfile = {
    host: '127.0.0.1',
    port: peer.port,
    maxPermission: 1,
    privateKey: privateToPem(clientKeys.privateKey),
    peerPublicKey: publicToPem(agentKeys.publicKey),
    timeoutMs: 20_000,
    allowLegacyHandshake: true, // Deliberately old fixture, explicit compatibility only.
  }

  // ---------------------------------------------------------------- with a peer
  section('with a peer declared')
  const ctx = new Context()
  await ctx.plugin(StubSandboxPolicy)
  await ctx.plugin(FederatedFileSystem, { cwd: process.cwd(), peers: { 'peer-one': peerProfile } } as never)
  const fs = ctx.fs as FederatedFileSystem

  const peerFile = `/peers/peer-one/${remoteRoot}/hello.txt`
  const parsed = await fs.resolve(peerFile)
  check('resolve maps the path onto a peer key',
    String(parsed.targetKey) === `peer:peer-one:${remoteRoot}/hello.txt`,
    String(parsed.targetKey))

  const info = await fs.stat(parsed)
  check('stat reports a regular file', info?.type === 'file', JSON.stringify(info))
  check('stat reports the peer size', info?.size === 32, String(info?.size))

  const text = await fs.readText(parsed)
  check('readText returns the peer content', text.startsWith('hello from the peer'), JSON.stringify(text))

  const window = await fs.readByteRange(parsed, { offset: 0, length: 5 })
  check('readByteRange returns the exact window', Buffer.from(window).toString('utf8') === 'hello')

  const dirTarget = await fs.resolve(`/peers/peer-one/${remoteRoot}`)
  const entries = await fs.listDir(dirTarget)
  const names = entries.map(e => e.name).sort()
  check('listDir returns both children', JSON.stringify(names) === '["hello.txt","sub"]', JSON.stringify(names))
  const sub = entries.find(e => e.name === 'sub')
  check('listDir child targets carry peer keys',
    String(sub?.target.targetKey).startsWith('peer:peer-one:'), String(sub?.target.targetKey))
  check('listDir types the directory', sub?.type === 'directory', String(sub?.type))

  const nested = await fs.readText(await fs.resolve(`/peers/peer-one/${remoteRoot}/sub/nested.txt`))
  check('a nested path reads too', nested === 'nested\n', JSON.stringify(nested))

  // -------------------------------------------------- rmt: alias (default peer)
  const aliasPath = `rmt:/${remoteRoot}/hello.txt`
  const alias = await fs.resolve(aliasPath)
  check('rmt: alias resolves to the default peer',
    String(alias.targetKey) === `peer:peer-one:${remoteRoot}/hello.txt`, String(alias.targetKey))
  check('rmt: display path is canonicalized to forward slashes',
    alias.displayPath === aliasPath, alias.displayPath)
  check('rmt: alias reads the peer file',
    (await fs.readText(alias)).startsWith('hello from the peer'))
  const backslashAlias = await fs.resolve(`rmt:\\${remoteRoot.replace(/\//gu, '\\')}\\hello.txt`)
  check('rmt: backslash spelling resolves to the same target',
    String(backslashAlias.targetKey) === String(alias.targetKey), String(backslashAlias.targetKey))

  const aliasDir = await fs.resolve(`rmt:/${remoteRoot}`)
  const aliasEntries = await fs.listDir(aliasDir)
  check('rmt: a directory lists its children', aliasEntries.length === 2, JSON.stringify(aliasEntries.map(e => e.name)))
  check('rmt: child targets keep the alias display path',
    aliasEntries.every(entry => entry.target.displayPath.startsWith('rmt:/')),
    JSON.stringify(aliasEntries.map(entry => entry.target.displayPath)))

  let emptyAlias = ''
  try {
    await fs.resolve('rmt:')
  } catch (error) {
    emptyAlias = error instanceof FsError ? error.code : String(error)
  }
  check('rmt: without a path is refused with a helpful code', emptyAlias === 'FS_NOT_FOUND', emptyAlias)

  // ------------------------------------------- /rmt mount spelling (Markdown)
  // This is what the chat's /api/file image route can serve: OS-absolute path,
  // read through the same federated backend.
  const mountPath = `/rmt/${remoteRoot}/hello.txt`
  const mounted = await fs.resolve(mountPath)
  check('mount spelling resolves to the default peer',
    String(mounted.targetKey) === `peer:peer-one:${remoteRoot}/hello.txt`, String(mounted.targetKey))
  check('mount display path stays mount-spelled', mounted.displayPath === mountPath, mounted.displayPath)
  check('mount spelling reads the peer file',
    (await fs.readText(mounted)).startsWith('hello from the peer'))
  const mountDir = await fs.resolve(`/rmt/${remoteRoot}`)
  const mountEntries = await fs.listDir(mountDir)
  check('mount directory lists its children', mountEntries.length === 2, JSON.stringify(mountEntries.map(e => e.name)))
  check('mount child targets keep the /rmt/ display path',
    mountEntries.every(entry => entry.target.displayPath.startsWith('/rmt/')),
    JSON.stringify(mountEntries.map(entry => entry.target.displayPath)))
  const mountInfo = await fs.stat(mounted)
  check('mount stat reports the file', mountInfo?.type === 'file' && mountInfo.size === 32,
    JSON.stringify(mountInfo))
  const mountLstat = await fs.lstat(mountPath)
  check('mount lstat works too', mountLstat?.type === 'file', JSON.stringify(mountLstat))
  const mountBytes = await fs.readBytes(mounted, undefined, 1024)
  check('mount bytes read through readBytes (the /api/file route)',
    mountBytes.byteLength === 32 && Buffer.from(mountBytes).toString('utf8').startsWith('hello'), String(mountBytes.byteLength))

  // ------------------------------------------- peer:/ spelling + default peer
  // The scp-style token must be a declared peer name of at least two chars, so
  // this uses a second context whose single peer is named `pp` (the real
  // deployment's names — home-pc, laptop — are longer than a drive letter).
  const scpCtx = new Context()
  await scpCtx.plugin(StubSandboxPolicy)
  await scpCtx.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { pp: peerProfile },
  } as never)
  const scpFs = scpCtx.fs as FederatedFileSystem
  const scpTarget = await scpFs.resolve(`pp:/${remoteRoot}/hello.txt`)
  check('peer:/ spelling resolves to that peer',
    String(scpTarget.targetKey) === `peer:pp:${remoteRoot}/hello.txt`, String(scpTarget.targetKey))
  check('peer:/ display path is canonical',
    scpTarget.displayPath === `pp:/${remoteRoot}/hello.txt`, scpTarget.displayPath)
  check('peer:/ spelling reads the peer file',
    (await scpFs.readText(scpTarget)).startsWith('hello from the peer'))
  check('peer names are exposed for completion',
    scpFs.remotePeerNames().includes('pp') && scpFs.remoteDefaultPeerName() === 'pp',
    `${JSON.stringify(scpFs.remotePeerNames())} / ${scpFs.remoteDefaultPeerName()}`)

  const twoCtx = new Context()
  await twoCtx.plugin(StubSandboxPolicy)
  await twoCtx.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { aa: peerProfile, bb: peerProfile },
    defaultPeer: 'bb',
  } as never)
  const twoFs = twoCtx.fs as FederatedFileSystem
  const defaultTarget = await twoFs.resolve(`rmt:/${remoteRoot}/hello.txt`)
  check('defaultPeer decides what rmt: addresses',
    String(defaultTarget.targetKey).startsWith('peer:bb:'), String(defaultTarget.targetKey))
  check('defaultPeer is also first in the completion order',
    twoFs.remotePeerNames()[0] === 'bb', JSON.stringify(twoFs.remotePeerNames()))

  const missing = await fs.stat(await fs.resolve(`/peers/peer-one/${remoteRoot}/nope.txt`))
  check('an absent peer file stats to undefined', missing === undefined)

  let unknownPeer = ''
  try {
    await fs.resolve('/peers/not-declared/E:/x.txt')
  } catch (error) {
    unknownPeer = error instanceof FsError ? error.code : String(error)
  }
  check('an undeclared peer is refused', unknownPeer === 'FS_NOT_FOUND', unknownPeer)

  let writeRefusal = ''
  let writeRefusalMessage = ''
  try {
    await fs.writeText(parsed, 'nope')
  } catch (error) {
    writeRefusal = error instanceof FsError ? error.code : String(error)
    writeRefusalMessage = error instanceof Error ? error.message : String(error)
  }
  check('peer writes are refused, not silently attempted',
    writeRefusal === 'FS_PERMISSION_DENIED', writeRefusal)

  // -------------------------------------------------- ceiling wiring (S2)
  section('what refuses the write, and why')
  check('a read-only peer is stopped by the ceiling, and the message says so',
    writeRefusalMessage.includes('ceiling') && writeRefusalMessage.includes('level 2'),
    writeRefusalMessage)

  const full = new Context()
  await full.plugin(StubSandboxPolicy)
  await full.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { 'peer-one': { ...peerProfile, maxPermission: 3 } },
  } as never)
  const fullFs = full.fs as FederatedFileSystem
  // A dedicated probe file: writing through a peer must not disturb the fixture
  // the read-side checks later in this file depend on.
  const probeFile = `/peers/peer-one/${remoteRoot}/write-probe.txt`
  let level3Message = ''
  try {
    await fullFs.writeText(await fullFs.resolve(probeFile), 'nope')
  } catch (error) {
    level3Message = error instanceof Error ? error.message : String(error)
  }
  check('a level-3 peer clears the ceiling and the write lands',
    readFileSync(join(workspace, 'write-probe.txt'), 'utf8') === 'nope', level3Message)

  const aliasProbe = `rmt:/${remoteRoot}/alias-probe.txt`
  let aliasWriteError = ''
  try {
    await fullFs.writeText(await fullFs.resolve(aliasProbe), 'via-alias')
  } catch (error) {
    aliasWriteError = error instanceof Error ? error.message : String(error)
  }
  check('rmt: alias writes land on the peer file too',
    readFileSync(join(workspace, 'alias-probe.txt'), 'utf8') === 'via-alias', aliasWriteError)

  const confined = new Context()
  await confined.plugin(StubSandboxPolicy)
  await confined.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { 'peer-one': { ...peerProfile, maxPermission: 2, workspaceRoot: 'E:/somewhere-else' } },
  } as never)
  const confinedFs = confined.fs as FederatedFileSystem
  let outsideMessage = ''
  try {
    await confinedFs.writeText(await confinedFs.resolve(peerFile), 'nope')
  } catch (error) {
    outsideMessage = error instanceof Error ? error.message : String(error)
  }
  check('a level-2 peer writing outside its declared root is refused for containment',
    outsideMessage.includes('outside the declared workspace'), outsideMessage)

  check('peer processPath is not a local path',
    fs.processPath(parsed).startsWith('peer://'), fs.processPath(parsed))
  check('contains() stays inside one peer',
    fs.contains(dirTarget, parsed) && !fs.contains(dirTarget, await fs.resolve('/peers/peer-one/E:/other.txt')))

  // ------------------------------------------------------ local paths untouched
  section('local paths (zero regression)')
  const localTarget = await fs.resolve(join(workspace, 'hello.txt'))
  check('a local path still resolves locally', !String(localTarget.targetKey).startsWith('peer:'),
    String(localTarget.targetKey))
  check('a local read still works',
    (await fs.readText(localTarget)).startsWith('hello from the peer'))
  const localDir = await fs.resolve(workspace)
  const localNames = (await fs.listDir(localDir)).map(e => e.name)
  check('a local listing still works',
    localNames.includes('hello.txt') && localNames.includes('sub'), localNames.join(','))
  check('local containment still holds', fs.contains(localDir, localTarget))

  // ------------------------------------------------------------- with no peers
  section('with no peers declared')
  const bare = new Context()
  await bare.plugin(StubSandboxPolicy)
  await bare.plugin(FederatedFileSystem, { cwd: process.cwd() } as never)
  const bareFs = bare.fs as FederatedFileSystem
  check('local reads still work', (await bareFs.readText(await bareFs.resolve(join(workspace, 'hello.txt')))).length > 0)
  let unmounted = ''
  try {
    await bareFs.resolve('/peers/peer-one/E:/x.txt')
  } catch (error) {
    unmounted = error instanceof FsError ? error.code : String(error)
  }
  check('the mount point is inert when nothing is declared', unmounted === 'FS_NOT_FOUND', unmounted)

  // ------------------------------------------- shared declarations (S2 finish)
  section('the shared registry is the single source of truth')
  const shared = new Context()
  await shared.plugin(StubSandboxPolicy)
  await shared.plugin(PeerRegistry, { peers: { 'peer-one': { ...peerProfile, maxPermission: 3 } } } as never)
  // Deliberately no `peers` of its own: the mount must come from the registry.
  await shared.plugin(FederatedFileSystem, { cwd: process.cwd() } as never)
  const sharedFs = shared.fs as FederatedFileSystem
  const sharedText = await sharedFs.readText(await sharedFs.resolve(peerFile))
  check('a peer declared only in the registry is mounted and readable',
    sharedText.startsWith('hello from the peer'), JSON.stringify(sharedText.slice(0, 20)))
  let sharedWrite = ''
  try {
    await sharedFs.writeText(await sharedFs.resolve(probeFile), 'nope')
  } catch (error) {
    sharedWrite = error instanceof Error ? error.message : String(error)
  }
  check('the registry\'s ceiling is the one enforced (level 3 lets the write through)',
    readFileSync(join(workspace, 'write-probe.txt'), 'utf8') === 'nope', sharedWrite || '(no throw)')

  const conflicting = new Context()
  await conflicting.plugin(StubSandboxPolicy)
  await conflicting.plugin(PeerRegistry, { peers: { 'peer-one': { ...peerProfile, maxPermission: 3 } } } as never)
  await conflicting.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { 'peer-one': { ...peerProfile, maxPermission: 1 } },
  } as never)
  const conflictingFs = conflicting.fs as FederatedFileSystem
  let conflictMessage = ''
  try {
    await conflictingFs.writeText(await conflictingFs.resolve(probeFile), 'nope')
  } catch (error) {
    conflictMessage = error instanceof Error ? error.message : String(error)
  }
  check('when both declare, the registry wins (level 3 writes; the config said level 1)',
    conflictMessage === '', conflictMessage)

  // --------------------------------------------------- the version guard (S3)
  section('a stale write is refused, not silently applied')
  writeFileSync(join(workspace, 'hello.txt'), 'hello from the peer\nsecond line\n', 'utf8')
  const guardCtx = new Context()
  await guardCtx.plugin(StubSandboxPolicy)
  await guardCtx.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    peers: { 'peer-one': { ...peerProfile, maxPermission: 3 } },
  } as never)
  const guardFs = guardCtx.fs as FederatedFileSystem
  const guardTarget = await guardFs.resolve(peerFile)
  const observed = await guardFs.stat(guardTarget)
  check('the peer supplies the version token', typeof observed?.version === 'string' && String(observed.version).includes(':'),
    String(observed?.version))

  // Someone else changes the file after we observed it.
  writeFileSync(join(workspace, 'hello.txt'), 'changed underneath, a different length\n', 'utf8')
  let staleCode = ''
  try {
    await guardFs.writeText(guardTarget, 'should not land', { kind: 'replaceIfVersion', version: observed!.version })
  } catch (error) {
    staleCode = error instanceof FsError ? error.code : String(error)
  }
  check('a guarded write against a changed file is FS_STALE_VERSION', staleCode === 'FS_STALE_VERSION', staleCode)
  check('and the file was left untouched',
    readFileSync(join(workspace, 'hello.txt'), 'utf8') === 'changed underneath, a different length\n')

  const fresh = await guardFs.stat(guardTarget)
  const written = await guardFs.writeText(guardTarget, 'guarded write landed\n', { kind: 'replaceIfVersion', version: fresh!.version })
  check('a guarded write against the current version lands', written.operation === 'update'
    && readFileSync(join(workspace, 'hello.txt'), 'utf8') === 'guarded write landed\n')

  const edited = await guardFs.editText(guardTarget, { oldString: 'guarded write', newString: 'edited text', replaceAll: false })
  check('a peer edit applies the literal replacement',
    edited.after === 'edited text landed\n' && readFileSync(join(workspace, 'hello.txt'), 'utf8') === 'edited text landed\n',
    JSON.stringify(edited.after))

  let ambiguous = ''
  try {
    await guardFs.editText(guardTarget, { oldString: 'e', newString: 'X', replaceAll: false })
  } catch (error) {
    ambiguous = error instanceof FsError ? error.code : String(error)
  }
  check('an ambiguous edit is refused', ambiguous === 'FS_AMBIGUOUS_EDIT', ambiguous)

  let missingEdit = ''
  try {
    await guardFs.editText(guardTarget, { oldString: 'no such text', newString: 'x', replaceAll: false })
  } catch (error) {
    missingEdit = error instanceof FsError ? error.code : String(error)
  }
  check('a non-matching edit is refused', missingEdit === 'FS_EDIT_NOT_FOUND', missingEdit)

  // ------------------------------------- chunked fast path (r19 peers, S3+)
  section('a peer that advertises the chunked transfer ops uses the fast path')
  const fastPeer = await startFakePeer(agentKeys.privateKey, clientKeys.publicKey, { fast: true })
  const fastProfile = { ...peerProfile, port: fastPeer.port, maxPermission: 3 }
  const fastCtx = new Context()
  await fastCtx.plugin(StubSandboxPolicy)
  await fastCtx.plugin(FederatedFileSystem, {
    cwd: process.cwd(),
    // Explicit (smaller) threshold keeps the test independent of the default.
    transferFastPathBytes: 64 * 1024,
    peers: { 'peer-one': fastProfile },
  } as never)
  const fastFs = fastCtx.fs as FederatedFileSystem

  // A file past the provider's fast-path threshold (64 KiB) and compressible,
  // so the read path exercises parallel `fs.get` chunks and the write path
  // exercises `fs.put.begin/chunk/commit`.
  const bigText = Array.from({ length: 8192 }, (_, i) => `line ${String(i).padStart(5, '0')} payload`).join('\n') + '\n'
  writeFileSync(join(workspace, 'big.txt'), bigText, 'utf8')
  const bigRemote = `/peers/peer-one/${remoteRoot}/big.txt`
  const bigTarget = await fastFs.resolve(bigRemote)
  const bigRead = await fastFs.readText(bigTarget)
  check('readText returns the whole large file through fs.get', bigRead === bigText, `${bigRead.length} vs ${bigText.length}`)
  const bigBytes = await fastFs.readBytes(bigTarget, undefined, 10 * 1024 * 1024)
  check('readBytes returns the same bytes', Buffer.from(bigBytes).toString('utf8') === bigText)
  let streamed = ''
  for await (const piece of await fastFs.streamText(bigTarget)) streamed += piece
  check('streamText reconstructs the text across chunk boundaries', streamed === bigText, `${streamed.length} vs ${bigText.length}`)
  check('the read actually used fs.get', fastPeer.ops.includes('fs.get'),
    [...new Set(fastPeer.ops)].join(','))

  const putPath = `/peers/peer-one/${remoteRoot}/put-big.txt`
  const putTarget = await fastFs.resolve(putPath)
  const putOutcome = await fastFs.writeText(putTarget, bigText)
  check('writeText creates the large file through the chunked path',
    putOutcome.operation === 'create' && readFileSync(join(workspace, 'put-big.txt'), 'utf8') === bigText,
    `${putOutcome.operation} / ${readFileSync(join(workspace, 'put-big.txt'), 'utf8').length} bytes`)
  check('the write actually used fs.put.begin/chunk/commit',
    fastPeer.ops.includes('fs.put.begin') && fastPeer.ops.includes('fs.put.chunk') && fastPeer.ops.includes('fs.put.commit'),
    [...new Set(fastPeer.ops)].join(','))
  const updateOutcome = await fastFs.writeText(putTarget, `${bigText}tail\n`)
  check('a second write reports update and the new content',
    updateOutcome.operation === 'update' && readFileSync(join(workspace, 'put-big.txt'), 'utf8').endsWith('tail\n'),
    updateOutcome.operation)

  const observedBig = await fastFs.stat(putTarget)
  writeFileSync(join(workspace, 'put-big.txt'), 'changed by someone else\n', 'utf8')
  let fastStale = ''
  try {
    await fastFs.writeText(putTarget, 'should not land', { kind: 'replaceIfVersion', version: observedBig!.version })
  } catch (error) {
    fastStale = error instanceof FsError ? error.code : String(error)
  }
  check('the fast path keeps the version guard', fastStale === 'FS_STALE_VERSION', fastStale)
  check('and the changed file was left alone',
    readFileSync(join(workspace, 'put-big.txt'), 'utf8') === 'changed by someone else\n')
  fastPeer.close()

  section('a peer that does not advertise them keeps the legacy single-frame path')
  // All earlier sections ran against the non-fast fake peer; assert what it saw.
  check('the legacy peer was written through fs.write', peer.ops.includes('fs.write'))
  check('and the chunked ops were never attempted against it',
    !peer.ops.includes('fs.put.begin') && !peer.ops.includes('fs.put.chunk'))

  peer.close()
  console.log(`\n${checks - failures}/${checks} checks passed`)
  console.log('peer ops exercised:', [...new Set(peer.ops)].join(', '))
  if (failures > 0) process.exitCode = 1
  await new Promise<void>((resolve) => { setTimeout(resolve, 50) })
}

await main()
