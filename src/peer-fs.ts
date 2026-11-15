/**
 * Peer-federated filesystem provider.
 *
 * Mounts other machines' files at `<peerRoot>/<peer>/<absolute-path>` — with the
 * default root that reads `/peers/home-pc/E:/project/src/index.ts`. Every
 * model-facing file tool (`read`, `write`, `edit`, …) already goes through
 * `ctx.fs`, so this provider adds peer addressing **without adding a single
 * tool**: the tools keep their schemas and the model keeps its habits.
 *
 * ## Why it extends the sandboxed backend
 *
 * The base bundle installs `fs-sandbox` (`SandboxedFileSystem`), which extends
 * `LocalFileSystem` and overrides only `writeText`/`editText` to add the
 * per-call policy fence — reads pass through untouched. Extending *that* means a
 * local path keeps the deployment's exact containment behaviour, because every
 * non-peer path is delegated with `super`. The fence is deliberately NOT applied
 * to peer targets: a peer URI is not a local path, and the peer's own
 * `maxPermission` ceiling is what confines those writes.
 *
 * ## Scope of this stage (S1, plus the S3 transfer fast path)
 *
 * Read paths are implemented: `resolve`, `stat`, `lstat`, `listDir`, `readText`,
 * `streamText`, `readBytes`, `readByteRange`, plus the identity helpers.
 * **Peer writes are refused with a typed error rather than silently attempted**
 * — version-guarded writes and edits arrive with the `fs.write`/`fs.edit` ops.
 *
 * Large transfers use the chunked, per-block-compressed `fs.put.*` / `fs.get`
 * ops whenever the peer advertises them (see `transfer-client.ts`), and fall
 * back to the single-frame `fs.write`/`fs.read` ops for an older peer. That
 * fallback is the reason this provider must never assume the fast path exists:
 * the capability probe decides per peer, and every call site keeps the legacy
 * shape as its else branch.
 *
 * `glob`/`grep` are spawn-backed in this deployment (they shell out to `rg`
 * locally) and never call this provider, so peer paths do not search. That is a
 * known gap with a known fix (a remote rg channel); until then a peer search
 * fails loudly instead of returning an empty result.
 *
 * @module dsh-remote/peer-fs
 */

import type { Context } from '@deepseek-ai/cordis'
import { FsError, FsTargetKey, FsVersion } from '@deepseek-ai/dsh-fs'
import type {
  FsDirEntry,
  FsEditOutcome,
  FsEditRequest,
  FsInfo,
  FsPathInfo,
  FsTarget,
  FsWriteIntent,
  FsWriteOutcome,
} from '@deepseek-ai/dsh-fs'
import { SandboxedFileSystem } from '@deepseek-ai/dsh-fs-sandbox'
import type { Config as LocalConfig } from '@deepseek-ai/dsh-fs-local'
import type { SandboxExecutionPolicy } from '@deepseek-ai/dsh-sandbox'
import z from '@deepseek-ai/schemastery'
import { StringDecoder } from 'node:string_decoder'
import { gunzipSync } from 'node:zlib'

import { dshHomePath } from './keys.ts'
import { LinkClient } from './link.ts'
import { meshSocketFactory } from './mesh-transport.ts'
import { assertPeerOperation, normalizePermission } from './peers.ts'
import type { PeerRegistry } from './peers.ts'
import { createOpProbe, downloadToBuffer, uploadBuffer } from './transfer-client.ts'
import type { TransferOptions, TransferRequest } from './transfer-client.ts'
import { mountPathFor, parseMountPath, parseRemotePath, parseScpPath } from './remote-path.ts'
import { parseHostReference } from './reference-query.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-peer-fs'

/** The ceiling a peer starts at until a deployment raises it deliberately. */
export const DEFAULT_MAX_PERMISSION = 1

/** Prefix that marks a peer target key: `peer:<name>:<remotePath>`. */
const PEER_KEY_PREFIX = 'peer:'

/** Read window used when the caller does not bound a read. */
const DEFAULT_READ_WINDOW = 256 * 1024

/** Window used by the lazy `streamText` reader on an old (non-fast-path) peer. */
const STREAM_READ_WINDOW = 256 * 1024

/** Chunk size for the `streamText` adapter when the whole text is already local. */
const STREAM_CHUNK = 64 * 1024

/** Content at or above this size takes the chunked fast path (when advertised). */
const DEFAULT_TRANSFER_FAST_PATH_BYTES = 512 * 1024

/**
 * One reachable peer. Connection fields mirror the client plugin's settings so a
 * deployment writes them the same way in both places.
 */
export interface PeerProfile {
  /** Peer host — whatever address reaches that machine. No default. */
  host?: string
  /** Peer port. No default. */
  port?: number
  /** Optional mesh target; its inner public-key pin still identifies the device. */
  relayTarget?: string
  /**
   * Ceiling on what this peer may be asked to do, `1 < 2 < 3`:
   * 1 read-only, 2 workspace-write, 3 danger-full-access.
   * Defaults to 1 so a newly declared peer can only be read.
   */
  maxPermission?: number
  /** Boundary a level-2 peer may write inside (empty = the peer decides). */
  workspaceRoot?: string
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
  /** Explicit compatibility with a pre-selector server; false by default. */
  allowLegacyHandshake?: boolean
  /** Maximum authenticated session lifetime; at most one hour. */
  maxSessionMs?: number
}

const PeerProfileSchema = z.object({
  host: z.string().default(''),
  port: z.number().default(0),
  relayTarget: z.string().default(''),
  maxPermission: z.number().default(DEFAULT_MAX_PERMISSION),
  workspaceRoot: z.string().default(''),
  privateKey: z.string().role('secret').default(''),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.key')),
  autoGenerateKey: z.boolean().default(true),
  peerPublicKey: z.string().default(''),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.pub')),
  timeoutMs: z.number().default(120_000),
  allowLegacyHandshake: z.boolean().default(false),
  maxSessionMs: z.number().default(3_600_000),
})

/** Plugin config: the local backend's knobs plus the peer mounts. */
export interface Config extends LocalConfig {
  /** Mount point for peer paths. Defaults to `/peers`. */
  peerRoot?: string
  /**
   * Peer that a bare `rmt:/…` path addresses (default: the first declared one).
   *
   * A deployment with several peers declares this so `rmt:` has one obvious
   * meaning; the `/peers/<name>/…` form stays available for the others.
   */
  defaultPeer?: string
  /** Declared peers, keyed by the name used in a path. */
  peers?: Record<string, PeerProfile>
  /** Content at or above this many UTF-8 bytes takes the chunked fast path. */
  transferFastPathBytes?: number
  /** Chunk size for chunked transfers (the peer clamps it further). */
  transferChunkBytes?: number
  /** How many transfer chunks may be in flight at once. */
  transferConcurrency?: number
  /** gzip each transfer chunk when it shrinks the wire payload. */
  transferCompression?: boolean
}

export const Config = z.object({
  cwd: z.string().default(process.cwd()),
  diffBasisMaxBytes: z.number().default(10 * 1024 * 1024),
  peerRoot: z.string().default('/peers'),
  defaultPeer: z.string().default(''),
  peers: z.dict(PeerProfileSchema).default({}),
  transferFastPathBytes: z.number().default(DEFAULT_TRANSFER_FAST_PATH_BYTES),
  transferChunkBytes: z.number().default(1024 * 1024),
  transferConcurrency: z.number().default(4),
  transferCompression: z.boolean().default(true),
})

/** A path recognised as peer-addressed. */
export interface ParsedPeerPath {
  /** Declared peer name. */
  peer: string
  /** The peer's own absolute path, verbatim. */
  remote: string
}

/**
 * Recognise `<peerRoot>/<peer>/<absolute-path>`.
 *
 * The peer name is restricted to `[A-Za-z0-9._-]` so the remainder is
 * unambiguously the peer's own path — a Windows `E:/…` keeps its colon.
 *
 * @param path - the model-supplied path.
 * @param peerRoot - the configured mount point, without a trailing slash.
 * @returns the parsed parts, or undefined when this is not a peer path.
 */
export function parsePeerPath(path: string, peerRoot: string): ParsedPeerPath | undefined {
  if (!path.startsWith(`${peerRoot}/`)) return undefined
  const rest = path.slice(peerRoot.length + 1)
  const slash = rest.indexOf('/')
  if (slash <= 0) return undefined
  const peer = rest.slice(0, slash)
  if (!/^[A-Za-z0-9._-]+$/.test(peer)) return undefined
  const remote = rest.slice(slash + 1)
  if (remote === '') return undefined
  return { peer, remote }
}

/** Build the opaque target key for a peer target. */
export function peerTargetKey(peer: string, remote: string): string {
  return `${PEER_KEY_PREFIX}${peer}:${remote}`
}

/**
 * Split a peer target key back into its parts.
 * @param key - a key previously produced by {@link peerTargetKey}.
 * @returns the parts, or undefined when the key is not a peer key.
 */
export function splitPeerTargetKey(key: string): ParsedPeerPath | undefined {
  if (!key.startsWith(PEER_KEY_PREFIX)) return undefined
  const rest = key.slice(PEER_KEY_PREFIX.length)
  const colon = rest.indexOf(':')
  if (colon <= 0) return undefined
  return { peer: rest.slice(0, colon), remote: rest.slice(colon + 1) }
}

/** Synthesize a freshness token from the peer's cheap metadata. */
function peerVersion(peer: string, remote: string, mtime: unknown, size: unknown): FsVersion {
  return FsVersion(`pv1:${peer}:${String(mtime ?? 0)}:${String(size ?? 0)}:${remote}`)
}

/**
 * Wrap the version token the peer reported.
 *
 * The peer must be the authority here: a write guard round-trips this exact
 * string back to it, so anything this side invents could never match.
 * @param reply - the peer's reply.
 * @param parsed - the peer and path, used only for the diagnostic fallback.
 * @returns the version token.
 */
function peerVersionOf(reply: Record<string, unknown>, parsed: ParsedPeerPath): FsVersion {
  const raw = reply.version
  if (typeof raw === 'string' && raw !== '') return FsVersion(raw)
  return peerVersion(parsed.peer, parsed.remote, peerMtime(reply), reply.size)
}

/** Map the peer's `dir` boolean onto the FS type union. */
function peerType(reply: Record<string, unknown>): 'file' | 'directory' | 'other' {
  // The peer plugin reports `isDir`; a test peer may report `dir`. Accept both.
  return (reply.isDir ?? reply.dir) === true ? 'directory' : 'file'
}

/** The peer's mtime in milliseconds, whichever name it used. */
function peerMtime(reply: Record<string, unknown>): unknown {
  return reply.mtimeMs ?? reply.mtime
}

/**
 * The federated provider. Local paths behave exactly as the deployment's
 * sandboxed backend; peer paths are routed over the authenticated link.
 */
export class FederatedFileSystem extends SandboxedFileSystem {
  static override inject = ['sandboxPolicy']

  /** Mount point without a trailing slash. */
  private readonly peerRoot: string
  /**
   * Fallback declarations from this plugin's own config. Normally empty: the
   * deployment declares peers once, in the client plugin, which publishes them
   * through {@link PeerRegistry}. Kept so this provider also works standalone
   * (tests, or a deployment that mounts peers without the client plugin).
   */
  private readonly profiles: Record<string, PeerProfile>
  /** One reusable link per peer, created on first use. */
  private readonly links = new Map<string, LinkClient>()
  /** Cached "does this peer advertise the chunked transfer ops?" probes. */
  private readonly fastProbes = new Map<string, () => Promise<boolean>>()
  /** Fast-path knobs from config; read per transfer, not captured at boot. */
  private readonly transferConfig: Config
  /** Configured default peer for `rmt:` paths; empty means "the first declared". */
  private readonly configuredDefaultPeer: string
  /**
   * Marker the file-reference provider checks before offering `rmt:` completion:
   * only this backend can resolve such paths, and a bare local backend must not
   * advertise candidates it cannot read.
   */
  readonly supportsRemotePaths = true

  constructor(ctx: Context, config: Config) {
    super(ctx, config)
    this.transferConfig = config
    this.configuredDefaultPeer = String(config.defaultPeer ?? '')
    const raw = String(config.peerRoot ?? '/peers')
    this.peerRoot = raw.replace(/\/+$/, '') === '' ? '/peers' : raw.replace(/\/+$/, '')
    this.profiles = config.peers ?? {}
    const own = Object.keys(this.profiles)
    const shared = this.registry()?.list() ?? []
    const declared = shared.length > 0 ? shared : own
    ctx.on('loader/volatile-update', () => {
      for (const link of this.links.values()) link.dispose()
      this.links.clear()
      this.fastProbes.clear()
    })
    ctx.effect(() => () => {
      for (const link of this.links.values()) link.dispose()
      this.links.clear()
    }, 'dsh-remote-peer-fs: close links')
    this.ctx.logger.info(
      declared.length === 0
        ? `${name}: no peers declared — ${this.peerRoot}/* is not mounted`
        : `${name}: mounting ${declared.length} peer(s) at ${this.peerRoot}: ${declared.join(', ')}`
          + (shared.length > 0 ? ' (from the shared registry)' : ' (from this plugin\'s own config)'),
    )
  }

  /**
   * The peer a bare `rmt:/…` path addresses.
   *
   * An explicit `defaultPeer` wins; otherwise the first declared peer is the
   * default, which is exactly the single-peer deployment's only peer.
   * @returns the peer name.
   * @throws FsError when no peer is declared at all.
   */
  private defaultPeerName(): string {
    const shared = this.registry()?.defaultPeerName?.()
    if (typeof shared === 'string' && shared !== '') return shared
    const wanted = this.configuredDefaultPeer.trim()
    if (wanted !== '') return wanted
    const declared = [...new Set([...(this.registry()?.list() ?? []), ...Object.keys(this.profiles)])]
    if (declared.length === 0) {
      throw new FsError(
        'no remote peer is declared: add `peers` (or `host`/`port`) to the dsh-remote-client settings before using rmt: paths',
        'FS_NOT_FOUND',
      )
    }
    return declared[0]!
  }

  /** The shared declarations, when the client plugin published them. */
  private registry(): PeerRegistry | undefined {
    return this.ctx.get('dshRemotePeers') as PeerRegistry | undefined
  }

  /**
   * The declaration for a peer. The shared registry wins; this plugin's own
   * config is the fallback, so a deployment never writes an address twice.
   * @param peerName - the name from the path.
   * @returns the profile.
   * @throws FsError when the peer is declared in neither place.
   */
  private profileOf(peerName: string): PeerProfile {
    const shared = this.registry()
    if (shared !== undefined && shared.has(peerName)) return shared.profile(peerName)
    const own = this.profiles[peerName]
    if (own !== undefined) return own
    const declared = [...new Set([...(shared?.list() ?? []), ...Object.keys(this.profiles)])]
    throw new FsError(
      `unknown peer "${peerName}": declare it under peers in the dsh-remote-client settings`
      + (declared.length === 0 ? ' (none are declared)' : ` (declared: ${declared.join(', ')})`),
      'FS_NOT_FOUND',
    )
  }

  /**
   * The reusable link for a peer, created on first use.
   * @param peerName - the name from the path.
   * @returns the link.
   * @throws FsError when the peer is not declared.
   */
  private linkFor(peerName: string): LinkClient {
    const existing = this.links.get(peerName)
    if (existing !== undefined) return existing
    this.profileOf(peerName) // throws for an unknown peer before a link is cached
    const link = new LinkClient(
      // Resolved per dial, so a declaration changed in settings is picked up.
      () => this.profileOf(peerName),
      message => this.ctx.logger.info(message),
      `dsh-remote peer ${peerName}`,
      meshSocketFactory(this.ctx),
    )
    this.links.set(peerName, link)
    return link
  }

  /** The declared ceiling for a peer, normalized by the shared rule. */
  private ceilingOf(peerName: string): number {
    return normalizePermission(this.profileOf(peerName).maxPermission ?? DEFAULT_MAX_PERMISSION)
  }

  /**
   * Check one operation against a peer's ceiling.
   *
   * The same function the controlled side runs on arrival, so the two ends
   * cannot disagree — and this side refuses before spending a round trip.
   * @param parsed - the peer and the path it targets.
   * @param op - the wire operation name.
   * @throws FsError when the operation exceeds the ceiling.
   */
  private assertPeer(parsed: ParsedPeerPath, op: string): void {
    assertPeerOperation(this.ceilingOf(parsed.peer), op, {
      peer: parsed.peer,
      path: parsed.remote,
      workspaceRoot: String(this.profileOf(parsed.peer).workspaceRoot ?? ''),
    })
  }

  /** `link.request` in the shape the transfer module expects. */
  private transferRequestOf(peerName: string): TransferRequest {
    return (op, args, timeoutMs) => this.linkFor(peerName).request(op, args, timeoutMs)
  }

  /** Fast-path knobs; the transfer module clamps them to its own safe ranges. */
  private transferOptionsOf(signal?: AbortSignal): TransferOptions {
    return {
      chunkSize: this.transferConfig.transferChunkBytes,
      concurrency: this.transferConfig.transferConcurrency,
      compression: this.transferConfig.transferCompression !== false,
      ...(signal === undefined ? {} : { signal }),
    }
  }

  /**
   * Does this peer advertise the chunked transfer ops?
   *
   * Probed once per peer and cached inside the probe itself, so a read or write
   * does not pay a `sysinfo` round trip every time. A failed probe is NOT
   * cached: a tunnel that blinks must not downgrade the provider for minutes.
   */
  private fastTransferSupported(peerName: string): Promise<boolean> {
    let probe = this.fastProbes.get(peerName)
    if (probe === undefined) {
      probe = createOpProbe(this.transferRequestOf(peerName))
      this.fastProbes.set(peerName, probe)
    }
    return probe()
  }

  /**
   * Is this failure "the peer turned out not to know the fast ops"?
   *
   * Only then may a call fall back to the legacy single-frame op. A real error
   * (permission, stale version, checksum, an ambiguous commit) must surface: a
   * silent rewrite could clobber a target the peer already replaced.
   */
  private isUnknownTransferOp(error: unknown): boolean {
    const code = (error as { peerCode?: unknown } | null)?.peerCode
    if (code === 'FS_UNSUPPORTED' || code === 'FS_UNKNOWN_OP') return true
    const message = error instanceof Error ? error.message : String(error)
    return /unknown op|unsupported op|not supported|no such op/iu.test(message)
  }

  /**
   * Read a whole peer file through the legacy windowed `fs.read` op.
   *
   * The old single request capped itself at one window, which silently truncated
   * a larger text file. Looping until the peer reports a short window (or the
   * requested cap) is the honest behaviour for the fallback path.
   */
  private async readPeerAllBytes(
    parsed: ParsedPeerPath,
    signal: AbortSignal | undefined,
    maxBytes: number = Number.MAX_SAFE_INTEGER,
  ): Promise<Uint8Array> {
    const chunks: Buffer[] = []
    let offset = 0
    for (;;) {
      if (signal?.aborted === true) throw new FsError('read aborted', 'FS_ABORTED')
      const window = await this.readPeerBytes(parsed, { offset, length: DEFAULT_READ_WINDOW }, signal)
      if (window.length === 0) break
      chunks.push(Buffer.from(window))
      offset += window.length
      if (offset >= maxBytes) break
      if (window.length < DEFAULT_READ_WINDOW) break
    }
    return new Uint8Array(Buffer.concat(chunks).subarray(0, Math.min(offset, maxBytes)))
  }

  /** Every declared peer name, shared registry first, in declaration order. */
  private declaredPeerNames(): string[] {
    return [...new Set([...(this.registry()?.list() ?? []), ...Object.keys(this.profiles)])]
  }

  /** Whether a token is a declared peer name (case-sensitive, like the paths). */
  private isDeclaredPeer(name: string): boolean {
    return this.registry()?.has(name) === true || this.profiles[name] !== undefined
  }

  /**
   * The declared peers, for a completion provider that wants to offer
   * `peer:/…` spellings without duplicating the registry. The default peer
   * (`rmt:`) comes first so prefix hints prefer it.
   * @returns peer names, default first.
   */
  remotePeerNames(): string[] {
    const declared = this.declaredPeerNames()
    try {
      const fallback = this.defaultPeerName()
      if (fallback !== '') return [fallback, ...declared.filter(name => name !== fallback)]
    } catch {
      // No default resolvable; fall through to declaration order.
    }
    return declared
  }

  /**
   * The peer a bare `rmt:` path addresses, for a completion provider that wants
   * to label the default namespace.
   * @returns the peer name, or empty when none is declared.
   */
  remoteDefaultPeerName(): string {
    try {
      return this.defaultPeerName()
    } catch {
      return ''
    }
  }

  /**
   * Resolve one mount-spelling path (`/rmt/E:/x`, `/rmt/<peer>/E:/x`).
   *
   * This is the spelling the chat's Markdown image route can serve: it is
   * OS-absolute, so `/api/file?path=` accepts it, and it routes through this same
   * federated backend.
   * @param path - the mount-spelling path.
   * @returns the peer, its normalized path, and the canonical display path.
   * @throws FsError when the spelling names no remote path.
   */
  private mountAliasTarget(path: string): { peer: string; remote: string; displayPath: string } {
    const parsed = parseMountPath(path, name => this.isDeclaredPeer(name))
    if (parsed === undefined) throw new FsError(`"${path}" is not a mount path`, 'FS_NOT_FOUND')
    if (parsed.remote === '') {
      throw new FsError(`"${path}" names no remote path: use e.g. /rmt/E:/dir/file`, 'FS_NOT_FOUND')
    }
    const peer = parsed.peer ?? this.defaultPeerName()
    this.profileOf(peer) // validates the declaration before any round trip
    return {
      peer,
      remote: parsed.remote,
      displayPath: mountPathFor(peer, parsed.remote, peer === this.defaultPeerName()),
    }
  }

  /**
   * Resolve one scp/rsync-style path (`peer:/E:/x`) to its peer target.
   * @param path - the model-supplied path.
   * @returns the peer, its normalized path, and the canonical display path.
   * @throws FsError when the spelling names no path.
   */
  private scpAliasTarget(path: string): { peer: string; remote: string; displayPath: string } {
    const parsed = parseScpPath(path, name => this.isDeclaredPeer(name))
    if (parsed === undefined) throw new FsError(`"${path}" is not a peer path`, 'FS_NOT_FOUND')
    if (parsed.remote === '') {
      throw new FsError(`"${path}" names no remote path: use e.g. ${parsed.peer}:/E:/dir/file`, 'FS_NOT_FOUND')
    }
    this.profileOf(parsed.peer) // validates the declaration before any round trip
    return { peer: parsed.peer, remote: parsed.remote, displayPath: `${parsed.peer}:/${parsed.remote}` }
  }

  /**
   * Resolve one `rmt:` path to its peer target.
   *
   * The display path keeps the alias spelling canonicalized to forward slashes
   * (`rmt:/E:/dir`), so tool results show exactly what the user can type again.
   * @param path - the model-supplied `rmt:` path.
   * @returns the peer, its verbatim path, and the canonical display path.
   * @throws FsError when the spelling names no path or no peer is declared.
   */
  private remoteAliasTarget(path: string): { peer: string; remote: string; displayPath: string } {
    const parsed = parseRemotePath(path)
    if (parsed === undefined) {
      throw new FsError(`"${path}" is not a remote path`, 'FS_NOT_FOUND')
    }
    const remote = parsed.remote.trim()
    if (remote === '') {
      throw new FsError(
        `"${path}" names no remote path: use e.g. rmt:/E:/dir/file`,
        'FS_NOT_FOUND',
      )
    }
    // One identity per remote file: `rmt:\E:\x` and `rmt:/E:/x` must target the
    // same peer key, and Windows peers accept forward slashes for every op.
    const normalized = remote.replace(/\\/gu, '/')
    const peer = this.defaultPeerName()
    this.profileOf(peer) // validates the declaration before any round trip
    return { peer, remote: normalized, displayPath: `rmt:/${normalized}` }
  }

  override async resolve(
    path: string,
    opts?: { cwd?: string; signal?: AbortSignal },
  ): Promise<FsTarget> {
    const expression = parseHostReference(path, this.declaredPeerNames())
    if (expression !== undefined && expression.kind !== 'path') {
      if (expression.kind === 'plugin') throw new FsError('A plugin reference is not a file path; use remote_capabilities or remote_tool_call', 'FS_NOT_FOUND')
      if (expression.query === '') throw new FsError('A workspace name is required after the host colon', 'FS_NOT_FOUND')
      opts?.signal?.throwIfAborted()
      this.assertPeer({ peer: expression.peer, remote: '' }, 'references.list')
      const reply = await this.linkFor(expression.peer).request('references.list', {
        kind: 'workspace', query: expression.query, relative: expression.relative, resolve: true, limit: 200,
      }, 15_000)
      opts?.signal?.throwIfAborted()
      if (reply.status === 'ambiguous') throw new FsError('Multiple workspaces share this name; select the workspace by its full ID', 'FS_NOT_FOUND')
      if (reply.status !== 'resolved' || typeof reply.path !== 'string') throw new FsError('Workspace reference could not be resolved on its host', 'FS_NOT_FOUND')
      return { targetKey: FsTargetKey(peerTargetKey(expression.peer, reply.path)), displayPath: mountPathFor(expression.peer, reply.path, false) }
    }
    const parsed = parsePeerPath(path, this.peerRoot)
    if (parsed === undefined && parseMountPath(path, name => this.isDeclaredPeer(name)) !== undefined) {
      if (opts?.signal?.aborted === true) throw new FsError('resolve aborted', 'FS_ABORTED')
      const alias = this.mountAliasTarget(path)
      return {
        targetKey: FsTargetKey(peerTargetKey(alias.peer, alias.remote)),
        displayPath: alias.displayPath,
      }
    }
    if (parsed === undefined && parseRemotePath(path) !== undefined) {
      if (opts?.signal?.aborted === true) throw new FsError('resolve aborted', 'FS_ABORTED')
      const alias = this.remoteAliasTarget(path)
      return {
        targetKey: FsTargetKey(peerTargetKey(alias.peer, alias.remote)),
        displayPath: alias.displayPath,
      }
    }
    if (parsed === undefined && parseScpPath(path, name => this.isDeclaredPeer(name)) !== undefined) {
      if (opts?.signal?.aborted === true) throw new FsError('resolve aborted', 'FS_ABORTED')
      const alias = this.scpAliasTarget(path)
      return {
        targetKey: FsTargetKey(peerTargetKey(alias.peer, alias.remote)),
        displayPath: alias.displayPath,
      }
    }
    if (parsed === undefined) return await super.resolve(path, opts)
    if (opts?.signal?.aborted === true) throw new FsError('resolve aborted', 'FS_ABORTED')
    this.profileOf(parsed.peer) // validates the name; no link is created here
    return {
      targetKey: FsTargetKey(peerTargetKey(parsed.peer, parsed.remote)),
      displayPath: path,
    }
  }

  override processPath(target: FsTarget): string {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return super.processPath(target)
    // Deliberately NOT a local path: handing a subprocess something that could
    // name a real local file would be worse than handing it an unusable URI.
    return `peer://${parsed.peer}/${parsed.remote}`
  }

  override fileUrl(target: FsTarget): string {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return super.fileUrl(target)
    return `peer://${parsed.peer}/${parsed.remote}`
  }

  override contains(parent: FsTarget, child: FsTarget): boolean {
    const a = splitPeerTargetKey(String(parent.targetKey))
    const b = splitPeerTargetKey(String(child.targetKey))
    if (a === undefined || b === undefined) {
      if (a === undefined && b === undefined) return super.contains(parent, child)
      return false // never claim containment across the peer boundary
    }
    if (a.peer !== b.peer) return false
    if (a.remote === b.remote) return true
    const prefix = a.remote.endsWith('/') ? a.remote : `${a.remote}/`
    return b.remote.startsWith(prefix)
  }

  override async stat(target: FsTarget, signal?: AbortSignal): Promise<FsInfo | undefined> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.stat(target, signal)
    if (signal?.aborted === true) throw new FsError('stat aborted', 'FS_ABORTED')
    const reply = await this.linkFor(parsed.peer).request('fs.stat', { path: parsed.remote })
    if (reply.exists !== true) return undefined
    const size = typeof reply.size === 'number' ? reply.size : undefined
    return {
      version: peerVersionOf(reply, parsed),
      type: peerType(reply),
      ...(size === undefined ? {} : { size }),
    }
  }

  override async lstat(
    path: string,
    opts?: { cwd?: string },
    signal?: AbortSignal,
  ): Promise<FsPathInfo | undefined> {
    const parsed = parsePeerPath(path, this.peerRoot)
    if (parsed === undefined && parseMountPath(path, name => this.isDeclaredPeer(name)) !== undefined) {
      const alias = this.mountAliasTarget(path)
      const info = await this.stat(
        { targetKey: FsTargetKey(peerTargetKey(alias.peer, alias.remote)), displayPath: alias.displayPath },
        signal,
      )
      if (info === undefined) return undefined
      return {
        version: info.version,
        type: info.type,
        ...(info.size === undefined ? {} : { size: info.size }),
      }
    }
    if (parsed === undefined && parseRemotePath(path) !== undefined) {
      const alias = this.remoteAliasTarget(path)
      const info = await this.stat(
        { targetKey: FsTargetKey(peerTargetKey(alias.peer, alias.remote)), displayPath: alias.displayPath },
        signal,
      )
      if (info === undefined) return undefined
      return {
        version: info.version,
        type: info.type,
        ...(info.size === undefined ? {} : { size: info.size }),
      }
    }
    if (parsed === undefined && parseScpPath(path, name => this.isDeclaredPeer(name)) !== undefined) {
      const alias = this.scpAliasTarget(path)
      const info = await this.stat(
        { targetKey: FsTargetKey(peerTargetKey(alias.peer, alias.remote)), displayPath: alias.displayPath },
        signal,
      )
      if (info === undefined) return undefined
      return {
        version: info.version,
        type: info.type,
        ...(info.size === undefined ? {} : { size: info.size }),
      }
    }
    if (parsed === undefined) return await super.lstat(path, opts, signal)
    // The peer reports one metadata shape; without a follow/no-follow split the
    // honest answer is the stat result, never a fabricated `symlink`.
    const info = await this.stat(
      { targetKey: FsTargetKey(peerTargetKey(parsed.peer, parsed.remote)), displayPath: path },
      signal,
    )
    if (info === undefined) return undefined
    return {
      version: info.version,
      type: info.type,
      ...(info.size === undefined ? {} : { size: info.size }),
    }
  }

  override async listDir(target: FsTarget, signal?: AbortSignal): Promise<FsDirEntry[]> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.listDir(target, signal)
    if (signal?.aborted === true) throw new FsError('listDir aborted', 'FS_ABORTED')
    const reply = await this.linkFor(parsed.peer).request('fs.list', { path: parsed.remote })
    const entries = Array.isArray(reply.entries) ? reply.entries as Array<Record<string, unknown>> : []
    return entries.map((entry) => {
      const childName = String(entry.name ?? '')
      const childRemote = parsed.remote.endsWith('/')
        ? `${parsed.remote}${childName}`
        : `${parsed.remote}/${childName}`
      const size = typeof entry.size === 'number' ? entry.size : undefined
      return {
        name: childName,
        type: peerType(entry),
        target: {
          targetKey: FsTargetKey(peerTargetKey(parsed.peer, childRemote)),
          displayPath: `${target.displayPath.replace(/\/+$/, '')}/${childName}`,
        },
        version: peerVersion(parsed.peer, childRemote, peerMtime(entry), entry.size),
        ...(size === undefined ? {} : { size }),
      }
    })
  }

  override async readText(target: FsTarget, signal?: AbortSignal): Promise<string> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.readText(target, signal)
    // One stat up front tells us whether the fast path can pay off. On a
    // ~78 ms-RTT tunnel the chunked path costs two extra round trips, so a
    // file that fits in one legacy window is strictly cheaper read the old way.
    const info = await this.stat(target, signal)
    if (info === undefined) throw new FsError(`cannot read "${target.displayPath}": not found`, 'FS_NOT_FOUND')
    if (info.type !== 'file') {
      throw new FsError(`cannot read "${target.displayPath}": not a regular file`, 'FS_NOT_REGULAR_FILE')
    }
    this.assertPeer(parsed, 'fs.get')
    const fastPathBytes = this.transferConfig.transferFastPathBytes ?? DEFAULT_TRANSFER_FAST_PATH_BYTES
    const large = info.size !== undefined && info.size > Math.max(fastPathBytes, DEFAULT_READ_WINDOW)
    if (large && await this.fastTransferSupported(parsed.peer)) {
      const result = await downloadToBuffer(
        this.transferRequestOf(parsed.peer),
        parsed.remote,
        this.transferOptionsOf(signal),
      )
      return decodePeerText(result.data, target.displayPath)
    }
    const bytes = await this.readPeerAllBytes(parsed, signal)
    return decodePeerText(bytes, target.displayPath)
  }

  override async streamText(
    target: FsTarget,
    signal?: AbortSignal,
  ): Promise<AsyncIterable<string>> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.streamText(target, signal)
    if (!(await this.fastTransferSupported(parsed.peer))) {
      // No fast path: the legacy op has no streaming primitive, so read and
      // slice. Same shape this adapter always had, never worse.
      const text = await this.readText(target, signal)
      return (async function* chunks() {
        for (let at = 0; at < text.length; at += STREAM_CHUNK) {
          if (signal?.aborted === true) throw new FsError('stream aborted', 'FS_ABORTED')
          yield text.slice(at, at + STREAM_CHUNK)
        }
      })()
    }
    this.assertPeer(parsed, 'fs.get')
    const request = this.transferRequestOf(parsed.peer)
    const options = this.transferOptionsOf(signal)
    const remote = parsed.remote
    // Decode across chunk boundaries: a multi-byte UTF-8 character can be split
    // between two `fs.get` replies, and slicing the buffer would corrupt it.
    return (async function* chunks() {
      const decoder = new StringDecoder('utf8')
      let offset = 0
      for (;;) {
        if (signal?.aborted === true) throw new FsError('stream aborted', 'FS_ABORTED')
        const reply = await request('fs.get', {
          path: remote,
          offset,
          length: STREAM_READ_WINDOW,
          encoding: options.compression === false ? 'raw' : 'gzip',
        }, 600_000)
        const encoded = Buffer.from(String(reply.dataB64 ?? ''), 'base64')
        const data = reply.encoding === 'gzip' ? gunzipSync(encoded) : encoded
        if (data.length === 0) break
        offset += data.length
        const piece = decoder.write(data)
        if (piece !== '') yield piece
        if (reply.eof === true) break
      }
      const tail = decoder.end()
      if (tail !== '') yield tail
    })()
  }

  override async readBytes(
    target: FsTarget,
    signal: AbortSignal | undefined,
    maxBytes: number,
  ): Promise<Uint8Array> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.readBytes(target, signal, maxBytes)
    const info = await this.stat(target, signal)
    if (info === undefined) throw new FsError(`cannot read "${target.displayPath}": not found`, 'FS_NOT_FOUND')
    if (info.type !== 'file') {
      throw new FsError(`cannot read "${target.displayPath}": not a regular file`, 'FS_NOT_REGULAR_FILE')
    }
    if (info.size !== undefined && info.size > maxBytes) {
      throw new FsError(`cannot read "${target.displayPath}": file exceeds ${maxBytes} bytes`, 'FS_TOO_LARGE')
    }
    const fastPathBytes = this.transferConfig.transferFastPathBytes ?? DEFAULT_TRANSFER_FAST_PATH_BYTES
    const large = info.size !== undefined && info.size > fastPathBytes
    if (large && await this.fastTransferSupported(parsed.peer)) {
      const result = await downloadToBuffer(
        this.transferRequestOf(parsed.peer),
        parsed.remote,
        { ...this.transferOptionsOf(signal), maxBytes },
      )
      return result.data
    }
    return await this.readPeerAllBytes(parsed, signal, maxBytes)
  }

  override async readByteRange(
    target: FsTarget,
    range: { offset: number; length: number },
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.readByteRange(target, range, signal)
    return await this.readPeerBytes(parsed, range, signal)
  }

  /**
   * One bounded byte read over the link.
   * @param parsed - the peer and its path.
   * @param range - `offset` and the largest `length` to transfer.
   * @param signal - aborts before the request is sent.
   * @returns the window's bytes.
   */
  private async readPeerBytes(
    parsed: ParsedPeerPath,
    range: { offset: number; length: number },
    signal?: AbortSignal,
  ): Promise<Uint8Array> {
    if (signal?.aborted === true) throw new FsError('read aborted', 'FS_ABORTED')
    // Every read funnels through here, so one check covers readText,
    // readBytes and readByteRange alike.
    this.assertPeer(parsed, 'fs.read')
    const length = Math.max(0, Math.min(range.length, Number.MAX_SAFE_INTEGER))
    const reply = await this.linkFor(parsed.peer).request('fs.read', {
      path: parsed.remote,
      offset: range.offset,
      length: length === Number.MAX_SAFE_INTEGER ? DEFAULT_READ_WINDOW : length,
    })
    const encoded = typeof reply.dataB64 === 'string' ? reply.dataB64 : ''
    return Uint8Array.from(Buffer.from(encoded, 'base64'))
  }

  /**
   * One peer request, with the peer's typed failure code preserved.
   * @param parsed - the peer and the path it targets.
   * @param op - the wire operation name.
   * @param args - its arguments.
   * @returns the peer's reply.
   * @throws FsError carrying the peer's own code when it refused.
   */
  private async peerRequest(
    parsed: ParsedPeerPath,
    op: string,
    args: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    try {
      return await this.linkFor(parsed.peer).request(op, args)
    } catch (error) {
      const code = (error as { peerCode?: unknown }).peerCode
      if (typeof code === 'string' && /^FS_[A-Z_]+$/.test(code)) {
        throw new FsError(error instanceof Error ? error.message : String(error), code as never)
      }
      throw error
    }
  }

  // `sandboxPolicy` is part of the seam: the tool layer resolves the session's
  // per-call policy and passes it in. Dropping it here did not fail loudly —
  // the local branch fell back to the *deployment* default, so a read-only
  // session could be allowed to write and a workspace-write session denied,
  // with the containment root taken from config instead of the session cwd.
  // Peer targets deliberately keep bypassing the fence (the peer enforces its
  // own), so the parameter is only forwarded on the local branch.
  override async writeText(
    target: FsTarget,
    content: string,
    expected?: FsWriteIntent,
    signal?: AbortSignal,
    sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsWriteOutcome> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.writeText(target, content, expected, signal, sandboxPolicy)
    if (signal?.aborted === true) throw new FsError('write aborted', 'FS_ABORTED')
    this.assertPeer(parsed, 'fs.write')
    const data = Buffer.from(content, 'utf8')
    const fastPathBytes = this.transferConfig.transferFastPathBytes ?? DEFAULT_TRANSFER_FAST_PATH_BYTES
    if (data.length >= fastPathBytes && await this.fastTransferSupported(parsed.peer)) {
      try {
        const result = await uploadBuffer(this.transferRequestOf(parsed.peer), parsed.remote, data, {
          ...this.transferOptionsOf(signal),
          ...(expected?.kind === 'createIfAbsent' ? { createOnly: true } : {}),
          ...(expected?.kind === 'replaceIfVersion' ? { expectedVersion: String(expected.version) } : {}),
        })
        let version = result.version
        if (version === null) {
          // The peer committed but did not report a version: ask it once rather
          // than handing the FS layer a token it cannot guard against.
          const info = await this.stat(target, signal)
          version = info === undefined ? null : String(info.version)
        }
        if (version === null) throw new FsError('peer committed the write but reported no version', 'FS_IO_ERROR')
        return {
          operation: result.created ? 'create' : 'update',
          version: FsVersion(version),
          before: result.before,
          after: content,
        }
      } catch (error) {
        // Only "this peer does not actually know the fast ops" may fall back:
        // a permission/stale/checksum failure — or an ambiguous commit — must
        // reach the caller unchanged, or a retry could clobber the target.
        if (!this.isUnknownTransferOp(error)) throw error
      }
    }
    const reply = await this.peerRequest(parsed, 'fs.write', {
      path: parsed.remote,
      dataB64: data.toString('base64'),
      ...(expected?.kind === 'createIfAbsent' ? { createOnly: true } : {}),
      ...(expected?.kind === 'replaceIfVersion' ? { expectedVersion: String(expected.version) } : {}),
    })
    return {
      operation: reply.created === true ? 'create' : 'update',
      version: peerVersionOf(reply, parsed),
      before: typeof reply.before === 'string' ? reply.before : null,
      after: typeof reply.after === 'string' ? reply.after : content,
    }
  }

  override async editText(
    target: FsTarget,
    edit: FsEditRequest,
    expected?: { version: FsVersion },
    signal?: AbortSignal,
    sandboxPolicy?: SandboxExecutionPolicy,
  ): Promise<FsEditOutcome> {
    const parsed = splitPeerTargetKey(String(target.targetKey))
    if (parsed === undefined) return await super.editText(target, edit, expected, signal, sandboxPolicy)
    if (signal?.aborted === true) throw new FsError('edit aborted', 'FS_ABORTED')
    this.assertPeer(parsed, 'fs.edit')
    const reply = await this.peerRequest(parsed, 'fs.edit', {
      path: parsed.remote,
      oldString: edit.oldString,
      newString: edit.newString,
      replaceAll: edit.replaceAll === true,
      ...(expected === undefined ? {} : { expectedVersion: String(expected.version) }),
    })
    return {
      version: peerVersionOf(reply, parsed),
      before: String(reply.before ?? ''),
      after: String(reply.after ?? ''),
    }
  }
}

/**
 * Decode peer bytes as UTF-8 text without pretending binary is text.
 * @param bytes - the raw content.
 * @param displayPath - used in the error message.
 * @returns the decoded text.
 * @throws FsError with `FS_NOT_TEXT` when the content is not regular text.
 */
export function decodePeerText(bytes: Uint8Array, displayPath: string): string {
  if (bytes.includes(0)) {
    throw new FsError(`cannot read "${displayPath}": not a text file`, 'FS_NOT_TEXT')
  }
  return Buffer.from(bytes).toString('utf8')
}

export { FederatedFileSystem as default }
