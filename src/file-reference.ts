/**
 * `@`-completion for remote paths: the local file-reference provider plus the
 * `rmt:` namespace.
 *
 * The shipped provider (`@deepseek-ai/dsh-file-reference-local`) owns their
 * agent's local workspace index. This subclass keeps every local query byte-for-
 * byte and adds one namespace of its own: `@rmt:/E:/…` lists the configured
 * peer's directories, using the same federated filesystem backend that serves
 * `read`/`write`/`edit` for `rmt:` paths. A selected mention is still ordinary
 * prompt text — nothing is read while completing.
 *
 * The provider is only useful when the federated backend (`dsh-remote/peer-fs`)
 * is mounted; it detects that through the backend's `supportsRemotePaths` marker
 * and otherwise simply offers local candidates.
 *
 * @module dsh-remote/file-reference
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import LocalFileReferenceService from '@deepseek-ai/dsh-file-reference-local'
import {
  DEFAULT_FILE_SEARCH_EXCLUDED_DIRECTORIES,
  DEFAULT_FILE_SEARCH_MAX_ENTRIES,
  DEFAULT_FILE_SEARCH_MAX_RESULTS,
} from '@deepseek-ai/dsh-file-reference-local'
import type { Config as LocalFileReferenceConfig } from '@deepseek-ai/dsh-file-reference-local'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { FileReferenceCandidate } from '@deepseek-ai/dsh-file-reference'
import type { FileSystem } from '@deepseek-ai/dsh-fs'
import type {} from '@deepseek-ai/dsh-system-prompt'
import type {} from '@deepseek-ai/dsh-tools'

import { MOUNT_PREFIX, parseMountReferenceQuery, parseRemoteReferenceQuery, parseScpReferenceQuery, scpPathFor } from './remote-path.ts'
import { matchingWorkspaces, parseHostReference, parseReferenceCatalog, workspaceChildPath } from './reference-query.ts'
import type { ReferenceDeps } from './reference-tool.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-file-reference'

/**
 * Guidance the provider adds when the peer namespace is usable.
 *
 * It is separate from `FILE_REFERENCE_PROMPT` (which the local provider owns)
 * because it only tells the truth when the federated backend is mounted.
 */
export const REMOTE_REFERENCE_PROMPT = 'Remote references: @host:/C:/path is a path on that configured host; @host:workspace/child resolves a DSH named workspace; @host:plugin names a remote plugin. Use remote_references(query) to discover or resolve names; ambiguous titles require the workspace ID, and explicit host:workspace:ID / host:plugin:package disambiguate types. References discover metadata only, never create sessions or execute tools. remote_capabilities(peer) and remote_tool_call(peer, name, arguments) target that host. Markdown files/images must use absolute /rmt/<host>/C:/path; /rmt/C:/path and rmt:/… address the configured default host. Never assume a local path exists remotely.'

/** How long a probed drive list stays valid. */
const DRIVE_CACHE_MS = 5 * 60_000

/** Drive letters probed for `rmt:/` root completion (A/B floppies are skipped). */
const DRIVE_LETTERS = 'CDEFGHIJKLMNOPQRSTUVWXYZ'.split('')

/** File-reference config: the local provider's knobs. */
export type Config = LocalFileReferenceConfig

export const Config = z.object({
  maxResults: z.number().step(1).min(1).default(DEFAULT_FILE_SEARCH_MAX_RESULTS),
  maxEntries: z.number().step(1).min(1).default(DEFAULT_FILE_SEARCH_MAX_ENTRIES),
  excludedDirectories: z.array(z.string()).default([...DEFAULT_FILE_SEARCH_EXCLUDED_DIRECTORIES]),
})

/** The federated backend, when it is mounted and advertises remote paths. */
interface RemoteCapableFileSystem extends FileSystem {
  supportsRemotePaths?: unknown
  /** Declared peer names, in declaration order. */
  remotePeerNames?: () => string[]
  /** The peer a bare `/rmt/…` path addresses. */
  remoteDefaultPeerName?: () => string
}

/**
 * File-reference provider: local workspace completion plus the `rmt:` namespace.
 */
export class RemoteFileReferenceService extends LocalFileReferenceService {
  readonly supportsWorkspaceReferences = true
  private readonly owner: Context
  private readonly remoteMaxResults: number
  private readonly remotePromptFibers = new Map<Agent, ReturnType<Context['inject']>>()
  private readonly driveCaches = new Map<string, { at: number; roots: string[] }>()
  private warnedAt = 0

  constructor(ctx: Context, config: Config = {}) {
    super(ctx, config)
    this.owner = ctx
    this.remoteMaxResults = config.maxResults ?? DEFAULT_FILE_SEARCH_MAX_RESULTS

    const installPrompt = (agent: Agent): void => {
      if (this.remotePromptFibers.has(agent)) return
      try {
        const fiber = agent.ctx.inject(['systemPrompt', 'tools'], (scope: Context) => {
          scope.systemPrompt.section({
            name: 'context:file-reference-remote',
            order: scope.systemPrompt.getSectionOrder('FILE_REFERENCE') + 1,
            text: () => {
              if (this.fsService() === undefined) return ''
              return scope.tools.get('read', agent) === undefined ? '' : REMOTE_REFERENCE_PROMPT
            },
          })
        })
        this.remotePromptFibers.set(agent, fiber)
      } catch (error) {
        ctx.logger.debug(`dsh-remote-file-reference: could not install remote guidance: ${String(error)}`)
      }
    }
    const disposePrompt = (agent: Agent): void => {
      const fiber = this.remotePromptFibers.get(agent)
      if (fiber === undefined) return
      this.remotePromptFibers.delete(agent)
      void fiber.dispose().catch((error: unknown) => {
        ctx.logger.warn(`dsh-remote-file-reference: prompt cleanup failed: ${error instanceof Error ? error.message : String(error)}`)
      })
    }
    for (const agent of this.agentsList()) installPrompt(agent)
    ctx.on('agent/created', ({ agent }) => {
      installPrompt(agent)
      return undefined
    })
    ctx.on('agent/disposed', ({ agent }) => {
      disposePrompt(agent)
      return undefined
    })
    ctx.effect(() => async () => {
      const fibers = [...this.remotePromptFibers.values()]
      this.remotePromptFibers.clear()
      await Promise.all(fibers.map(fiber => fiber.dispose()))
    }, 'dsh-remote-file-reference: guidance')
  }

  /** The live agent list, when the registry is present. */
  private agentsList(): Agent[] {
    try {
      const agents = (this.owner as unknown as { get?: (name: string) => unknown }).get?.('agents') as
        | { list?: () => unknown }
        | undefined
      const list = agents?.list?.()
      return Array.isArray(list) ? list as Agent[] : []
    } catch {
      return []
    }
  }

  /** The mounted filesystem backend, only when it can resolve `rmt:` paths. */
  private fsService(): RemoteCapableFileSystem | undefined {
    try {
      const service = (this.owner as unknown as { get?: (name: string) => unknown }).get?.('fs') as
        | RemoteCapableFileSystem
        | undefined
      return service?.supportsRemotePaths === true ? service : undefined
    } catch {
      return undefined
    }
  }

  /**
   * Complete one `@` query.
   *
   * Three namespaces, in order:
   *  - a declared peer name spelled scp/rsync style (`home-pc:/E:/…`) — the
   *    default, so the completion menu offers a Linux-tooling-looking path;
   *  - a peer name being typed (`thi` → `home-pc:`), merged with local matches;
   *  - the `rmt:` alias for the default peer (kept for compatibility).
   * Everything else is the shipped local provider's, untouched.
   * @param agent - the agent whose completion is requested.
   * @param query - the text after `@`.
   * @param signal - caller cancellation.
   * @returns path-only candidates.
   */
  override async list(agent: Agent, query: string, signal: AbortSignal): Promise<FileReferenceCandidate[]> {
    const fs = this.fsService()
    const peerNames = fs?.remotePeerNames?.() ?? []
    const defaultPeer = fs?.remoteDefaultPeerName?.() ?? peerNames[0] ?? ''
    signal.throwIfAborted()
    const host = parseHostReference(query, peerNames)
    if (host !== undefined && host.kind !== 'path') {
      const service = this.owner.get('dshRemoteReferences') as unknown as ReferenceDeps | undefined
      // Bare host: now discovers resources; host:/ still discovers drives.
      if (service !== undefined) {
        try {
          const reply = await service.list(host.peer, {
            query: host.query, kind: host.kind === 'search' ? 'all' : host.kind, limit: this.remoteMaxResults,
          }, signal)
          const catalog = parseReferenceCatalog(reply)
          if (!catalog.available) return []
          const exact = matchingWorkspaces(catalog.workspaces, host.query)
          if (host.relative !== '' || query.endsWith('/')) {
            if (exact.length !== 1 || catalog.truncated) return []
            const workspace = exact[0]!
            workspaceChildPath(workspace.path, host.relative) // reject traversal before contacting the host
            const end = host.relative.endsWith('/') ? host.relative.length : host.relative.lastIndexOf('/') + 1
            const directory = host.relative.slice(0, end)
            const partial = host.relative.slice(end)
            const resolved = await service.list(host.peer, {
              query: workspace.id, kind: 'workspace', relative: directory, resolve: true, limit: 2,
            }, signal)
            if (resolved.status !== 'resolved' || typeof resolved.path !== 'string' || resolved.kind !== 'directory') return []
            const rest = `${resolved.path.replace(/\\/gu, '/').replace(/\/+$/u, '')}/${partial}`
            return this.listRemote(fs, { peer: host.peer, isDefaultPeer: false, partial, rest }, signal)
          }
          const workspaceRows = catalog.workspaces.map(workspace => ({
            path: scpPathFor(host.peer, workspace.path.replace(/\\/gu, '/').replace(/\/+$/u, '')), kind: 'directory' as const,
          }))
          const pluginRows = catalog.plugins.map(plugin => ({ path: `${host.peer}:plugin:${plugin.name}`, kind: 'file' as const }))
          return [...new Map([...workspaceRows, ...pluginRows].map(row => [row.path, row])).values()].slice(0, this.remoteMaxResults)
        } catch (error) { return this.remoteFailure(error, signal) }
      }
      // Compatibility: an old deployment without the discovery service can
      // still use host: to enumerate drive roots as before.
      if (host.query !== '') return []
    }

    // Typing `/rmt/…` still completes, but every candidate is offered in the
    // explicit `host:/…` spelling so a selected mention names its host.
    const mount = parseMountReferenceQuery(query, peerNames, defaultPeer)
    if (mount !== undefined) {
      try {
        if (mount.root) return this.peerMentions(peerNames)
        if (mount.peerHint !== undefined) {
          return [{ path: `${mount.peerHint}:`, kind: 'directory' as const }]
        }
        return await this.listRemote(fs, {
          peer: mount.peer === '' ? defaultPeer : mount.peer,
          isDefaultPeer: mount.peer === '' || mount.peer === defaultPeer,
          partial: mount.partial,
          rest: mount.rest,
        }, signal)
      } catch (error) {
        return this.remoteFailure(error, signal)
      }
    }

    // A peer name being typed: offer its mount directory, keeping local matches.
    const scp = parseScpReferenceQuery(query, peerNames)
    if (scp !== undefined) {
      if ('peerHint' in scp) {
        const local = await super.list(agent, query, signal).catch(() => [])
        return [...local, { path: `${scp.peerHint}:`, kind: 'directory' as const }]
      }
      try {
        return await this.listRemote(fs, {
          peer: scp.peer,
          isDefaultPeer: scp.peer === defaultPeer,
          partial: scp.partial,
          rest: scp.rest,
        }, signal)
      } catch (error) {
        return this.remoteFailure(error, signal)
      }
    }

    // Typed aliases keep completing, but every candidate comes back in the
    // explicit `host:/…` spelling.
    if (/^rmt$/iu.test(query)) {
      const local = await super.list(agent, query, signal).catch(() => [])
      if (defaultPeer === '') return [...local, { path: MOUNT_PREFIX, kind: 'directory' as const }]
      return [...local, { path: `${defaultPeer}:`, kind: 'directory' as const }]
    }
    const parsed = parseRemoteReferenceQuery(query)
    if (parsed === undefined) {
      const workspaces = this.owner.get('workspaceReferences') as unknown as {
        list(agent: Agent, query: string, signal: AbortSignal): Promise<FileReferenceCandidate[] | undefined>
        match?(query: string): 'hint' | 'path' | undefined
      } | undefined
      const extra = await workspaces?.list(agent, query, signal)
      if (extra === undefined) return super.list(agent, query, signal)
      if (workspaces?.match?.(query) === 'path' || /[\/\\]/u.test(query)) return extra
      const local = await super.list(agent, query, signal)
      return [...new Map([...extra, ...local].map(row => [row.path, row])).values()].slice(0, this.remoteMaxResults)
    }
    try {
      return await this.listRemote(fs, {
        peer: defaultPeer,
        isDefaultPeer: true,
        partial: parsed.partial,
        rest: parsed.rest,
      }, signal)
    } catch (error) {
      return this.remoteFailure(error, signal)
    }
  }

  /** Peer directories offered for the mount root and for name hints. */
  private peerMentions(peerNames: readonly string[]): FileReferenceCandidate[] {
    return peerNames.map(name => ({ path: `${name}:`, kind: 'directory' as const }))
  }

  /** Log a remote-completion failure once a minute and return no candidates. */
  private remoteFailure(error: unknown, signal: AbortSignal): FileReferenceCandidate[] {
    if ((error as { name?: string } | null)?.name === 'AbortError' || signal.aborted) throw error
    const now = Date.now()
    if (now - this.warnedAt > 60_000) {
      this.warnedAt = now
      this.owner.logger.debug(`dsh-remote-file-reference: remote completion failed: ${error instanceof Error ? error.message : String(error)}`)
    }
    return []
  }

  /** Complete one remote query, emitting `host:/…` candidates it can be typed from. */
  private async listRemote(
    fs: RemoteCapableFileSystem | undefined,
    parsed: { peer: string; isDefaultPeer: boolean; partial: string; rest: string },
    signal: AbortSignal,
  ): Promise<FileReferenceCandidate[]> {
    if (fs === undefined) return []
    if (signal.aborted) throw signal.reason ?? new Error('aborted')
    if (parsed.peer === '') return []
    // One spelling for both halves: the backend resolves `host:/…` exactly like
    // the mount form, so what completion shows is what the mention will say.
    const base = scpPathFor(parsed.peer, '')
    const rest = parsed.rest

    // `…:/` or `…:/E` → drive roots, filtered.
    if (rest === '' || /^[A-Za-z]:?$/u.test(rest)) {
      const roots = await this.driveRoots(fs, base, signal)
      const partial = rest.toLowerCase()
      return roots
        .filter(root => root.toLowerCase().startsWith(partial))
        .slice(0, this.remoteMaxResults)
        .map(root => ({
          // The mention formatter appends `/` to a directory; a candidate that
          // already carried one would render as `//`.
          path: `${base}${root.replace(/\/+$/u, '')}`,
          kind: 'directory' as const,
        }))
    }

    // One directory listing; the last segment is the completion prefix.
    const directoryEnd = rest.endsWith('/') ? rest.length : rest.lastIndexOf('/') + 1
    const directory = rest.slice(0, directoryEnd)
    const partial = rest.slice(directoryEnd).toLowerCase()
    const target = await fs.resolve(`${base}${directory}`, { signal })
    const entries = await fs.listDir(target, signal)
    const matched = entries
      .filter(entry => entry.name.toLowerCase().startsWith(partial))
      .sort((left, right) => {
        const leftDir = left.type === 'directory' ? 0 : 1
        const rightDir = right.type === 'directory' ? 0 : 1
        return leftDir === rightDir ? left.name.localeCompare(right.name) : leftDir - rightDir
      })
      .slice(0, this.remoteMaxResults)
    return matched.map(entry => ({
      // Directory candidates are path-only too: the mention formatter owns the
      // trailing separator (and keeps a quoted directory open for descending).
      path: `${base}${directory}${entry.name}`,
      kind: entry.type === 'directory' ? 'directory' as const : 'file' as const,
    }))
  }

  /**
   * Drive roots on the peer, probed once per cache window and alias form.
   *
   * The peer protocol has no "list volumes" op; a directory probe per letter is
   * the cheap, read-only way to discover them, and the result changes rarely
   * enough to cache.
   */
  private async driveRoots(
    fs: RemoteCapableFileSystem,
    aliasBase: string,
    signal: AbortSignal,
  ): Promise<string[]> {
    const cached = this.driveCaches.get(aliasBase)
    if (cached !== undefined && Date.now() - cached.at < DRIVE_CACHE_MS) return cached.roots
    const probes = await Promise.all(DRIVE_LETTERS.map(async (letter) => {
      const root = `${letter}:/`
      try {
        const target = await fs.resolve(`${aliasBase}${root}`, { signal })
        const info = await fs.stat(target, signal)
        return info?.type === 'directory' ? root : undefined
      } catch {
        return undefined
      }
    }))
    const roots = probes.filter((root): root is string => root !== undefined)
    this.driveCaches.set(aliasBase, { at: Date.now(), roots })
    return roots
  }
}

export default RemoteFileReferenceService
