/** Bounded discovery and resolution for typed and hand-written @host:resource. */
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { mountPathFor } from './remote-path.ts'
import { matchingWorkspaces, parseHostReference, parseReferenceCatalog, workspaceChildPath } from './reference-query.ts'
import type { HostReference, ReferenceCatalog, ReferencePlugin } from './reference-query.ts'

export interface ReferenceDeps {
  peers(): string[]
  list(peer: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<Record<string, unknown>>
}
const shortName = (name: string): string => name.replace(/^@[^/]+\//u, '')
const pluginExact = (row: ReferencePlugin, query: string): boolean => row.id === query || row.name === query || row.title === query || shortName(row.name) === query

export function resolveCatalogReference(parsed: HostReference, catalog: ReferenceCatalog): Record<string, unknown> {
  if (parsed.kind === 'path') return { status: 'resolved', kind: 'path', peer: parsed.peer, path: mountPathFor(parsed.peer, parsed.path, false) }
  const workspaces = parsed.kind === 'plugin' ? [] : matchingWorkspaces(catalog.workspaces, parsed.query)
  const plugins = parsed.kind === 'workspace' || parsed.relative !== '' ? [] : catalog.plugins.filter(row => pluginExact(row, parsed.query))
  if (workspaces.length === 1 && plugins.length === 0 && !catalog.truncated) {
    const workspace = workspaces[0]!
    return { status: 'resolved', kind: 'workspace', peer: parsed.peer, workspace,
      path: mountPathFor(parsed.peer, workspaceChildPath(workspace.path, parsed.relative), false) }
  }
  if (workspaces.length === 0 && plugins.length > 0) {
    // The same package may be contributed by multiple presets; report all
    // registrations so a caller can choose the intended preset explicitly.
    const names = new Set(plugins.map(row => row.name))
    return { status: names.size === 1 && !catalog.truncated ? 'resolved' : 'ambiguous', kind: 'plugin', peer: parsed.peer, plugins, truncated: catalog.truncated }
  }
  if (workspaces.length > 0 || plugins.length > 0) {
    return { status: 'ambiguous', peer: parsed.peer, workspaces, plugins, truncated: catalog.truncated }
  }
  return { status: 'not-found', peer: parsed.peer, workspaces: catalog.workspaces, plugins: catalog.plugins, truncated: catalog.truncated }
}

/** A lexical match is not a resolved workspace child until its host verifies
 * canonical containment. All consumers (tool, message mapping, completion) use
 * this read-only protocol operation rather than trusting a concatenated path. */
export async function resolveRemoteReference(
  deps: ReferenceDeps, parsed: HostReference, signal?: AbortSignal, limit = 40,
): Promise<Record<string, unknown>> {
  signal?.throwIfAborted()
  if (parsed.kind === 'path') return resolveCatalogReference(parsed, { available: true, workspaces: [], plugins: [], truncated: false })
  const catalog = parseReferenceCatalog(await deps.list(parsed.peer, {
    query: parsed.query, kind: parsed.kind === 'search' ? 'all' : parsed.kind, limit,
  }, signal))
  if (!catalog.available) return { status: 'unavailable', peer: parsed.peer }
  const result = resolveCatalogReference(parsed, catalog)
  if (result.status !== 'resolved' || result.kind !== 'workspace') return result
  const resolved = await deps.list(parsed.peer, {
    query: (result.workspace as { id: string }).id,
    kind: 'workspace', relative: parsed.relative, resolve: true, limit: 2,
  }, signal)
  signal?.throwIfAborted()
  if (resolved.status !== 'resolved' || typeof resolved.path !== 'string') {
    return { status: resolved.status === 'ambiguous' ? 'ambiguous' : 'unavailable', peer: parsed.peer }
  }
  return { ...result, path: mountPathFor(parsed.peer, resolved.path, false), fileKind: resolved.kind }
}

export function createReferenceTool(deps: ReferenceDeps): ToolDefinition {
  return defineTool({
    name: 'remote_references',
    description: '检索或解析 @主机:插件名、@主机:工作区名/子路径，返回带类型的候选与绝对远程路径；重名返回歧义，不创建会话、不读文件内容。',
    parameters: {
      query: { type: 'string', required: true, description: '完整引用（可带 @），或配合 peer 使用的资源名。类型重名时可写 主机:workspace:ID 或 主机:plugin:包名。' },
      peer: { type: 'string', description: '检索的已配置主机名；query 已含主机时可省略。' },
      kind: { type: 'string', enum: ['all', 'workspace', 'plugin'], description: '只检索该类型；默认 all。' },
      limit: { type: 'number', description: '每类候选上限，1–200，默认 40。' },
    },
    output: { schema: { type: 'json' }, render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }] },
    async execute(args: { query: string; peer?: string; kind?: string; limit?: number }, exec?: { signal?: AbortSignal }): Promise<JsonValue> {
      if (args.query.length > 2048 || /[\u0000-\u001f\u007f]/u.test(args.query)) throw new Error('Reference query exceeds its safe length or contains control characters')
      let raw = args.query
      if (raw.startsWith('@"') && raw.endsWith('"')) raw = raw.slice(2, -1)
      else if (raw.startsWith('@') && parseHostReference(raw.slice(1), deps.peers()) !== undefined) raw = raw.slice(1)
      const existing = parseHostReference(raw, deps.peers())
      if (existing !== undefined && args.peer !== undefined && args.peer !== existing.peer) throw new Error('The query host and peer parameter disagree')
      const query = existing !== undefined || args.peer === undefined ? raw : `${args.peer}:${raw}`
      let parsed = parseHostReference(query, deps.peers())
      if (parsed === undefined) throw new Error('Unknown or missing host; use a configured host name followed by a colon')
      if (parsed.kind !== 'path' && (args.kind === 'workspace' || args.kind === 'plugin')) parsed = { ...parsed, kind: args.kind }
      const limit = args.limit === undefined ? 40 : Math.max(1, Math.min(200, Math.trunc(args.limit)))
      if (!Number.isFinite(limit)) throw new Error('limit must be a finite number')
      return await resolveRemoteReference(deps, parsed, exec?.signal, limit) as unknown as JsonValue
    },
  })
}
