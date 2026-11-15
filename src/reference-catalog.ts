/** Read-only named resources for @ discovery; deliberately excludes configs/secrets. */
import type { Context } from '@deepseek-ai/cordis'
import type { ReferencePlugin, ReferenceWorkspace } from './reference-query.ts'
import { matchingWorkspaces, workspaceChildPath } from './reference-query.ts'
import type { FileSystem } from '@deepseek-ai/dsh-fs'

interface WorkspaceRegistry { list(): Array<{ id: string; title: string; path: string }> }
interface PluginInventory {
  listPlugins(): Promise<Array<{ entryId: string; moduleName: string; enabled: boolean; meta?: { title?: unknown } }>>
}
interface PresetInventory {
  compositionInventory(): Promise<Array<{ id: string; rows: Array<{ entryId: string | null; moduleName: string; enabled: boolean | 'conditional' }> }>>
}
const presentable = (value: string): boolean => value !== '' && !/[\u0000-\u001f\u007f"]/u.test(value)

/** Exact names and short package names both participate in plugin discovery. */
export function resourceMatches(query: string, ...names: Array<string | undefined>): boolean {
  const needle = query.toLocaleLowerCase()
  return needle === '' || names.some(name => name?.toLocaleLowerCase().includes(needle))
}

export async function listReferenceCatalog(
  ctx: Context, args: Record<string, unknown>, signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  signal?.throwIfAborted()
  const query = typeof args.query === 'string' ? args.query.slice(0, 300) : ''
  const limitValue = Number(args.limit ?? 40)
  const limit = Number.isFinite(limitValue) ? Math.max(1, Math.min(200, Math.trunc(limitValue))) : 40
  const kind = args.kind === 'workspace' || args.kind === 'plugin' ? args.kind : 'all'
  const get = (name: string): unknown => (ctx as unknown as { get(name: string): unknown }).get(name)
  const workspaces: ReferenceWorkspace[] = []
  const plugins: ReferencePlugin[] = []
  const errors: string[] = []
  let workspaceAvailable = false
  let pluginAvailable = false
  if (kind !== 'plugin') {
    const registry = get('workspaceRegistry') as WorkspaceRegistry | undefined
    workspaceAvailable = registry !== undefined
    for (const row of registry?.list() ?? []) {
      if (presentable(row.id) && resourceMatches(query, row.id, row.title)) {
        workspaces.push({ id: row.id, title: row.title, path: row.path })
      }
    }
  }
  if (kind !== 'workspace') {
    const manager = get('pluginManager') as PluginInventory | undefined
    const presets = get('agentPresets') as PresetInventory | undefined
    pluginAvailable = manager !== undefined || presets !== undefined
    if (manager !== undefined) {
      try {
        for (const row of await manager.listPlugins()) {
          const rawTitle = row.meta?.title
          const title = typeof rawTitle === 'string' ? rawTitle
            : rawTitle !== null && typeof rawTitle === 'object' ? Object.values(rawTitle).filter((value): value is string => typeof value === 'string').join(' · ') : undefined
          // file:// and absolute module entries expose deployment locations. The
          // public discovery catalog exposes package specifiers only.
          if (!presentable(row.moduleName) || /^(?:file:|[A-Za-z]:[\\/]|\/)/u.test(row.moduleName)) continue
          if (!resourceMatches(query, row.entryId, row.moduleName, title)) continue
          plugins.push({ id: row.entryId, name: row.moduleName, enabled: row.enabled,
            ...(title === undefined ? {} : { title }) })
        }
      } catch { errors.push('host-plugin-inventory-unavailable') }
    }
    if (presets !== undefined) {
      try {
        for (const preset of await presets.compositionInventory()) {
          for (const row of preset.rows) {
            if (!presentable(row.moduleName) || /^(?:file:|[A-Za-z]:[\\/]|\/)/u.test(row.moduleName)) continue
            if (!resourceMatches(query, row.entryId ?? undefined, row.moduleName)) continue
            plugins.push({ id: row.entryId ?? row.moduleName, name: row.moduleName, enabled: row.enabled, presetId: preset.id })
          }
        }
      } catch { errors.push('preset-plugin-inventory-unavailable') }
    }
  }
  signal?.throwIfAborted()
  // Resolve registered workspace children on their owning host. Its realpath-
  // aware fs.contains is authoritative, so a symlink cannot escape the root.
  if (args.resolve === true && kind === 'workspace') {
    const exact = matchingWorkspaces(workspaces, query)
    if (exact.length !== 1) return { available: true, status: exact.length === 0 ? 'not-found' : 'ambiguous', workspaces: exact.slice(0, limit), plugins: [], truncated: exact.length > limit }
    const workspace = exact[0]!
    const fs = get('fs') as FileSystem | undefined
    if (fs === undefined) return { available: false, reason: 'filesystem-unavailable', workspaces: [], plugins: [], truncated: false }
    const relative = typeof args.relative === 'string' ? args.relative : ''
    const root = await fs.resolve(workspace.path, { signal })
    const target = await fs.resolve(workspaceChildPath(workspace.path, relative), { signal })
    if (!fs.contains(root, target)) throw new Error('Workspace reference escapes its registered directory')
    const info = await fs.stat(target, signal)
    if (info === undefined) return { available: true, status: 'not-found', workspaces: [workspace], plugins: [], truncated: false }
    return { available: true, status: 'resolved', path: target.displayPath, kind: info.type, workspaces: [workspace], plugins: [], truncated: false }
  }
  const unique = [...new Map(plugins.map(row => [`${row.presetId ?? ''}\0${row.id}\0${row.name}`, row])).values()]
  return {
    available: workspaceAvailable || pluginAvailable,
    workspaceAvailable, pluginAvailable,
    workspaces: workspaces.slice(0, limit), plugins: unique.slice(0, limit),
    truncated: workspaces.length > limit || unique.length > limit,
    ...(errors.length === 0 ? {} : { errors }),
  }
}
