/** Host-qualified @ references. No I/O, session creation, or configuration data. */
export interface ReferenceWorkspace { id: string; title: string; path: string }
export interface ReferencePlugin { id: string; name: string; title?: string; enabled: boolean | 'conditional'; presetId?: string }
export interface ReferenceCatalog {
  available: boolean
  workspaces: ReferenceWorkspace[]
  plugins: ReferencePlugin[]
  truncated: boolean
}
export type HostReference =
  | { peer: string; kind: 'path'; path: string }
  | { peer: string; kind: 'workspace' | 'plugin' | 'search'; query: string; relative: string }

/** Unknown hosts never become remote paths; Windows drive letters stay local. */
export function parseHostReference(query: string, peers: readonly string[]): HostReference | undefined {
  const colon = query.indexOf(':')
  if (colon < 2) return undefined
  const peer = query.slice(0, colon)
  if (!peers.includes(peer)) return undefined
  const tail = query.slice(colon + 1).replace(/\\/gu, '/')
  if (tail.startsWith('/')) return { peer, kind: 'path', path: tail.slice(1) }
  const typed = /^(workspace|plugin):(.*)$/su.exec(tail)
  if (typed?.[1] === 'plugin') return { peer, kind: 'plugin', query: typed[2] ?? '', relative: '' }
  const content = typed?.[2] ?? tail
  // Scoped npm plugin names contain a slash; only workspace-qualified values
  // interpret it as directory descent. Bare scoped names remain plugin searches.
  const slash = content.startsWith('@') && typed === null ? -1 : content.indexOf('/')
  return {
    peer, kind: typed?.[1] === 'workspace' ? 'workspace' : 'search',
    query: slash < 0 ? content : content.slice(0, slash),
    relative: slash < 0 ? '' : content.slice(slash + 1),
  }
}

export function parseReferenceCatalog(value: Record<string, unknown>): ReferenceCatalog {
  const rows = (v: unknown): Record<string, unknown>[] => Array.isArray(v)
    ? v.filter((row): row is Record<string, unknown> => row !== null && typeof row === 'object') : []
  return {
    available: value.available !== false,
    workspaces: rows(value.workspaces).flatMap(row => typeof row.id === 'string' && typeof row.title === 'string' && typeof row.path === 'string'
      ? [{ id: row.id, title: row.title, path: row.path }] : []),
    plugins: rows(value.plugins).flatMap(row => typeof row.id === 'string' && typeof row.name === 'string'
      ? [{ id: row.id, name: row.name, enabled: row.enabled === 'conditional' ? 'conditional' as const : row.enabled !== false,
        ...(typeof row.title === 'string' ? { title: row.title } : {}),
        ...(typeof row.presetId === 'string' ? { presetId: row.presetId } : {}),
      }] : []),
    truncated: value.truncated === true,
  }
}

/** Titles are display names, not unique keys. Return every exact match. */
export function matchingWorkspaces(rows: readonly ReferenceWorkspace[], name: string): ReferenceWorkspace[] {
  const id = rows.filter(row => row.id === name)
  return id.length > 0 ? id : rows.filter(row => row.title === name)
}

/** Never let a workspace-relative expression become a path to its parent. */
export function workspaceChildPath(root: string, relative: string): string {
  const suffix = relative.replace(/\\/gu, '/')
  if (suffix.startsWith('/') || /[\u0000-\u001f\u007f:]/u.test(suffix)
    || suffix.split('/').some(segment => segment === '..' || segment === '.')) {
    throw new Error('Workspace child paths must be relative and cannot contain traversal or drive prefixes')
  }
  const base = root.replace(/\\/gu, '/').replace(/\/+$/u, '')
  if (!/^(?:[A-Za-z]:\/|\/)/u.test(`${base}/`)) throw new Error('Workspace registry returned a non-absolute path')
  return suffix === '' ? (base || '/') : `${base}/${suffix}`
}

/** Caller budgets apply before scanning or retaining reference text. */
export interface ReferenceTokenBounds {
  /** UTF-16 input characters inspected; default 65,536, maximum 1,048,576. */
  maxChars?: number
  /** UTF-16 characters in a complete query; default 2,048, maximum 8,192. */
  maxQueryLength?: number
  /** Distinct queries returned; default 20, maximum 100. */
  maxMentions?: number
}
export interface ReferenceTokenExtraction { tokens: string[]; truncated: boolean }
export const DEFAULT_REFERENCE_TOKEN_BOUNDS = Object.freeze({ maxChars: 65_536, maxQueryLength: 2_048, maxMentions: 20 })

function tokenBounds(options: ReferenceTokenBounds): Required<ReferenceTokenBounds> {
  const resolved = { ...DEFAULT_REFERENCE_TOKEN_BOUNDS, ...options }
  for (const [key, maximum] of [['maxChars', 1_048_576], ['maxQueryLength', 8_192], ['maxMentions', 100]] as const) {
    const value = resolved[key]
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new TypeError(`${key} must be an integer from 1 to ${maximum}`)
  }
  return resolved
}

/**
 * Retain every UTF-16 offset and non-code boundary. Replacing code with spaces
 * would turn `@host:name`code`` or `code`@host:name into a different valid token.
 */
function referenceProse(text: string): string {
  const mask = (value: string): string => value.replace(/[^\r\n]/g, '\u0000')
  const lines: string[] = []
  let fence: { character: string; length: number } | undefined
  for (const line of text.split(/(?<=\n)/u)) {
    const marker = /^ {0,3}(`{3,}|~{3,})(.*)$/u.exec(line.replace(/\r?\n$/u, ''))
    if (fence !== undefined) {
      lines.push(mask(line))
      if (marker?.[1]?.[0] === fence.character && marker[1].length >= fence.length && marker[2]?.trim() === '') fence = undefined
    } else if (marker?.[1] !== undefined && (marker[1][0] !== '`' || !marker[2]?.includes('`'))) {
      fence = { character: marker[1][0]!, length: marker[1].length }
      lines.push(mask(line))
    } else lines.push(/^(?: {4}|\t)/u.test(line) ? mask(line) : line)
  }
  const fenced = lines.join('')
  const runs: Array<{ start: number; end: number; length: number; next?: number }> = []
  for (const match of fenced.matchAll(/`+/gu)) runs.push({ start: match.index, end: match.index + match[0].length, length: match[0].length })
  // A reverse index finds exact closing run lengths without repeated suffix
  // searches, including multiline inline spans and unusually long delimiters.
  const nextByLength = new Map<number, number>()
  for (let index = runs.length - 1; index >= 0; index--) {
    const run = runs[index]!
    const next = nextByLength.get(run.length)
    if (next !== undefined) run.next = next
    nextByLength.set(run.length, index)
  }
  const output: string[] = []
  let cursor = 0
  for (let index = 0; index < runs.length; index++) {
    const run = runs[index]!
    if (run.start < cursor) continue
    output.push(fenced.slice(cursor, run.start))
    const close = run.next === undefined ? undefined : runs[run.next]
    const newline = close === undefined ? fenced.indexOf('\n', run.end) : -1
    const end = close?.end ?? (newline < 0 ? fenced.length : newline)
    output.push(mask(fenced.slice(run.start, end)))
    cursor = end
    if (run.next !== undefined) index = run.next
  }
  output.push(fenced.slice(cursor))
  return output.join('')
}

/**
 * Extract complete Host-grammar @path / @"path with spaces" from original
 * prose. Email, fenced/indented/inline code and malformed suffixes never trigger
 * discovery. The Host formatter's final open quoted directory ending `/` is
 * accepted only at the actual end of the input, not at a scan-budget boundary.
 */
export function extractReferenceTokens(text: string, options: ReferenceTokenBounds = {}): ReferenceTokenExtraction {
  const { maxChars, maxQueryLength, maxMentions } = tokenBounds(options)
  const bounded = text.slice(0, maxChars)
  const prose = referenceProse(bounded)
  const tokens: string[] = []
  const seen = new Set<string>()
  let truncated = text.length > maxChars
  for (let index = 0; index < prose.length; index++) {
    if (prose[index] !== '@' || index > 0 && !/\s/u.test(prose[index - 1]!)) continue
    const quoted = prose[index + 1] === '"'
    const start = index + (quoted ? 2 : 1)
    let end = start
    if (quoted) {
      while (end < prose.length && prose[end] !== '"' && prose[end] !== '\r' && prose[end] !== '\n') end++
      const closed = prose[end] === '"'
      const queryEnd = end
      if (closed) end++
      else if (end !== text.length || text[end - 1] !== '/') { index = end; continue }
      if (end < text.length && !/\s/u.test(text[end]!)) { index = end; continue }
      if (queryEnd - start > maxQueryLength) { truncated = true; index = end - 1; continue }
      const query = text.slice(start, queryEnd)
      if (query === '' || /[\u0000-\u001f\u007f-\u009f"]/u.test(prose.slice(start, queryEnd))) { index = end - 1; continue }
      if (!seen.has(query)) {
        if (tokens.length >= maxMentions) { truncated = true; break }
        tokens.push(query); seen.add(query)
      }
    } else {
      while (end < prose.length && !/\s/u.test(prose[end]!)) end++
      if (end === prose.length && end < text.length && !/\s/u.test(text[end]!)) { index = end - 1; continue }
      if (end - start > maxQueryLength) { truncated = true; index = end - 1; continue }
      const query = text.slice(start, end)
      if (query === '' || /[\u0000-\u001f\u007f-\u009f"]/u.test(prose.slice(start, end))) { index = end - 1; continue }
      if (!seen.has(query)) {
        if (tokens.length >= maxMentions) { truncated = true; break }
        tokens.push(query); seen.add(query)
      }
    }
    index = end - 1
  }
  return { tokens, truncated }
}

/** Compatibility helper for consumers that need only the bounded query list. */
export function referenceTokens(text: string, options: ReferenceTokenBounds = {}): string[] {
  return extractReferenceTokens(text, options).tokens
}
