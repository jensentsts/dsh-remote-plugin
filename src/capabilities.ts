/**
 * The peer's function-call surface, and the local mirrors of it.
 *
 * ## What this is for
 *
 * A remote DSH already has a *kernel* full of capabilities: its plugins, the
 * tools they register, the subagent providers, the agent presets. Driving that
 * machine through `remote_agent_prompt` makes the controller talk to its agent;
 * this module makes the controller call those capabilities **directly**, as if
 * they were local tools:
 *
 *   peer `caps.list`  → catalog of what the peer can call
 *   local mirror      → one local ToolDefinition per peer tool
 *   peer `caps.call`  → the peer's OWN tool body runs there, result comes back
 *
 * The mirror is deliberately data-only: it carries the peer's schema verbatim, so
 * the local model sees exactly the function the peer advertises. Nothing here
 * creates or resumes a session on the peer — a catalog read takes a preset scope
 * lease, and a call runs the tool definition itself.
 *
 * ## Naming
 *
 * A remote tool is registered under **its own name**. That is the zero-token
 * choice, and it is safe because DSH resolves tools per agent scope: a preset's
 * own `read`/`pwsh`/`todo_write` shadows a global mirror of the same name, so the
 * local tool always wins and the mirror only fills gaps. A mirror is therefore
 * skipped only when it would collide in the *global* layer (two plugins claiming
 * one name), which this module reports instead of hiding.
 *
 * @module dsh-remote/capabilities
 */

/** Where a peer tool came from, as far as the peer can tell. */
export type CatalogOrigin = 'preset' | 'global'

/** One tool the peer's kernel can run. */
export interface CatalogTool {
  /** The tool's registered name — the name the local mirror uses. */
  name: string
  /** Model-facing description, verbatim from the peer. */
  description: string
  /** Raw JSON Schema of the arguments, verbatim from the peer. */
  parameters: Record<string, unknown>
  /** `preset` when an agent preset contributes it, `global` when host-level. */
  origin: CatalogOrigin
  /** False when the peer refuses to run it (bridge tools, interactive tools, config). */
  callable: boolean
  /** Why the peer refuses, when it does. */
  reason?: string
}

/** One agent preset (the peer's subagent types). */
export interface CatalogPreset {
  id: string
  name?: string
  description?: string
  isDefault: boolean
  /** Present when the preset cannot compose a session. */
  broken?: string
}

/** One plugin row of a preset composition. */
export interface CatalogPluginRow {
  id: string | null
  name: string
  /** `conditional` when a `!!js` condition cannot be evaluated outside a mount. */
  enabled: boolean | 'conditional'
}

/** One preset's plugin inventory. */
export interface CatalogPlugin {
  presetId: string
  name?: string
  isDefault: boolean
  broken?: string
  rows: CatalogPluginRow[]
}

/** One live agent session on the peer (read-only context, never driven by a call). */
export interface CatalogSession {
  sessionId: string
  presetId?: string
  status?: string
  cwd?: string
}

/** The whole answer to one `caps.list`. */
export interface CapabilityCatalog {
  available: boolean
  /** Why the catalog is unavailable, when it is. */
  reason?: string
  build?: string
  /** The preset whose tool surface the catalog describes. */
  presetId: string
  presets: CatalogPreset[]
  tools: CatalogTool[]
  plugins: CatalogPlugin[]
  sessions: CatalogSession[]
  subagentProviders: string[]
}

/** One peer tool call's outcome. */
export interface CapabilityCallResult {
  /** Rendered content blocks, as the peer's own tool would have shown them. */
  content: unknown[]
  durationMs?: number
  /** The canonical value, when the peer returned one. */
  value?: unknown
}

/** One local mirror to register, plus how to run it. */
export interface ProxySpec {
  name: string
  description: string
  parameters: Record<string, unknown>
  /** Run the peer's tool. Throws with the peer's message on failure. */
  call(args: Record<string, unknown>, signal?: AbortSignal): Promise<CapabilityCallResult>
}

/** A catalog entry that produced no mirror, and why. */
export interface SkippedTool {
  name: string
  reason: string
  /** True when a LOCAL global tool already owns the name (the local tool wins). */
  local?: boolean
}

// ------------------------------------------------------------- defensive read

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined

const asString = (value: unknown): string | undefined =>
  typeof value === 'string' && value !== '' ? value : undefined

const asArray = (value: unknown): unknown[] => Array.isArray(value) ? value : []

const asBool = (value: unknown): boolean | undefined => typeof value === 'boolean' ? value : undefined

/**
 * Read one `caps.list` reply into the typed catalog.
 *
 * Total by construction: every field is optional on the wire, and a peer that
 * answers `available: false` (or an older peer that has no `caps.list` at all,
 * whose failure the caller handles) degrades to an empty catalog rather than to
 * a parse error.
 *
 * @param reply - the peer's raw reply object.
 * @returns the catalog, with `available: false` when the reply says so.
 */
export function parseCatalog(reply: Record<string, unknown>): CapabilityCatalog {
  const available = reply.available !== false
  const presetId = asString(reply.presetId) ?? ''
  const tools: CatalogTool[] = []
  for (const raw of asArray(reply.tools)) {
    const row = asRecord(raw)
    const name = asString(row?.name)
    if (row === undefined || name === undefined) continue
    const reason = asString(row.reason)
    tools.push({
      name,
      description: asString(row.description) ?? '',
      parameters: asRecord(row.parameters) ?? { type: 'object', properties: {} },
      origin: row.origin === 'global' ? 'global' : 'preset',
      callable: row.callable !== false,
      ...(reason === undefined ? {} : { reason }),
    })
  }
  const presets: CatalogPreset[] = []
  for (const raw of asArray(reply.presets)) {
    const row = asRecord(raw)
    const id = asString(row?.id)
    if (row === undefined || id === undefined) continue
    presets.push({
      id,
      ...(asString(row.name) === undefined ? {} : { name: String(row.name) }),
      ...(asString(row.description) === undefined ? {} : { description: String(row.description) }),
      isDefault: row.isDefault === true,
      ...(asString(row.broken) === undefined ? {} : { broken: String(row.broken) }),
    })
  }
  const plugins: CatalogPlugin[] = []
  for (const raw of asArray(reply.plugins)) {
    const row = asRecord(raw)
    const presetIdOfRow = asString(row?.presetId)
    if (row === undefined || presetIdOfRow === undefined) continue
    const rows: CatalogPluginRow[] = []
    for (const rawRow of asArray(row.rows)) {
      const pluginRow = asRecord(rawRow)
      const name = asString(pluginRow?.name)
      if (pluginRow === undefined || name === undefined) continue
      const enabled = pluginRow.enabled
      rows.push({
        id: typeof pluginRow.id === 'string' ? pluginRow.id : null,
        name,
        enabled: enabled === 'conditional' ? 'conditional' : enabled !== false,
      })
    }
    plugins.push({
      presetId: presetIdOfRow,
      ...(asString(row.name) === undefined ? {} : { name: String(row.name) }),
      isDefault: row.isDefault === true,
      ...(asString(row.broken) === undefined ? {} : { broken: String(row.broken) }),
      rows,
    })
  }
  const sessions: CatalogSession[] = []
  for (const raw of asArray(reply.sessions)) {
    const row = asRecord(raw)
    const sessionId = asString(row?.sessionId)
    if (row === undefined || sessionId === undefined) continue
    sessions.push({
      sessionId,
      ...(asString(row.presetId) === undefined ? {} : { presetId: String(row.presetId) }),
      ...(asString(row.status) === undefined ? {} : { status: String(row.status) }),
      ...(asString(row.cwd) === undefined ? {} : { cwd: String(row.cwd) }),
    })
  }
  const subagentProviders = asArray(reply.subagentProviders)
    .map(value => asString(value))
    .filter((value): value is string => value !== undefined)
  return {
    available,
    ...(asString(reply.reason) === undefined ? {} : { reason: String(reply.reason) }),
    ...(asString(reply.build) === undefined ? {} : { build: String(reply.build) }),
    presetId,
    presets,
    tools,
    plugins,
    sessions,
    subagentProviders,
  }
}

/**
 * Read one `caps.call` reply.
 * @param reply - the peer's raw reply object.
 * @returns rendered blocks and timing.
 */
export function parseCallResult(reply: Record<string, unknown>): CapabilityCallResult {
  return {
    content: asArray(reply.content),
    ...(typeof reply.durationMs === 'number' ? { durationMs: reply.durationMs } : {}),
    ...(reply.value === undefined ? {} : { value: reply.value }),
  }
}

// ------------------------------------------------------------------- rendering

/**
 * Turn rendered content blocks into the text a local model should read.
 *
 * Text is passed through verbatim; anything else (images, cards, tool-call
 * blocks) is reduced to a bracketed placeholder. An image block references an
 * attachment ON THE PEER, which the local harness has no way to resolve, so
 * pretending it were local content would be worse than saying what it is.
 *
 * @param blocks - the peer's rendered content blocks (untrusted shape).
 * @returns one text body, never empty.
 */
export function contentToText(blocks: readonly unknown[]): string {
  const parts: string[] = []
  for (const raw of blocks) {
    const block = asRecord(raw)
    if (block === undefined) continue
    const type = asString(block.type) ?? 'unknown'
    if (type === 'text') {
      const text = asString(block.text)
      if (text !== undefined) parts.push(text)
      continue
    }
    const label = asString(block.title) ?? asString(block.name) ?? asString(block.alt) ?? asString(block.text)
    parts.push(label === undefined ? `[${type}]` : `[${type}: ${label}]`)
  }
  return parts.length === 0 ? '(the peer returned no content)' : parts.join('\n')
}

/**
 * The local mirror text for one whole proxy call.
 * @param result - the peer's call outcome.
 * @returns model-facing text (content, plus a one-line timing footer).
 */
export function proxyResultText(result: CapabilityCallResult): string {
  const body = contentToText(result.content)
  return result.durationMs === undefined ? body : `${body}\n\n(executed on the remote host in ${result.durationMs} ms)`
}

// ------------------------------------------------------------------- mirrors

/**
 * Build one local mirror per peer tool that can be exposed.
 *
 * `taken` answers "is this name already registered in the local global layer?":
 * a name already taken is skipped with a reason instead of throwing inside
 * `tools.register`, so one collision cannot cost the whole catalog.
 *
 * @param catalog - the parsed peer catalog.
 * @param call - runs one peer tool by name.
 * @param taken - names already registered locally (global layer only).
 * @returns the mirrors and the skipped entries, both sorted by name.
 */
export function createProxySpecs(
  catalog: CapabilityCatalog,
  call: (name: string, args: Record<string, unknown>, signal?: AbortSignal) => Promise<CapabilityCallResult>,
  taken: (name: string) => boolean,
): { specs: ProxySpec[], skipped: SkippedTool[] } {
  const specs: ProxySpec[] = []
  const skipped: SkippedTool[] = []
  const seen = new Set<string>()
  for (const tool of catalog.tools) {
    if (seen.has(tool.name)) {
      skipped.push({ name: tool.name, reason: 'the peer listed it twice' })
      continue
    }
    seen.add(tool.name)
    if (!tool.callable) {
      skipped.push({ name: tool.name, reason: tool.reason ?? 'the peer marked it not callable' })
      continue
    }
    if (taken(tool.name)) {
      skipped.push({ name: tool.name, reason: 'a local plugin already owns this global tool name', local: true })
      continue
    }
    specs.push({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      call: (args, signal) => call(tool.name, args, signal),
    })
  }
  specs.sort((a, b) => a.name.localeCompare(b.name))
  skipped.sort((a, b) => a.name.localeCompare(b.name))
  return { specs, skipped }
}

// ------------------------------------------------------------------ presenting

/** Optional detail for {@link formatCatalog}. */
export interface FormatCatalogOptions {
  /** Local names already owned by a local plugin, annotated as hidden locally. */
  shadowed?: ReadonlySet<string>
  /** Ask for one tool's full schema instead of the normal overview. */
  tool?: string
}

/** First sentence (or 100 chars) of a description, for a one-line listing. */
function oneLine(description: string, limit = 100): string {
  const flat = description.replace(/\s+/gu, ' ').trim()
  const sentence = flat.split(/(?<=[.!。！?])\s/u)[0] ?? flat
  const body = sentence.length > 0 ? sentence : flat
  return body.length <= limit ? body : `${body.slice(0, limit)}…`
}

/**
 * Render the catalog as the text a model reads from `remote_capabilities`.
 *
 * Kept terse on purpose: the catalog is context, and a tool listing that costs
 * more than the tools it describes is a net loss. Parameters are shown only when
 * one tool is asked for by name.
 *
 * @param catalog - the parsed peer catalog.
 * @param options - local shadowing and optional single-tool detail.
 * @returns markdown-ish text.
 */
export function formatCatalog(catalog: CapabilityCatalog, options: FormatCatalogOptions = {}): string {
  const shadowed = options.shadowed ?? new Set<string>()
  const lines: string[] = []
  if (!catalog.available) {
    return `远端能力目录不可用：${catalog.reason ?? '对端没有回答 caps.list'}`
  }
  if (options.tool !== undefined) {
    const wanted = catalog.tools.find(tool => tool.name === options.tool)
    if (wanted === undefined) return `远端能力目录里没有名为 ${options.tool} 的工具`
    lines.push(`## ${wanted.name}`)
    lines.push(wanted.description === '' ? '(no description)' : wanted.description)
    lines.push(`- origin: ${wanted.origin}`)
    lines.push(`- callable: ${wanted.callable ? 'yes' : `no (${wanted.reason ?? 'refused'})`}`)
    lines.push(`- local mirror: ${wanted.callable && !shadowed.has(wanted.name) ? wanted.name : (shadowed.has(wanted.name) ? 'hidden — a local tool owns this name' : 'none')}`)
    lines.push('- parameters:')
    lines.push('```json')
    lines.push(JSON.stringify(wanted.parameters, null, 2))
    lines.push('```')
    return lines.join('\n')
  }

  const callable = catalog.tools.filter(tool => tool.callable)
  const refused = catalog.tools.filter(tool => !tool.callable)
  const preset = catalog.presets.find(row => row.id === catalog.presetId)
  const defaultPreset = catalog.presets.find(row => row.isDefault)?.id
  lines.push('## 远端 capability 目录')
  lines.push(
    `preset ${catalog.presetId}`
    + `${preset?.name === undefined ? '' : ` (${preset.name})`}`
    + `${defaultPreset === undefined ? '' : ` · 部署默认 preset: ${defaultPreset}`}`
    + `${catalog.build === undefined ? '' : ` · build ${catalog.build}`}`
    + ` · tools ${catalog.tools.length}`,
  )
  lines.push('')
  lines.push('### 可直接调用（本机已有同名工具时，本地工具优先）')
  if (callable.length === 0) lines.push('(none)')
  for (const tool of callable) {
    const tag = shadowed.has(tool.name) ? '  [本机同名工具优先，已隐藏]' : ''
    const origin = tool.origin === 'global' ? '  (host)' : ''
    lines.push(`- ${tool.name}${origin} — ${oneLine(tool.description)}${tag}`)
  }
  if (refused.length > 0) {
    lines.push('')
    lines.push('### 远端标记为不可调用')
    for (const tool of refused) lines.push(`- ${tool.name} — ${tool.reason ?? 'refused'}`)
  }
  lines.push('')
  lines.push('### Agent preset（子智能体类型）')
  for (const row of catalog.presets) {
    lines.push(
      `- ${row.id}${row.isDefault ? ' (default)' : ''}`
      + `${row.name === undefined ? '' : ` — ${row.name}`}`
      + `${row.broken === undefined ? '' : `  [broken: ${oneLine(row.broken, 80)}]`}`,
    )
  }
  if (catalog.subagentProviders.length > 0) {
    lines.push('')
    lines.push(`### 子智能体 provider: ${catalog.subagentProviders.join(', ')}`)
  }
  if (catalog.plugins.length > 0) {
    lines.push('')
    lines.push('### 插件清单（按 preset）')
    for (const row of catalog.plugins) {
      const enabled = row.rows.filter(plugin => plugin.enabled !== false).length
      const names = row.rows
        .filter(plugin => plugin.enabled !== false)
        .map(plugin => plugin.id ?? plugin.name)
        .slice(0, 12)
      lines.push(
        `- ${row.presetId}${row.isDefault ? ' (default)' : ''}: ${enabled}/${row.rows.length} enabled`
        + `${names.length === 0 ? '' : ` — ${names.join(', ')}${row.rows.length > names.length ? ', …' : ''}`}`
        + `${row.broken === undefined ? '' : `  [broken: ${oneLine(row.broken, 80)}]`}`,
      )
    }
  }
  if (catalog.sessions.length > 0) {
    lines.push('')
    lines.push('### 远端活跃会话（只读信息，本工具不会驱动它们）')
    for (const row of catalog.sessions.slice(0, 20)) {
      lines.push(
        `- ${row.sessionId}`
        + `${row.presetId === undefined ? '' : ` · preset ${row.presetId}`}`
        + `${row.status === undefined ? '' : ` · ${row.status}`}`
        + `${row.cwd === undefined ? '' : ` · ${row.cwd}`}`,
      )
    }
  }
  lines.push('')
  lines.push(
    '调用方式：上面列出的工具已直接注册成本机工具，可直接 function call；'
    + '要按名字调用（例如本机同名工具遮挡时），用 `remote_tool_call(name, arguments)`。',
  )
  return lines.join('\n')
}
