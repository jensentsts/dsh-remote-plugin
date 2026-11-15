/**
 * Self-test for capability federation: the peer's function-call surface, the
 * local mirrors, and the wire ops behind both.
 *
 * Two layers, because they fail in different ways:
 *
 *  1. the pure helpers (`src/capabilities.ts`) - parsing, naming, rendering, and
 *     which entries become mirrors;
 *  2. a REAL loopback pair - the actual `server.apply()` listener on a random
 *     port and the actual `client.apply()` half in the same process, over the
 *     real handshake, with fake cordis services on both sides. That proves the
 *     thing this feature exists for: a local tool name whose body runs on the
 *     peer through `caps.call`, with no session created there.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/capabilities.test.ts
 */

import { connect } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { createServer } from 'node:net'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const home = mkdtempSync(join(tmpdir(), 'dshr-caps-'))
process.env.DSH_HOME = home

const caps = await import('../src/capabilities.ts')
const { clientHandshake, generateKeyPair, parsePrivateKey, privateToPem, publicToPem } = await import('../src/protocol.ts')

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

const wait = (ms: number): Promise<void> => new Promise(resolve => { setTimeout(resolve, ms) })

/** Poll until the probe answers true, or the deadline expires. */
async function until(probe: () => boolean, timeoutMs = 5000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (probe()) return true
    await wait(25)
  }
  return probe()
}

async function freePort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port
  await new Promise<void>(resolve => probe.close(() => resolve()))
  return port
}

// ---------------------------------------------------------------------------
// 1. the pure helpers
// ---------------------------------------------------------------------------

console.log('\n== 1. catalog parsing and mirror selection ==')
{
  const catalog = caps.parseCatalog({
    available: true,
    build: 'r21',
    presetId: 'standard',
    tools: [
      { name: 'read', description: 'Read', parameters: { type: 'object', properties: {} }, callable: true, origin: 'preset' },
      { name: 'remote_exec', description: 'loop', parameters: {}, callable: false, reason: 'bridge tool' },
      { name: 'taken', description: 'collides', parameters: {}, callable: true, origin: 'global' },
      { name: 'odd', description: 'no reason', parameters: {}, callable: false },
    ],
    presets: [{ id: 'standard', name: 'Standard', isDefault: true }],
    plugins: [{ presetId: 'standard', isDefault: true, rows: [{ id: 'tool-fs', name: '@deepseek-ai/dsh-tool-fs', enabled: true }, { id: 'x', name: 'off', enabled: false }] }],
    sessions: [{ sessionId: 's-1', presetId: 'standard', status: 'idle', cwd: 'C:/w' }],
    subagentProviders: ['spawn', 'remote'],
  })
  check('available and preset round-trip', catalog.available && catalog.presetId === 'standard')
  check('tools parse', catalog.tools.length === 4 && catalog.tools[0]?.name === 'read', JSON.stringify(catalog.tools.map(t => t.name)))
  check('a refusal without a reason still reads as not callable',
    catalog.tools.find(t => t.name === 'odd')?.callable === false)
  check('presets/plugins/sessions/providers parse',
    catalog.presets.length === 1 && catalog.plugins[0]?.rows.length === 2
    && catalog.sessions[0]?.sessionId === 's-1' && catalog.subagentProviders.join(',') === 'spawn,remote')
  check('an unavailable reply degrades instead of throwing',
    caps.parseCatalog({ available: false, reason: 'off' }).available === false)

  const { specs, skipped } = caps.createProxySpecs(
    catalog,
    async (name) => ({ content: [{ type: 'text', text: `called ${name}` }] }),
    name => name === 'taken',
  )
  check('one callable, non-colliding tool becomes a mirror', specs.length === 1 && specs[0]?.name === 'read', JSON.stringify(specs.map(s => s.name)))
  check('the refusal and the collision are reported, not hidden',
    skipped.some(row => row.name === 'remote_exec') && skipped.some(row => row.name === 'taken' && row.local === true),
    JSON.stringify(skipped))
  const result = await specs[0]?.call({}, undefined)
  check('the mirror forwards the tool name', result?.content !== undefined
    && JSON.stringify(result.content).includes('called read'), JSON.stringify(result))
}

console.log('\n== 2. rendering and the human-readable catalog ==')
{
  check('text blocks pass through, others are labelled',
    caps.contentToText([{ type: 'text', text: 'a' }, { type: 'image', alt: 'shot' }]) === 'a\n[image: shot]')
  check('an empty result is not an empty string',
    caps.contentToText([]) === '(the peer returned no content)')
  check('the proxy footer names the remote timing',
    caps.proxyResultText({ content: [{ type: 'text', text: 'ok' }], durationMs: 12 }).includes('remote host in 12 ms'))

  const catalog = caps.parseCatalog({
    available: true,
    presetId: 'standard',
    tools: [
      { name: 'read', description: 'Read a file.', parameters: { type: 'object', properties: {} }, callable: true },
      { name: 'hidden', description: 'Hidden.', parameters: {}, callable: true },
      { name: 'remote_exec', description: '', parameters: {}, callable: false, reason: 'bridge' },
    ],
    presets: [{ id: 'standard', isDefault: true }, { id: 'minimal' }],
    plugins: [{ presetId: 'standard', isDefault: true, rows: [{ id: 'p1', name: 'pkg', enabled: true }] }],
    sessions: [{ sessionId: 's-1', status: 'idle' }],
    subagentProviders: ['spawn'],
  })
  const text = caps.formatCatalog(catalog, { shadowed: new Set(['hidden']) })
  check('lists callable tools and the local-shadow note',
    text.includes('- read') && text.includes('[本机同名工具优先，已隐藏]'), text.slice(0, 300))
  check('lists the refusal', text.includes('remote_exec — bridge'))
  check('lists presets, plugins, sessions and providers',
    text.includes('standard (default)') && text.includes('p1') && text.includes('s-1') && text.includes('spawn'))
  const detail = caps.formatCatalog(catalog, { tool: 'read' })
  check('one-tool detail carries the parameters schema',
    detail.includes('"properties"') && detail.includes('- local mirror: read'), detail.slice(0, 200))
  check('an unavailable catalog says so',
    caps.formatCatalog({ ...catalog, available: false, reason: 'off' }).includes('不可用'))
}

// ---------------------------------------------------------------------------
// 3. the real loopback pair
// ---------------------------------------------------------------------------

const controller = generateKeyPair()
const pin = { peerPublicKey: publicToPem(controller.publicKey) }

/** Recorded executions on the fake peer, so the test can prove where a body ran. */
const executions: Array<{ name: string, args: unknown, agent: unknown }> = []

/** One peer tool catalog plus the surfaces the two halves read. */
function peerHarness() {
  const presetTools = new Map<string, Record<string, unknown>>([
    ['read', {
      name: 'read',
      description: 'Read a file.',
      parameters: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
      output: { schema: {}, render: (_args: unknown, value: unknown) => [{ type: 'text', text: `read ${String(value)}` }] },
      async execute(args: Record<string, unknown>, exec: { agent?: unknown }) {
        executions.push({ name: 'read', args, agent: exec.agent })
        return `content-of-${String(args.path)}`
      },
    }],
    ['long', {
      name: 'long',
      description: 'Waits until aborted.',
      parameters: { type: 'object', properties: {} },
      output: { schema: {}, render: () => [{ type: 'text', text: 'never' }] },
      execute: (_args: unknown, exec: { signal: AbortSignal }) => new Promise((_resolve, reject) => {
        if (exec.signal.aborted) { reject(new Error('aborted')); return }
        exec.signal.addEventListener('abort', () => reject(new Error('aborted by signal')), { once: true })
      }),
    }],
    ['bad', {
      name: 'bad',
      description: 'Always throws.',
      parameters: { type: 'object', properties: {} },
      output: { schema: {}, render: () => [] },
      async execute() { throw new Error('remote tool exploded') },
    }],
    // The name that broke a real boot when it was mirrored into the GLOBAL layer:
    // the official host plugin owning it could no longer register.
    ['load_workspace_dependencies', {
      name: 'load_workspace_dependencies',
      description: 'Loads workspace dependencies (peer copy).',
      parameters: { type: 'object', properties: {} },
      output: { schema: {}, render: () => [] },
      async execute() { return 'should not be mirrored locally' },
    }],
    ['remote_exec', {
      name: 'remote_exec',
      description: 'A bridge tool; must be refused.',
      parameters: { type: 'object', properties: {} },
      output: { schema: {}, render: () => [] },
      async execute() { return 'should never run' },
    }],
    ['ask_user_question', {
      name: 'ask_user_question',
      description: 'Interactive; refused by config.',
      parameters: { type: 'object', properties: {} },
      output: { schema: {}, render: () => [] },
      async execute() { return 'should never run' },
    }],
  ])
  /** Global (host-level) tool, also mirrored but claimed locally by the client. */
  const globalTools = new Map<string, Record<string, unknown>>([
    ['taken', {
      name: 'taken',
      description: 'A global tool the client already owns.',
      parameters: { type: 'object', properties: {} },
      output: { schema: {}, render: () => [] },
      async execute() { return 'taken' },
    }],
  ])
  const allTools = new Map([...globalTools, ...presetTools])
  const services: Record<string, unknown> = {
    tools: {
      schemas: (scope?: unknown) => {
        if (scope === undefined) return [...globalTools.values()].map(tool => ({ name: tool.name, description: tool.description, parameters: tool.parameters }))
        return [...allTools.values()].map(tool => ({ name: tool.name, description: tool.description, parameters: tool.parameters }))
      },
      get: (name: string, scope?: unknown) => scope === undefined ? globalTools.get(name) : allTools.get(name),
    },
    agentPresets: {
      defaultId: 'standard',
      acquireScope: async (id?: string) => ({
        key: { preset: id ?? 'standard' },
        [Symbol.asyncDispose]: async () => {},
      }),
      resolve: async (id?: string) => {
        if (id !== undefined && id !== 'standard') throw new Error(`Unknown agent preset: ${id}`)
        return { id: 'standard', name: 'Standard' }
      },
      list: async () => [{ id: 'standard', name: 'Standard', order: 1 }],
      compositionInventory: async () => [{
        id: 'standard',
        name: 'Standard',
        isDefault: true,
        rows: [
          { entryId: 'tool-fs', moduleName: '@deepseek-ai/dsh-tool-fs', enabled: true },
          { entryId: 'off', moduleName: 'disabled-row', enabled: false },
        ],
      }],
      composedPreset: () => 'standard',
    },
    agents: { list: () => [{ id: 'peer-session', status: 'idle', ctx: {}, session: { header: { cwd: 'C:/peer' } } }] },
    subagents: { list: () => ['spawn'] },
  }
  const handlers = new Map<string, Array<(...args: unknown[]) => void>>()
  const ctx: Record<string, unknown> = {
    logger: { info() {}, warn() {}, debug() {}, error() {} },
    effect(fn: () => unknown) { const stop = fn(); return typeof stop === 'function' ? stop : () => {} },
    on(event: string, handler: (...args: unknown[]) => void) {
      const list = handlers.get(event) ?? []
      list.push(handler)
      handlers.set(event, list)
      return () => {}
    },
    get(name: string) { return services[name] },
  }
  return {
    ctx,
    presetTools,
    allTools,
    fire: (event: string, ...args: unknown[]) => { for (const handler of handlers.get(event) ?? []) handler(...args) },
  }
}

interface Running { port: number, stop: () => void }

const server = await import('../src/server.ts')

async function startServer(
  fake: ReturnType<typeof peerHarness>,
  config: Record<string, unknown> = {},
): Promise<Running> {
  const port = await freePort()
  const disposers: Array<() => void> = []
  const ctx = fake.ctx as Record<string, unknown>
  const previousEffect = ctx.effect
  ctx.effect = (fn: () => unknown) => {
    const stop = fn()
    if (typeof stop === 'function') disposers.push(stop as () => void)
    return previousEffect === undefined ? () => {} : () => {}
  }
  server.apply(ctx as never, server.Config({
    host: '127.0.0.1',
    port,
    audit: false,
    allowLegacyHandshake: true, // Direct DSHR2 fixture opts into legacy authentication explicitly.
    ...pin,
    journalFile: join(home, `journal-${port}.jsonl`),
    heartbeatFile: join(home, `heartbeat-${port}.json`),
    ...config,
  }) as never)
  const deadline = Date.now() + 5000
  for (;;) {
    const reachable = await new Promise<boolean>((resolve) => {
      const probe = connect(port, '127.0.0.1')
      probe.once('connect', () => { probe.destroy(); resolve(true) })
      probe.once('error', () => { probe.destroy(); resolve(false) })
    })
    if (reachable || Date.now() > deadline) break
    await wait(50)
  }
  return { port, stop: () => { for (const dispose of disposers) { try { dispose() } catch { /* gone */ } } } }
}

/** The peer's own public key, as generated by the server half just now. */
function serverPublicKey(): KeyObject {
  return createPublicKey(parsePrivateKey(readFileSync(join(home, 'dsh-remote', 'server.key'), 'utf8')))
}

/** One authenticated controller connection with id-routed replies. */
async function dial(port: number) {
  const socket: Socket = connect(port, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })
  const session = await clientHandshake(socket, controller.privateKey, serverPublicKey())
  let counter = 0
  const waiting = new Map<number, (reply: Record<string, unknown>) => void>()
  const pushed: Array<Record<string, unknown>> = []
  void (async () => {
    for (;;) {
      const frame = await session.recv()
      if (frame === null) break
      const id = typeof frame.id === 'number' ? frame.id : undefined
      if (id !== undefined) waiting.get(id)?.(frame)
      else pushed.push(frame)
    }
  })().catch(() => { socket.destroy() }) // Protocol shutdown is terminal; never leave a detached recv rejection.
  const request = (op: string, args: Record<string, unknown> = {}, timeoutMs = 20_000) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      counter += 1
      const id = counter
      const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`${op} timed out`)) }, timeoutMs)
      waiting.set(id, (reply) => { clearTimeout(timer); waiting.delete(id); resolve(reply) })
      void session.send({ id, op, ...args }).catch((error) => { clearTimeout(timer); waiting.delete(id); reject(error) })
    })
  const next = async (timeoutMs = 4000): Promise<Record<string, unknown> | undefined> => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const frame = pushed.shift()
      if (frame !== undefined) return frame
      await wait(25)
    }
    return undefined
  }
  return { request, next, close: () => { socket.destroy() } }
}

const fake = peerHarness()
const running = await startServer(fake)
const wire = await dial(running.port)
/** The client half's GLOBAL tools (its own remote_* set and the two new tools). */
const clientGlobalTools = new Map<string, Record<string, unknown>>()
/** The client half's live agent handlers, for firing agent lifecycle events. */
const clientHandlers = new Map<string, Array<(payload: Record<string, unknown>) => void>>()
const clientLogger = { info() {}, warn() {}, debug() {}, error() {} }

/** One fake agent whose `ctx.inject(['tools'])` yields an agent-scoped registry. */
function makeFakeAgent(id: string, visibleNames: string[] = []) {
  const tools = new Map<string, Record<string, unknown>>()
  const visible = new Set<string>(visibleNames)
  const agentCtx: Record<string, unknown> = {
    logger: clientLogger,
    effect(fn: () => unknown) { const stop = fn(); return typeof stop === 'function' ? stop : () => {} },
    on() { return () => {} },
    plugin() { return () => {} },
    inject(deps: string[], run: (child: unknown) => void) {
      const owned = new Set<string>()
      const child: Record<string, unknown> = { ...agentCtx }
      if (deps.includes('tools')) {
        child.tools = {
          schemas() {
            return [
              ...[...visible].map(name => ({ name, description: '', parameters: {} })),
              ...[...tools.keys()].map(name => ({ name, description: '', parameters: {} })),
            ]
          },
          register(definition: { name: string }) {
            if (visible.has(definition.name) || tools.has(definition.name)) {
              throw new Error(`tool "${definition.name}" is already registered in this scope`)
            }
            tools.set(definition.name, definition as unknown as Record<string, unknown>)
            owned.add(definition.name)
            return () => { tools.delete(definition.name); owned.delete(definition.name) }
          },
          get(name: string) { return tools.get(name) },
        }
      }
      run(child)
      return {
        dispose() {
          for (const name of owned) tools.delete(name)
          owned.clear()
        },
      }
    },
  }
  return { agent: { id, ctx: agentCtx }, tools, visible }
}

const mainFake = makeFakeAgent('local-agent-1', ['taken', 'load_workspace_dependencies'])
const secondFake = makeFakeAgent('local-agent-2', [])

console.log('\n== 3. caps.list: the peer describes its kernel ==')
{
  const listed = await wire.request('caps.list')
  check('the catalog answers', listed.ok === true && listed.available === true, JSON.stringify(listed).slice(0, 200))
  check('it names the preset it describes', listed.presetId === 'standard', String(listed.presetId))
  const tools = (listed.tools ?? []) as Array<Record<string, unknown>>
  const byName = new Map(tools.map(tool => [String(tool.name), tool]))
  check('callable tools are listed with their schema',
    byName.get('read')?.callable === true
    && JSON.stringify(byName.get('read')?.parameters).includes('"path"'),
    JSON.stringify(byName.get('read')))
  check('a bridge tool is listed but not callable',
    byName.get('remote_exec')?.callable === false && String(byName.get('remote_exec')?.reason).length > 0,
    JSON.stringify(byName.get('remote_exec')))
  check('an interactive tool is refused by default config',
    byName.get('ask_user_question')?.callable === false, JSON.stringify(byName.get('ask_user_question')))
  check('a host-level tool keeps its origin',
    byName.get('taken')?.origin === 'global', JSON.stringify(byName.get('taken')))
  check('the plugin inventory comes along',
    JSON.stringify(listed.plugins).includes('@deepseek-ai/dsh-tool-fs'), JSON.stringify(listed.plugins).slice(0, 200))
  check('the live session is listed as information',
    JSON.stringify(listed.sessions).includes('peer-session'), JSON.stringify(listed.sessions))
  check('the subagent provider is listed', JSON.stringify(listed.subagentProviders).includes('spawn'))
  const info = await wire.request('sysinfo')
  const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
  check('sysinfo advertises the capability ops',
    ['caps.list', 'caps.call', 'caps.cancel'].every(op => ops.includes(op)), ops.filter(op => op.startsWith('caps.')).join(','))
}

console.log('\n== 4. caps.call: the body runs there, with no agent ==')
{
  const called = await wire.request('caps.call', {
    callId: 'call-read-1', name: 'read', arguments: { path: 'a.txt' },
  })
  check('the call answers ok', called.ok === true, JSON.stringify(called).slice(0, 200))
  check('the rendered content comes back',
    JSON.stringify(called.content).includes('read content-of-a.txt'), JSON.stringify(called.content))
  check('the canonical value comes back', called.value === 'content-of-a.txt', JSON.stringify(called.value))
  const seen = executions.find(row => row.name === 'read')
  check('the body ran with NO agent (no conversation was opened)', seen !== undefined && seen.agent === undefined,
    JSON.stringify(seen?.agent))
  check('and with the arguments the controller sent', JSON.stringify(seen?.args) === JSON.stringify({ path: 'a.txt' }), JSON.stringify(seen?.args))

  const missing = await wire.request('caps.call', { name: 'nope', arguments: {} })
  check('an unknown tool is refused, not silently executed',
    missing.ok === false && String(missing.error).includes('no tool named'), JSON.stringify(missing))
  const refused = await wire.request('caps.call', { name: 'remote_exec', arguments: {} })
  check('a bridge tool cannot be called even by name',
    refused.ok === false && String(refused.error).includes('bridge tool'), JSON.stringify(refused))
  const throwing = await wire.request('caps.call', { name: 'bad', arguments: {} })
  check('a throwing body surfaces as a failed call',
    throwing.ok === false && String(throwing.error).includes('remote tool exploded'), JSON.stringify(throwing))
}

console.log('\n== 5. caps.cancel and the peer-side timeout ==')
{
  const parked = wire.request('caps.call', { callId: 'call-long-1', name: 'long', arguments: {} })
  await wait(150)
  const cancel = await wire.request('caps.cancel', { callId: 'call-long-1' })
  check('the cancel finds the running call', cancel.ok === true && cancel.cancelled === true, JSON.stringify(cancel))
  const settled = await parked
  check('the waiting controller call settles as cancelled',
    settled.ok === false && String(settled.error).toLowerCase().includes('cancel'), JSON.stringify(settled))
  const again = await wire.request('caps.cancel', { callId: 'call-long-1' })
  check('cancelling a finished call is a clean miss', again.ok === true && again.cancelled === false, JSON.stringify(again))

  const slow = await startServer(fake, { maxToolCallTimeoutMs: 1000 })
  const slowWire = await dial(slow.port)
  const startedAt = Date.now()
  const timedOut = await slowWire.request('caps.call', { name: 'long', arguments: {}, timeoutMs: 1000 }, 15_000)
  const elapsed = Date.now() - startedAt
  check('a tool that never returns is capped by the peer',
    timedOut.ok === false && String(timedOut.error).includes('timed out'), JSON.stringify(timedOut))
  check('and the cap is bounded by the configured ceiling', elapsed < 8000, `${elapsed} ms`)
  slowWire.close()
  slow.stop()
}

console.log('\n== 6. the permission fence still applies ==')
{
  const fenced = await startServer(fake, { maxPermission: 1 })
  const fencedWire = await dial(fenced.port)
  const listed = await fencedWire.request('caps.list')
  check('reading the catalog needs only read permission', listed.ok === true && listed.available === true, JSON.stringify(listed).slice(0, 160))
  const refused = await fencedWire.request('caps.call', { name: 'read', arguments: { path: 'x' } })
  check('calling a tool needs full trust and is refused below it',
    refused.ok === false && String(refused.error).includes('permission level'), JSON.stringify(refused))
  fencedWire.close()
  fenced.stop()

  const off = await startServer(fake, { capabilities: false })
  const offWire = await dial(off.port)
  const hidden = await offWire.request('caps.list')
  check('capabilities:false hides the catalog', hidden.ok === true && hidden.available === false, JSON.stringify(hidden))
  const refusedCall = await offWire.request('caps.call', { name: 'read', arguments: {} })
  check('and refuses direct calls', refusedCall.ok === false && String(refusedCall.error).includes('disabled'), JSON.stringify(refusedCall))
  offWire.close()
  off.stop()
}

console.log('\n== 7. the peer pushes caps.changed when its tools change ==')
{
  fake.fire('tools/change')
  const frame = await wire.next(5000)
  check('a caps.changed frame arrives', frame?.kind === 'caps.changed', JSON.stringify(frame))
}

console.log('\n== 8. the client half mirrors the peer INTO AGENT SCOPES and calls it end to end ==')
{
  const client = await import('../src/client.ts')
  const clientCtx: Record<string, unknown> = {
    logger: clientLogger,
    effect(fn: () => unknown) { const stop = fn(); return typeof stop === 'function' ? stop : () => {} },
    on(name: string, handler: (payload: Record<string, unknown>) => void) {
      const list = clientHandlers.get(name) ?? []
      list.push(handler)
      clientHandlers.set(name, list)
      return () => {}
    },
    get(name: string) {
      // The live Agent registry; every agent-scoped mirror is installed through it.
      return name === 'agents' ? { list: () => [mainFake.agent, secondFake.agent] } : undefined
    },
    plugin() { return () => {} },
  }
  clientCtx.inject = (deps: string[], run: (child: unknown) => void) => {
    const child: Record<string, unknown> = { ...clientCtx }
    if (deps.includes('tools')) {
      child.tools = {
        register(definition: { name: string }) {
          if (clientGlobalTools.has(definition.name)) throw new Error(`tool "${definition.name}" is already registered`)
          clientGlobalTools.set(definition.name, definition as unknown as Record<string, unknown>)
          return () => { clientGlobalTools.delete(definition.name) }
        },
        get(name: string) { return clientGlobalTools.get(name) },
      }
    }
    if (deps.includes('systemPrompt')) {
      child.systemPrompt = { section: () => () => {} }
    }
    run(child)
    return () => {}
  }

  client.apply(clientCtx as never, client.Config({
    host: '127.0.0.1',
    port: running.port,
    privateKey: privateToPem(controller.privateKey),
    peerPublicKey: publicToPem(serverPublicKey()),
  }) as never)

  // `load_workspace_dependencies` is the exact name that broke a real boot when a
  // mirror took the GLOBAL layer first: the official host plugin then could not
  // register. Here it is a tool the fake agent already sees, so it must be skipped
  // and the agent-scoped registry must never fight over global names at all.
  const mirrored = await until(() => mainFake.tools.has('read'))
  check('a peer tool is registered in an AGENT scope under its own name',
    mirrored, [...mainFake.tools.keys()].join(','))
  check('nothing is mirrored in the GLOBAL layer',
    !clientGlobalTools.has('read') && !clientGlobalTools.has('load_workspace_dependencies'),
    [...clientGlobalTools.keys()].slice(0, 8).join(','))
  check('a name the agent already sees is skipped (local wins, no collision)',
    mainFake.visible.has('load_workspace_dependencies') && !mainFake.tools.has('load_workspace_dependencies'))
  check('a refused bridge tool is not mirrored', !mainFake.tools.has('remote_exec'))
  check('an interactive tool is not mirrored', !mainFake.tools.has('ask_user_question'))
  check('the catalog and by-name caller are global tools',
    clientGlobalTools.has('remote_capabilities') && clientGlobalTools.has('remote_tool_call'))

  const readMirror = mainFake.tools.get('read') as unknown as {
    execute(args: unknown, exec: unknown): Promise<{ content: Array<{ type: string, text: string }> }>
  }
  const outcome = await readMirror.execute({ path: 'mirrored.txt' }, {})
  check('calling the mirror runs the PEER body and returns its content',
    JSON.stringify(outcome.content).includes('read content-of-mirrored.txt'), JSON.stringify(outcome).slice(0, 200))
  const seen = executions.filter(row => row.name === 'read').at(-1)
  check('still with no agent on the peer side', seen?.agent === undefined, JSON.stringify(seen?.agent))

  const capabilitiesTool = clientGlobalTools.get('remote_capabilities') as unknown as {
    execute(args: unknown, exec: unknown): Promise<{ text: string }>
  }
  const listing = await capabilitiesTool.execute({}, { agent: mainFake.agent })
  check('remote_capabilities renders the catalog', listing.text.includes('standard') && listing.text.includes('- read'), listing.text.slice(0, 200))
  check('and marks the locally-shadowed peer tool',
    listing.text.includes('load_workspace_dependencies') && listing.text.includes('[本机同名工具优先，已隐藏]'),
    listing.text.split('\n').find(line => line.includes('load_workspace_dependencies')) ?? '')

  const byName = clientGlobalTools.get('remote_tool_call') as unknown as {
    execute(args: unknown, exec: unknown): Promise<{ text: string }>
  }
  const direct = await byName.execute({ name: 'read', arguments: { path: 'by-name.txt' } }, {})
  check('remote_tool_call reaches a tool by name', direct.text.includes('read content-of-by-name.txt'), direct.text.slice(0, 160))

  // A second agent created later must get its own mirrors (and only its own gaps).
  clientHandlers.get('agent/created')?.forEach(handler => handler({ agent: secondFake.agent }))
  const secondMirrored = await until(() => secondFake.tools.size > 0)
  check('an agent created later gets its own agent-scoped mirrors',
    secondMirrored && secondFake.tools.has('read'), [...secondFake.tools.keys()].slice(0, 8).join(','))
}

console.log('\n== 9. a push re-syncs the mirrors after the peer gains a tool ==')
{
  fake.allTools.set('added_later', {
    name: 'added_later',
    description: 'Appears after the first catalog.',
    parameters: { type: 'object', properties: {} },
    output: { schema: {}, render: () => [] },
    async execute() { return 'late' },
  })
  fake.fire('tools/change')
  const mirroredLate = await until(() => mainFake.tools.has('added_later') && secondFake.tools.has('added_later'), 6000)
  check('the new tool appears in every live agent scope without a restart', mirroredLate,
    [...mainFake.tools.keys()].slice(0, 10).join(','))
}

wire.close()
running.stop()
rmSync(home, { recursive: true, force: true })
console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
// Hard exit: the client half's authenticated socket and its retry timer are
// still live (by design), and this script outlives its assertions.
process.exit(failures === 0 ? 0 : 1)
