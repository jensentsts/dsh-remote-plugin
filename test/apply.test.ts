/**
 * Integration test for `apply()` - the half of the plugin no earlier test could
 * reach, because it needs a cordis context.
 *
 * The context is faked, but the things under test are real: the actual `Config`
 * schema, the actual `apply`, the actual tool definitions, the actual system
 * section text, the REAL lazy import of the subagent kit, and the actual
 * `loader/volatile-update` hot path (driven through `updateVolatile`, the same
 * entry the settings layer uses). A fake context is enough precisely because the
 * plugin talks to cordis through five calls: effect, inject, on, plugin, logger.
 *
 * `DSH_HOME` is redirected to a temp dir BEFORE the module is imported, so the
 * generated key and the session-memory file land there and never touch the
 * user's real mapping.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/apply.test.ts
 */

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createVolatile, updateVolatile } from '@deepseek-ai/cosmokit'

const home = mkdtempSync(join(tmpdir(), 'dshr-apply-'))
process.env.DSH_HOME = home

const plugin = await import('../src/client.ts')
const { anchorSessionId } = await import('../src/reuse.ts')

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

/** Let the lazy subagent-kit import settle. */
const settle = (): Promise<void> => new Promise(resolve => { setTimeout(resolve, 150) })

interface Harness {
  ctx: Record<string, unknown>
  tools: Array<{ name: string }>
  sections: Array<{ name: string, text: unknown }>
  providers: Array<{ name: string, inheritsParentContext?: boolean, capabilities?: unknown }>
  disposed: { tools: string[], providers: string[] }
  fire(event: string): void
}

/** A context exposing exactly what this plugin calls. */
function makeCtx(services: { tools?: boolean, systemPrompt?: boolean, subagents?: boolean } = {}): Harness {
  const wanted = { tools: true, systemPrompt: true, subagents: true, ...services }
  const harness: Partial<Harness> = {
    tools: [], sections: [], providers: [], disposed: { tools: [], providers: [] },
  }
  const handlers = new Map<string, Array<() => void>>()
  const ctx: Record<string, unknown> = {
    logger: { info() {}, warn() {}, debug() {}, error() {} },
    effect(fn: () => unknown) { const stop = fn(); return typeof stop === 'function' ? stop : () => {} },
    on(name: string, handler: () => void) {
      const list = handlers.get(name) ?? []
      list.push(handler)
      handlers.set(name, list)
      return () => {}
    },
    plugin() { return () => {} },
    get() { return undefined }, // Real Context exposes optional registry lookup.
  }
  ctx.inject = (deps: string[], run: (child: unknown) => void) => {
    const child: Record<string, unknown> = { ...ctx }
    for (const dep of deps) {
      if (dep === 'tools' && wanted.tools) {
        child.tools = {
          register: (tool: { name: string }) => {
            harness.tools?.push(tool)
            return () => { harness.disposed?.tools.push(tool.name) }
          },
          get: () => undefined,
        }
      }
      if (dep === 'systemPrompt' && wanted.systemPrompt) {
        child.systemPrompt = {
          section: (section: { name: string, text: unknown }) => {
            harness.sections?.push(section)
            return () => {}
          },
        }
      }
      if (dep === 'subagents' && wanted.subagents) {
        child.subagents = {
          registerProvider: (provider: { name: string }) => {
            harness.providers?.push(provider)
            return () => { harness.disposed?.providers.push(provider.name) }
          },
        }
      }
    }
    run(child)
    return () => {}
  }
  harness.ctx = ctx
  harness.fire = (event: string) => { for (const handler of handlers.get(event) ?? []) handler() }
  return harness as Harness
}

const config = (overrides: Record<string, unknown> = {}) => plugin.Config({
  host: 'peer.example',
  port: 50000,
  ...overrides,
})

console.log('\n== 1. defaults: tools, guidance, journal reader and the remote subagent ==')
{
  const h = makeCtx()
  plugin.apply(h.ctx as never, config())
  await settle()
  const names = h.tools.map(tool => tool.name).sort()
  check('the remote_* tools are registered', names.includes('remote_agent_prompt') && names.includes('remote_exec'), names.join(','))
  check('the remote_* set plus the journal reader and the delegation tool', h.tools.length === 25, String(h.tools.length))
  check('the shell/journal readers are present', names.includes('remote_journal') && names.includes('remote_agent_events'), names.join(','))
  check('the delegation tool is present by default', names.includes('subagent_remote'), names.join(','))
  check('the capability catalog and by-name caller are present',
    names.includes('remote_capabilities') && names.includes('remote_tool_call'), names.join(','))
  check('exactly one prompt section', h.sections.length === 1, String(h.sections.length))
  check('the section is the controller guidance', h.sections[0]?.name === 'dsh-remote:controller', String(h.sections[0]?.name))
  check('the provider is registered and named remote', h.providers.length === 1 && h.providers[0]?.name === 'remote', JSON.stringify(h.providers.map(p => p.name)))
  check('the provider is a remote run (no parent context)', h.providers[0]?.inheritsParentContext === false)
  check('and advertises no start capabilities',
    JSON.stringify(h.providers[0]?.capabilities) === JSON.stringify({ agentOptions: false, outputSchema: false, depthLimit: false, toolFilter: false, persona: false }),
    JSON.stringify(h.providers[0]?.capabilities))
}

console.log('\n== 2. the guidance is computed per chat ==')
{
  const h = makeCtx()
  plugin.apply(h.ctx as never, config())
  const text = h.sections[0]?.text as (context: unknown) => string
  const own = anchorSessionId('remote', 'session-chat-42')
  const rendered = text({ agent: { session: { id: 'session-chat-42' } } })
  check('names this chat\'s remote conversation', rendered.includes(own), rendered.slice(0, 200))
  check('states the one-chat-one-conversation rule', rendered.includes('一个 chat 只对应一个远端对话'))
  check('states local-first', rendered.includes('本机优先'))
  check('points at the delegation tool while it exists', rendered.includes('subagent_remote'))
  check('points at the cheap journal read', rendered.includes('remote_journal'))
  check('points at the direct capability path', rendered.includes('remote_capabilities'))
  check('demands stopping on a remote interrupt', rendered.includes('打断高于一切'))
  check('degrades without an agent in the context', text({}).includes('按本机会话推导'), text({}).slice(0, 160))

  const disabled = makeCtx()
  plugin.apply(disabled.ctx as never, config({ host: '', port: 0 }))
  check('stays silent until an endpoint is configured', (disabled.sections[0]?.text as (c: unknown) => string)({}) === '')
}

console.log('\n== 3. the switches are honoured ==')
{
  const noTools = makeCtx()
  plugin.apply(noTools.ctx as never, config({ toolEnabled: false }))
  await settle()
  check('toolEnabled: false registers no tools', noTools.tools.length === 0, String(noTools.tools.length))
  check('and still offers the provider (the switch is independent)', noTools.providers.length === 1, String(noTools.providers.length))

  const noGuidance = makeCtx()
  plugin.apply(noGuidance.ctx as never, config({ promptGuidance: false }))
  await settle()
  check('promptGuidance: false contributes no section', noGuidance.sections.length === 0, String(noGuidance.sections.length))

  const noSubagent = makeCtx()
  plugin.apply(noSubagent.ctx as never, config({ subagentProvider: false }))
  await settle()
  check('subagentProvider: false registers no provider', noSubagent.providers.length === 0, String(noSubagent.providers.length))
  check('and no delegation tool', !noSubagent.tools.some(tool => tool.name === 'subagent_remote'), noSubagent.tools.map(t => t.name).join(','))
  check('the other tools are unaffected', noSubagent.tools.length === 24, String(noSubagent.tools.length))
}

console.log('\n== 4. a composition without the subagent service still loads ==')
{
  const h = makeCtx({ subagents: false })
  plugin.apply(h.ctx as never, config())
  await settle()
  check('no provider, but the plugin applied', h.providers.length === 0 && h.tools.length === 24, `${h.providers.length}/${h.tools.length}`)
}

console.log('\n== 5. the hot switch: a settings edit registers and withdraws it ==')
{
  const h = makeCtx()
  const cfg = config({ subagentProvider: false })
  plugin.apply(h.ctx as never, cfg)
  await settle()
  check('starts withdrawn', h.providers.length === 0 && h.tools.length === 24, `${h.providers.length}/${h.tools.length}`)

  updateVolatile(cfg.subagentProvider as never, createVolatile(true) as never)
  h.fire('loader/volatile-update')
  await settle()
  check('turning it on registers the provider live', h.providers.length === 1, String(h.providers.length))
  check('and the tool with it', h.tools.length === 25 && h.tools.some(t => t.name === 'subagent_remote'), String(h.tools.length))

  updateVolatile(cfg.subagentProvider as never, createVolatile(false) as never)
  h.fire('loader/volatile-update')
  await settle()
  check('turning it off withdraws the provider', h.disposed.providers.includes('remote'), JSON.stringify(h.disposed.providers))
  check('and withdraws the tool', h.disposed.tools.includes('subagent_remote'), JSON.stringify(h.disposed.tools))

  updateVolatile(cfg.subagentProvider as never, createVolatile(true) as never)
  h.fire('loader/volatile-update')
  await settle()
  check('and it can be turned back on', h.providers.length === 2, String(h.providers.length))

  // A volatile update that changes something else must not disturb it.
  updateVolatile(cfg.reuseSessions as never, createVolatile(false) as never)
  h.fire('loader/volatile-update')
  await settle()
  check('an unrelated edit leaves one live registration', h.providers.length === 2 && h.disposed.providers.length === 1,
    `${h.providers.length}/${h.disposed.providers.length}`)
}

rmSync(home, { recursive: true, force: true })
console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
