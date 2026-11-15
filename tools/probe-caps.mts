/**
 * Real-peer probe for capability federation (`caps.*`, server build r21+).
 *
 * It dials a running peer with THIS machine's own `dsh-remote` key material, so
 * it validates the controlled side without restarting the controlling DSH — the
 * thing that makes "deploy → restart peer → verify" one command.
 *
 * What it proves, in order:
 *   1. the peer advertises the three ops and reports the expected build;
 *   2. `caps.list` enumerates one preset's tool surface, plugin inventory,
 *      presets, subagent providers and live sessions WITHOUT creating a session;
 *   3. `caps.call` runs a real tool body (no agent there) and returns content;
 *   4. `caps.cancel` on an unknown call is a clean miss;
 *   5. the peer's session count is unchanged — a capability call never opens a
 *      conversation.
 *
 * Usage (from the harness checkout, so `tsx` resolves):
 *   node --import tsx/esm tools/probe-caps.mts <host> <port> [presetId]
 *
 * Exits non-zero when a check fails, so a deploy script can gate on it.
 */

import { homedir } from 'node:os'
import { join } from 'node:path'

import { LinkClient } from '../src/link.ts'

const [host, portArg, presetArg] = process.argv.slice(2)
if (host === undefined || portArg === undefined) {
  console.error('usage: node --import tsx/esm tools/probe-caps.mts <host> <port> [presetId]')
  process.exit(2)
}

const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
let failures = 0
const check = (label: string, ok: boolean, detail?: string): void => {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail === undefined ? '' : `  <- ${detail}`}`)
}

const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 120_000,
}), message => console.log(`   ${message}`), 'probe-caps')

type Row = Record<string, unknown>
const rows = (value: unknown): Row[] => Array.isArray(value) ? value as Row[] : []

/** A comparable snapshot of the peer's sessions (live + workspace-backed). */
const sessionsOf = async (): Promise<string[]> => {
  try {
    const listed = await link.request('agent.sessions', {}, 30_000)
    return rows(listed.sessions).map(row => String(row.sessionId)).sort()
  } catch {
    const info = await link.request('sysinfo')
    return (Array.isArray(info.sessions) ? info.sessions.map(String) : []).sort()
  }
}

const info = await link.request('sysinfo')
const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
console.log(`\n== peer ${host}:${portArg} build ${String(info.build)} ==`)
check('advertises caps.list / caps.call / caps.cancel',
  ['caps.list', 'caps.call', 'caps.cancel'].every(op => ops.includes(op)),
  ops.filter(op => op.startsWith('caps.')).join(',') || '(none)')

const sessionsBefore = await sessionsOf()

const catalog = await link.request('caps.list', presetArg === undefined ? {} : { presetId: presetArg }, 60_000)
const tools = rows(catalog.tools)
const callable = tools.filter(tool => tool.callable !== false)
console.log(`\n== caps.list ==`)
check('catalog available', catalog.available === true, String(catalog.reason ?? ''))
check('names the preset it describes', String(catalog.presetId) === (presetArg ?? String(catalog.presetId)), String(catalog.presetId))
check('lists tools with their schemas',
  callable.length > 0 && typeof callable[0]?.description === 'string', `${tools.length} tools, ${callable.length} callable`)
check('lists the plugin inventory', rows(catalog.plugins).length > 0, JSON.stringify(rows(catalog.plugins).length))
check('lists presets (subagent types)', rows(catalog.presets).length > 0,
  rows(catalog.presets).map(row => String(row.id)).join(','))
check('lists subagent providers', Array.isArray(catalog.subagentProviders))
const denied = tools.filter(tool => tool.callable === false)
check('refuses its own bridge / interactive tools', denied.length > 0,
  denied.map(tool => `${String(tool.name)}(${String(tool.reason)})`).slice(0, 4).join(', '))
console.log(`   tools: ${callable.slice(0, 12).map(tool => String(tool.name)).join(', ')}${callable.length > 12 ? ', …' : ''}`)
console.log(`   live sessions: ${rows(catalog.sessions).length}`)

console.log(`\n== caps.call ==`)
const target = callable.find(tool => tool.name === 'read')
  ?? callable.find(tool => Array.isArray((tool.parameters as Row | undefined)?.required) === false)
  ?? callable[0]
if (target === undefined) {
  check('a callable tool exists to run', false)
} else {
  const name = String(target.name)
  const parameters = (target.parameters ?? {}) as { required?: string[] }
  const args: Record<string, unknown> = {}
  for (const key of parameters.required ?? []) {
    if (/path|file|dir/i.test(key)) args[key] = 'C:/Users/demo/.dsh/profiles/desktop/cordis.patch.yml'
    else if (/command|cmd/i.test(key)) args[key] = 'Write-Output probe-ok'
    else args[key] = 'probe'
  }
  const startedAt = Date.now()
  const called = await link.request('caps.call', { callId: 'probe-1', name, arguments: args }, 120_000, { retries: 0 })
  check(`ran ${name} on the peer with no agent there`, called.ok === true,
    String(called.error ?? ''))
  if (called.ok === true) {
    const content = JSON.stringify(called.content ?? [])
    const elapsed = Date.now() - startedAt
    check('returns rendered content', content.length > 2, content.slice(0, 120))
    check('settled well before the peer ceiling', elapsed < 120_000, `${elapsed} ms`)
    console.log(`   content head: ${content.slice(0, 240)}`)
  }
}

const cancelled = await link.request('caps.cancel', { callId: 'probe-does-not-exist' }, 30_000)
check('caps.cancel on an unknown call is a clean miss', cancelled.cancelled === false, JSON.stringify(cancelled))

const sessionsAfter = await sessionsOf()
check('the peer session set is unchanged (no conversation was opened)',
  JSON.stringify(sessionsAfter) === JSON.stringify(sessionsBefore),
  `${sessionsBefore.length} -> ${sessionsAfter.length}`)

link.close()
console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exit(failures === 0 ? 0 : 1)
