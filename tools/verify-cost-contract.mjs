/**
 * Contract check for the `external_usage.json` snapshot dsh-remote produces.
 *
 * This runs the INSTALLED dsh-cost-meter's own parser over a snapshot shaped by
 * our writer rules, so a change in our record shape fails here instead of
 * silently disappearing from the cost panel.
 *
 * cost-meter is an npm package resolved from the DSH profile, and its own
 * imports (`@deepseek-ai/dsh-credentials`, ...) only resolve inside a DSH
 * process. This script therefore copies the package into a temp dir next to
 * junctions for those peer packages, imports the parser from there, and throws
 * the temp dir away. Nothing in the real profile is touched.
 *
 * When cost-meter or the harness checkout is absent the check SKIPS (exit 0):
 * this plugin must stay installable on a machine without the meter.
 *
 * Usage:
 *   node E:/path/to/dsh-remote/tools/verify-cost-contract.mjs
 *   node E:/path/to/dsh-remote/tools/verify-cost-contract.mjs E:/tmp/external_usage.json
 *
 * With a path argument the check validates THAT snapshot (e.g. one written by a
 * real remote turn) instead of the built-in samples.
 */

import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, realpathSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const meterDir = process.env.DSH_COST_METER_DIR
  ?? (process.env.DSH_PROFILE_DIR === undefined
    ? undefined
    : join(process.env.DSH_PROFILE_DIR, 'node_modules', 'dsh-cost-meter'))
const harnessDir = process.env.DSH_HARNESS_DIR ?? '../../dsh'
const peerDir = join(harnessDir, 'node_modules', '.pnpm', 'node_modules', '@deepseek-ai')

const skip = reason => {
  console.log(`skip: ${reason}`)
  process.exit(0)
}
if (meterDir === undefined || !existsSync(join(meterDir, 'lib', 'external-usage.js'))) {
  skip('dsh-cost-meter is not installed at ' + (meterDir ?? '(no DSH_PROFILE_DIR)'))
}
if (!existsSync(peerDir)) skip(`harness peer packages not found at ${peerDir}`)

// Assemble a throwaway node_modules where both the meter and its peers resolve.
// The peer packages are own junctions to their REAL directories: the pnpm store
// entries are relative symlinks, and a relative symlink reached through a
// junction on another drive does not resolve (Windows resolves it against the
// path that was traversed).
const root = mkdtempSync(join(tmpdir(), 'dshr-cost-contract-'))
const nm = join(root, 'node_modules')
const meterCopy = join(nm, 'dsh-cost-meter')
const peerCopy = join(nm, '@deepseek-ai')
mkdirSync(peerCopy, { recursive: true })
mkdirSync(meterCopy, { recursive: true })
// Only the pieces the parser needs: the meter's own package.json and lib/.
for (const piece of ['package.json', 'lib']) cpSync(join(meterDir, piece), join(meterCopy, piece), { recursive: true })
for (const entry of readdirSync(peerDir)) {
  const source = join(peerDir, entry)
  try { symlinkSync(realpathSync(source), join(peerCopy, entry), 'junction') } catch { /* unreadable store entry */ }
}
for (const dependency of ['zod', 'acorn']) {
  const from = join(process.env.DSH_PROFILE_DIR ?? '', 'node_modules', dependency)
  if (existsSync(from)) symlinkSync(realpathSync(from), join(nm, dependency), 'junction')
}

let failures = 0
const check = (label, ok, detail) => {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

/** Validate a snapshot file produced elsewhere (one real remote turn). */
const externalPath = process.argv[2]
if (externalPath !== undefined) {
  try {
    const { defaultConfig } = await import(pathToFileURL(join(meterCopy, 'lib', 'store.js')).href)
    const { parseExternalUsageSnapshot } = await import(pathToFileURL(join(meterCopy, 'lib', 'external-usage.js')).href)
    const { readFileSync } = await import('node:fs')
    const value = JSON.parse(readFileSync(externalPath, 'utf8'))
    const now = Date.now()
    const parsed = parseExternalUsageSnapshot(value, defaultConfig(), now)
    check(`snapshot ${externalPath} parses`, parsed !== null)
    if (parsed !== null) {
      for (const source of parsed.sources) {
        console.log(`source ${source.source}: calls=${source.today.calls} cost=${source.today.cost}`)
      }
      console.log('combined today:', parsed.combined.today.cost, 'month:', parsed.combined.month.cost, 'total:', parsed.combined.total.cost)
      const rows = (value.sources ?? []).flatMap(source => Array.isArray(source.records) ? source.records : [])
      check('the snapshot carries real call records', rows.length > 0, String(rows.length))
    }
    console.log(failures === 0 ? '\nexternal_usage snapshot satisfies the cost-meter contract: OK' : `\n${failures} check(s) FAILED`)
    process.exitCode = failures === 0 ? 0 : 1
  } finally {
    if (process.exitCode !== 0) console.log('kept temp dir for inspection:', root)
    else rmSync(root, { recursive: true, force: true })
  }
  process.exit()
}

try {
  const { defaultConfig } = await import(pathToFileURL(join(meterCopy, 'lib', 'store.js')).href)
  const { parseExternalUsageSnapshot } = await import(pathToFileURL(join(meterCopy, 'lib', 'external-usage.js')).href)

  const config = defaultConfig()
  const now = Date.now()
  const at = offsetMinutes => new Date(now - offsetMinutes * 60_000).toISOString()

  /** One snapshot shaped exactly the way the client half writes it. */
  const snapshot = {
    fetchedAt: at(0),
    sources: [
      {
        source: 'remote/default',
        records: [
          // Every field this writer emits: id/at/provider/model + three required
          // token buckets, and the two optional buckets only when non-zero.
          { id: 'remote-abc:12', at: at(30), provider: 'deepseek-official', model: 'deepseek-flash', input: 18171, output: 231, cached: 0 },
          { id: 'remote-abc:24', at: at(20), provider: 'deepseek-official', model: 'deepseek-flash', input: 533, output: 284, cached: 18304, cacheWrite: 10, reasoning: 3 },
        ],
      },
      // A foreign producer's source must survive our rewrite untouched.
      {
        source: 'Hindsight',
        days: {
          [new Date(now - 86_400_000).toISOString().slice(0, 10)]: { input: 10, output: 5, cached: 0, calls: 1, costUsd: 0.5 },
        },
      },
    ],
  }

  const parsed = parseExternalUsageSnapshot(snapshot, config, now)
  check('snapshot parses with cost-meter records mode', parsed !== null)
  if (parsed !== null) {
    const ours = parsed.sources.find(row => row.source === 'remote/default')
    const today = ours?.today
    check('our source is present', ours !== undefined)
    check('our records were priced (today.cost > 0)', (today?.cost ?? 0) > 0, JSON.stringify(today))
    check('token buckets add up', today?.input === 18171 + 533 && today?.output === 231 + 284 && today?.cacheRead === 18304, JSON.stringify(today))
    check('call count is two', today?.calls === 2, String(today?.calls))
    check('foreign source is preserved', parsed.sources.some(row => row.source === 'Hindsight'))
    check('combined cost covers every source', (parsed.combined?.today?.cost ?? 0) >= (today?.cost ?? 0))
    console.log('combined today:', parsed.combined?.today?.cost, ' ours:', today?.cost)
  }

  // An unpriced provider/model invalidates the WHOLE snapshot (cost-meter is
  // fail-closed), which is why the writer filters local providers out.
  const unpriced = structuredClone(snapshot)
  unpriced.sources[0].records[0].provider = 'ollama'
  check('an unpriced provider is rejected as a whole (documented hazard)', parseExternalUsageSnapshot(unpriced, config, now) === null)

  // A stale snapshot is marked stale but still parsed.
  const stale = structuredClone(snapshot)
  stale.fetchedAt = at(25 * 60)
  const staleParsed = parseExternalUsageSnapshot(stale, config, now)
  check('stale snapshot still parses and is flagged', staleParsed !== null && staleParsed.stale === true)

  // The record cap we enforce leaves room under the file-size ceiling.
  const many = structuredClone(snapshot)
  many.sources[0].records = Array.from({ length: 2000 }, (_, i) => ({
    id: `remote-abc:${i + 1}`, at: at(i % 60), provider: 'deepseek-official', model: 'deepseek-flash', input: 1000, output: 100, cached: 0,
  }))
  const bytes = Buffer.byteLength(JSON.stringify(many))
  check('2000 records stay under the 512 KiB file cap', bytes < 512 * 1024, String(bytes))
  check('2000 records parse', parseExternalUsageSnapshot(many, config, now) !== null)

  console.log(failures === 0 ? '\ncost-meter external-usage contract: OK' : `\n${failures} contract check(s) FAILED`)
  process.exitCode = failures === 0 ? 0 : 1
} finally {
  if (process.exitCode !== 0) console.log('kept temp dir for inspection:', root)
  else rmSync(root, { recursive: true, force: true })
}
