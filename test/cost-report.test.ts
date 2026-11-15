/**
 * Unit tests for `src/cost-report.ts` — the remote-usage store and the
 * cost-meter `external_usage.json` snapshot writer.
 *
 * Everything here is offline: no link, no peer, no DSH context. The last case is
 * an OPTIONAL contract regression against the real `dsh-cost-meter` parser when
 * that plugin is installed; it prints `skip` instead of failing when the parser
 * cannot be imported outside the harness (its bare imports resolve only inside
 * a running DSH profile).
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/cost-report.test.ts
 */

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  MAX_SNAPSHOT_BYTES,
  MAX_SNAPSHOT_RECORDS,
  MAX_STORE_RECORDS,
  RemoteCostStore,
  composeSnapshot,
  sanitizeSample,
  type RemoteUsageRecord,
} from '../src/cost-report.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

/** ISO-8601 shape cost-meter accepts (`.sssZ` or an explicit offset). */
const COST_METER_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/

const NOW = Date.now()
/** Base timestamp old enough that index 0..2100 always lands in the past. */
const BASE_AT = NOW - 3_000_000

const dirs: string[] = []
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dshr-cost-'))
  dirs.push(dir)
  return dir
}

/** One valid `usage.read` sample, in the documented (nested `usage`) shape. */
function rawSample(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    seq: 1210,
    at: NOW - 60_000,
    provider: 'deepseek-official',
    model: 'deepseek-flash',
    turn: 1,
    step: 3,
    kind: 'call',
    usage: { input: 889, output: 92, cacheRead: 19072, cacheWrite: 0, reasoning: 0 },
    ...overrides,
  }
}

/** One valid persisted record. */
function makeRecord(index: number, overrides: Partial<RemoteUsageRecord> = {}): RemoteUsageRecord {
  return {
    id: `remote-test:${index}`,
    at: BASE_AT + index * 1000,
    provider: 'deepseek-official',
    model: 'deepseek-flash',
    input: 889,
    output: 92,
    cached: 19072,
    cacheWrite: 0,
    reasoning: 0,
    sessionId: 'remote-test',
    turn: 1,
    step: index,
    ...overrides,
  }
}

interface SnapshotRecordShape {
  id: string
  at: string
  provider: string
  model: string
  input: number
  output: number
  cached: number
  cacheWrite?: number
  reasoning?: number
}

interface SnapshotShape {
  fetchedAt: string
  sources: Array<Record<string, unknown> & { source: string, records?: SnapshotRecordShape[] }>
}

/** Our source's records from a composed snapshot (length 0 when absent). */
function recordsOf(json: { sources: Array<Record<string, unknown>> }, source = 'remote/default'): SnapshotRecordShape[] {
  const entry = json.sources.find(item => item.source === source)
  return (entry?.records as SnapshotRecordShape[] | undefined) ?? []
}

console.log('\n== 1. sanitizeSample ==')
{
  const record = sanitizeSample(rawSample(), 'remote-98bb')
  check('a legal nested-usage sample becomes a record', record !== null, JSON.stringify(record))
  check('the id is <sessionId>:<seq>', record?.id === 'remote-98bb:1210', String(record?.id))
  check('cacheRead is mapped onto cached', record?.cached === 19072, String(record?.cached))
  check('epoch-ms at is preserved', record?.at === NOW - 60_000, String(record?.at))
  check('input/output are read from the usage object', record?.input === 889 && record?.output === 92)
  check('cacheWrite/reasoning are optional but mapped', record?.cacheWrite === 0 && record?.reasoning === 0)

  const flat = sanitizeSample({
    seq: 7, at: NOW - 10_000, provider: 'deepseek-official', model: 'deepseek-flash',
    input: 5, output: 6, cacheRead: 7,
  }, 's1')
  check('a flat (event-shaped) sample is accepted with cached = cacheRead', flat?.cached === 7 && flat.input === 5, JSON.stringify(flat))

  const isoAt = new Date(NOW - 20_000).toISOString()
  check('an ISO-8601 at string is accepted', sanitizeSample(rawSample({ at: isoAt }), 's1')?.at === Date.parse(isoAt))

  check('empty provider is rejected', sanitizeSample(rawSample({ provider: '' }), 's1') === null)
  check('empty model is rejected', sanitizeSample(rawSample({ model: '   ' }), 's1') === null)
  check('missing provider is rejected', sanitizeSample(rawSample({ provider: undefined }), 's1') === null)
  check('a negative token bucket is rejected',
    sanitizeSample(rawSample({ usage: { input: -1, output: 1, cacheRead: 0 } }), 's1') === null)
  check('a non-integer token bucket is rejected',
    sanitizeSample(rawSample({ usage: { input: 1.5, output: 1, cacheRead: 0 } }), 's1') === null)
  check('a token bucket above 1e12 is rejected',
    sanitizeSample(rawSample({ usage: { input: 2e12, output: 1, cacheRead: 0 } }), 's1') === null)
  check('a missing input bucket is rejected',
    sanitizeSample(rawSample({ usage: { output: 1, cacheRead: 0 } }), 's1') === null)
  check('a future timestamp is rejected',
    sanitizeSample(rawSample({ at: NOW + 10 * 60_000 }), 's1') === null)
  check('a missing seq is rejected (no stable id)', sanitizeSample(rawSample({ seq: undefined }), 's1') === null)
  check('a local provider (ollama) is rejected',
    sanitizeSample(rawSample({ provider: 'ollama' }), 's1') === null)
  check('a local model prefix (lmstudio:) is rejected',
    sanitizeSample(rawSample({ model: 'lmstudio:qwen' }), 's1') === null)
  check('a non-object sample is rejected',
    sanitizeSample(null, 's1') === null && sanitizeSample(42, 's1') === null && sanitizeSample('x', 's1') === null)
  check('an empty sessionId is rejected', sanitizeSample(rawSample(), '') === null)
}

console.log('\n== 2. composeSnapshot ==')
{
  const records = [makeRecord(1), makeRecord(2)]
  const composed = composeSnapshot({
    fetchedAt: NOW,
    sources: [{ source: 'remote/default', records }],
  })
  const json = composed.json as SnapshotShape & { sources: Array<Record<string, unknown>> }
  const ours = recordsOf(composed.json)
  check('fetchedAt is the ISO-8601 form of the input timestamp',
    composed.json.fetchedAt === new Date(NOW).toISOString(), composed.json.fetchedAt)
  check('fetchedAt matches cost-meter\'s timestamp grammar', COST_METER_ISO.test(composed.json.fetchedAt))
  check('our source is present exactly once', json.sources.filter(s => s.source === 'remote/default').length === 1)
  check('every record keeps cost-meter\'s fields',
    ours.length === 2 && ours.every(r => typeof r.id === 'string' && typeof r.provider === 'string'
      && typeof r.model === 'string' && typeof r.input === 'number' && typeof r.output === 'number'
      && typeof r.cached === 'number'))
  check('every at is an ISO timestamp cost-meter accepts',
    ours.every(r => COST_METER_ISO.test(r.at)), JSON.stringify(ours.map(r => r.at)))
  check('ids are unique within our source', new Set(ours.map(r => r.id)).size === ours.length)
  check('records are sorted by at ascending', ours.every((r, i) => i === 0 || ours[i - 1]!.at <= r.at))
  check('reported bytes equal the serialized size',
    composed.bytes === Buffer.byteLength(JSON.stringify(composed.json), 'utf8'), String(composed.bytes))

  // A record that would invalidate the whole snapshot is dropped at assembly.
  const guarded = composeSnapshot({
    fetchedAt: NOW,
    sources: [{ source: 'remote/default', records: [makeRecord(1), makeRecord(2, { provider: 'ollama' })] }],
  })
  check('an unsafe record is dropped instead of invalidating the snapshot', recordsOf(guarded.json).length === 1)

  // Duplicate ids collapse.
  const deduped = composeSnapshot({
    fetchedAt: NOW,
    sources: [{ source: 'remote/default', records: [makeRecord(1), makeRecord(1)] }],
  })
  check('duplicate record ids collapse to one', recordsOf(deduped.json).length === 1)

  // Preserved sources from other producers survive and everything is sorted.
  const preserved = [
    { source: 'zzz-external', days: { '2026-10-01': { input: 1, output: 2, cached: 0, calls: 1, costUsd: 0.01 } } },
    { source: 'aaa-external', records: [{ id: 'x', at: new Date(NOW - 1000).toISOString(), provider: 'p', model: 'm', input: 1, output: 1, cached: 0 }] },
    { source: 'not-an-object-with-source' },
  ]
  const withPreserved = composeSnapshot({ fetchedAt: NOW, sources: [{ source: 'remote/default', records }], preserved })
  const names = withPreserved.json.sources.map(s => String(s.source))
  check('preserved sources are retained', names.includes('aaa-external') && names.includes('zzz-external'), names.join(','))
  check('sources are stable-sorted by name', JSON.stringify(names) === JSON.stringify([...names].sort()), names.join(','))
  check('a malformed preserved entry is dropped', withPreserved.json.sources.length === 3, names.join(','))

  // A preserved source that reuses a name we own must not duplicate the source.
  const collision = composeSnapshot({
    fetchedAt: NOW,
    sources: [{ source: 'remote/default', records }],
    preserved: [{ source: 'remote/default', records: [] }],
  })
  check('a preserved source cannot shadow our source name', collision.json.sources.length === 1)

  // Two own sources: sorted by name, each records-mode.
  const two = composeSnapshot({
    fetchedAt: NOW,
    sources: [
      { source: 'remote/b', records: [makeRecord(1, { id: 'b:1', sessionId: 'b' })] },
      { source: 'remote/a', records: [makeRecord(2, { id: 'a:2', sessionId: 'a' })] },
    ],
  })
  const twoNames = two.json.sources.map(s => String(s.source))
  check('two own sources are emitted in name order', JSON.stringify(twoNames) === JSON.stringify(['remote/a', 'remote/b']), twoNames.join(','))
  check('each own source keeps its own records',
    recordsOf(two.json, 'remote/a').length === 1 && recordsOf(two.json, 'remote/b').length === 1)

  // Count cap: the oldest records are dropped first.
  const many = Array.from({ length: MAX_SNAPSHOT_RECORDS + 10 }, (_, i) => makeRecord(i))
  const capped = composeSnapshot({ fetchedAt: NOW, sources: [{ source: 'remote/default', records: many }] })
  const cappedRecords = recordsOf(capped.json)
  check(`count is capped at ${MAX_SNAPSHOT_RECORDS}`, cappedRecords.length === MAX_SNAPSHOT_RECORDS, String(cappedRecords.length))
  check('the ten oldest are the ones dropped',
    cappedRecords[0]?.id === many[10]?.id && cappedRecords.at(-1)?.id === many.at(-1)?.id,
    `${cappedRecords[0]?.id}..${cappedRecords.at(-1)?.id}`)

  // Byte cap: long provider/model strings force the serialized size over budget.
  const fat = Array.from({ length: MAX_SNAPSHOT_RECORDS }, (_, i) => makeRecord(i, { model: `m${i}-${'x'.repeat(280)}` }))
  const squeezed = composeSnapshot({ fetchedAt: NOW, sources: [{ source: 'remote/default', records: fat }] })
  const squeezedRecords = recordsOf(squeezed.json)
  check(`serialized size stays within ${MAX_SNAPSHOT_BYTES} bytes`, squeezed.bytes <= MAX_SNAPSHOT_BYTES, String(squeezed.bytes))
  check('the byte cap drops the oldest records, not the newest',
    squeezedRecords.length > 0 && squeezedRecords.length < fat.length && squeezedRecords.at(-1)?.id === fat.at(-1)?.id,
    `${squeezedRecords.length}/${fat.length}`)
  check('the byte cap keeps whole, valid records',
    squeezedRecords.every(r => COST_METER_ISO.test(r.at) && typeof r.cached === 'number'))

  // A preserved source big enough to bust the budget is dropped before our data.
  const bigPreserved = [{ source: 'huge', days: Object.fromEntries(Array.from({ length: 3000 }, (_, i) => [
    `2026-${String(1 + (i % 12)).padStart(2, '0')}-${String(1 + (i % 28)).padStart(2, '0')}`,
    { input: 1, output: 1, cached: 0, calls: 1, costUsd: 0.01 },
  ])) }]
  const heavy = composeSnapshot({ fetchedAt: NOW, sources: [{ source: 'remote/default', records }], preserved: bigPreserved })
  check('an oversized preserved source does not break the byte budget', heavy.bytes <= MAX_SNAPSHOT_BYTES, String(heavy.bytes))
  check('our source survives when preserved data is dropped', recordsOf(heavy.json).length === 2)

  // fetchedAt is clamped into cost-meter's accepted window.
  const stale = composeSnapshot({ fetchedAt: NOW - 40 * 86_400_000, sources: [{ source: 'remote/default', records: [] }] })
  check('a fetchedAt older than 30 days is replaced with now',
    Math.abs(Date.parse(stale.json.fetchedAt) - Date.now()) < 5000, stale.json.fetchedAt)
  const future = composeSnapshot({ fetchedAt: NOW + 10 * 60_000, sources: [{ source: 'remote/default', records: [] }] })
  check('a fetchedAt more than 5 minutes in the future is replaced with now',
    Math.abs(Date.parse(future.json.fetchedAt) - Date.now()) < 5000, future.json.fetchedAt)
  check('an empty source is legal (zero records)', recordsOf(future.json).length === 0 && future.json.sources.length === 1)
}

console.log('\n== 3. RemoteCostStore (persistence + snapshot writes) ==')
{
  const dir = tempDir()
  const storeFile = join(dir, 'dsh-remote', 'client-cost.json')
  const snapshotFile = join(dir, 'storages', 'cost-meter', 'external_usage.json')
  const store = new RemoteCostStore({
    storeFile,
    snapshotFile,
    sourceName: 'remote/default',
    sourcePrefix: 'remote/',
  })
  store.load()
  check('an empty store starts at cursor 0', store.cursorOf('remote-98bb') === 0)

  await store.record('remote-98bb', [
    makeRecord(1, { sessionId: 'remote-98bb' }),
    makeRecord(2, { sessionId: 'remote-98bb' }),
  ], 1200)
  await store.record('remote-98bb', [
    makeRecord(2, { sessionId: 'remote-98bb' }),
    makeRecord(3, { sessionId: 'remote-98bb' }),
  ], 1210)

  const summary = store.summary()
  check('incremental writes merge into three records', summary.records === 3, String(summary.records))
  check('a replayed id is not counted twice', summary.records === 3)
  check('the cursor advances to the last page', store.cursorOf('remote-98bb') === 1210, String(store.cursorOf('remote-98bb')))
  check('summary.lastAt is the newest ISO timestamp', summary.lastAt === new Date(BASE_AT + 3000).toISOString(), String(summary.lastAt))
  check('summary reports our source name', summary.source === 'remote/default', summary.source)

  const snapshot = JSON.parse(readFileSync(snapshotFile, 'utf8')) as SnapshotShape
  const snapshotRecords = snapshot.sources.find(s => s.source === 'remote/default')?.records ?? []
  check('the snapshot file exists and parses', snapshot.sources.length === 1, JSON.stringify(snapshot.sources.map(s => s.source)))
  check('the snapshot carries the stored records', snapshotRecords.length === 3, String(snapshotRecords.length))
  check('cacheRead is written as cached', snapshotRecords[0]?.cached === 19072, String(snapshotRecords[0]?.cached))
  check('record timestamps are ISO', snapshotRecords.every(r => COST_METER_ISO.test(r.at)))
  check('record ids are stable within the source', new Set(snapshotRecords.map(r => r.id)).size === 3)

  const persisted = JSON.parse(readFileSync(storeFile, 'utf8')) as {
    version: number, sessions: Record<string, { cursor: number, records: RemoteUsageRecord[] }>
  }
  check('the store file has the documented schema',
    persisted.version === 1 && persisted.sessions['remote-98bb']?.cursor === 1210
    && persisted.sessions['remote-98bb']?.records.length === 3,
    JSON.stringify(persisted).slice(0, 160))
}

console.log('\n== 3b. a foreign source in the snapshot is preserved ==')
{
  const dir = tempDir()
  const storeFile = join(dir, 'cost.json')
  const snapshotFile = join(dir, 'storages', 'cost-meter', 'external_usage.json')
  mkdirSync(dirname(snapshotFile), { recursive: true })
  const foreign = {
    fetchedAt: new Date(NOW - 60_000).toISOString(),
    sources: [{
      source: 'hindsight',
      days: { '2026-10-01': { input: 1, output: 2, cached: 3, calls: 4, costUsd: 0.5 } },
    }],
  }
  writeFileSync(snapshotFile, JSON.stringify(foreign), 'utf8')
  const store = new RemoteCostStore({ storeFile, snapshotFile, sourceName: 'remote/default', sourcePrefix: 'remote/' })
  store.load()
  await store.record('remote-x', [makeRecord(1, { sessionId: 'remote-x' })], 5)
  const written = JSON.parse(readFileSync(snapshotFile, 'utf8')) as SnapshotShape
  const names = written.sources.map(s => s.source)
  check('the foreign source is retained', names.includes('hindsight'), names.join(','))
  check('our source is added next to it', names.includes('remote/default'), names.join(','))
  check('the foreign day data is untouched', JSON.stringify(written.sources.find(s => s.source === 'hindsight')?.days)
    === JSON.stringify(foreign.sources[0]!.days))

  // And it survives a pure refresh (start-up path), too.
  await store.refreshSnapshot()
  const refreshed = JSON.parse(readFileSync(snapshotFile, 'utf8')) as SnapshotShape
  check('refreshSnapshot keeps the foreign source', refreshed.sources.some(s => s.source === 'hindsight'))
  check('refreshSnapshot keeps our records', recordsOf(refreshed as never).length === 1)
  check('refreshSnapshot writes a fresh fetchedAt', COST_METER_ISO.test(refreshed.fetchedAt))
}

console.log('\n== 3c. corrupt files degrade instead of throwing ==')
{
  const dir = tempDir()
  const storeFile = join(dir, 'cost.json')
  const snapshotFile = join(dir, 'snap.json')
  writeFileSync(storeFile, '{ this is not json', 'utf8')
  writeFileSync(snapshotFile, 'also not json', 'utf8')
  const store = new RemoteCostStore({ storeFile, snapshotFile, sourceName: 'remote/default', sourcePrefix: 'remote/' })
  let threw = false
  try {
    store.load()
    await store.record('remote-x', [makeRecord(1, { sessionId: 'remote-x' })], 9)
    await store.refreshSnapshot()
  } catch {
    threw = true
  }
  check('a corrupt store/snapshot never throws', !threw)
  check('a corrupt store reports no cursor', store.cursorOf('remote-x') === 9, String(store.cursorOf('remote-x')))
  check('the corrupt snapshot is replaced by a parseable one',
    (JSON.parse(readFileSync(snapshotFile, 'utf8')) as SnapshotShape).sources.length === 1)
  check('the store file is rewritten in the documented schema',
    (JSON.parse(readFileSync(storeFile, 'utf8')) as { version: number }).version === 1)

  // An unknown future version is treated as "no data".
  const dir2 = tempDir()
  const futureStore = join(dir2, 'cost.json')
  writeFileSync(futureStore, JSON.stringify({ version: 99, sessions: { a: { cursor: 5, records: [] } } }), 'utf8')
  const store2 = new RemoteCostStore({ storeFile: futureStore, snapshotFile: join(dir2, 'snap.json'), sourceName: 'remote/default', sourcePrefix: 'remote/' })
  store2.load()
  check('an unknown store version is treated as empty', store2.cursorOf('a') === 0, String(store2.cursorOf('a')))
}

console.log('\n== 3d. the store keeps only the newest records ==')
{
  const dir = tempDir()
  const storeFile = join(dir, 'cost.json')
  const snapshotFile = join(dir, 'snap.json')
  const store = new RemoteCostStore({ storeFile, snapshotFile, sourceName: 'remote/default', sourcePrefix: 'remote/' })
  store.load()
  const samples = Array.from({ length: MAX_STORE_RECORDS + 100 }, (_, i) => makeRecord(i, { sessionId: 'remote-big' }))
  await store.record('remote-big', samples, 5000)
  const summary = store.summary()
  check(`the store is capped at ${MAX_STORE_RECORDS} records`, summary.records === MAX_STORE_RECORDS, String(summary.records))
  check('the oldest records are the ones dropped',
    summary.lastAt === new Date(BASE_AT + (MAX_STORE_RECORDS + 99) * 1000).toISOString(), String(summary.lastAt))
  const snapshot = JSON.parse(readFileSync(snapshotFile, 'utf8')) as SnapshotShape
  const written = snapshot.sources.find(s => s.source === 'remote/default')?.records ?? []
  check('the snapshot is capped too', written.length === MAX_STORE_RECORDS, String(written.length))
  check('the newest record is present in the snapshot',
    written.some(r => r.id === `remote-test:${MAX_STORE_RECORDS + 99}`))
}

console.log('\n== 3e. concurrent record() calls are serialized ==')
{
  const dir = tempDir()
  const storeFile = join(dir, 'cost.json')
  const snapshotFile = join(dir, 'snap.json')
  const store = new RemoteCostStore({ storeFile, snapshotFile, sourceName: 'remote/default', sourcePrefix: 'remote/' })
  store.load()
  await Promise.all([
    store.record('remote-a', [makeRecord(1, { id: 'a:1', sessionId: 'remote-a' })], 10),
    store.record('remote-b', [makeRecord(2, { id: 'b:2', sessionId: 'remote-b' })], 20),
    store.record('remote-a', [makeRecord(3, { id: 'a:3', sessionId: 'remote-a' })], 30),
  ])
  check('every concurrent write lands', store.summary().records === 3, String(store.summary().records))
  check('cursors are per session',
    store.cursorOf('remote-a') === 30 && store.cursorOf('remote-b') === 20,
    `${store.cursorOf('remote-a')}/${store.cursorOf('remote-b')}`)
  const snapshot = JSON.parse(readFileSync(snapshotFile, 'utf8')) as SnapshotShape
  check('the snapshot reflects all of them', (snapshot.sources.find(s => s.source === 'remote/default')?.records ?? []).length === 3)
}

console.log('\n== 4. real cost-meter parser contract regression (optional) ==')
{
  const libDir = join(homedir(), '.dsh', 'profiles', 'desktop', 'node_modules', 'dsh-cost-meter', 'lib')
  const parserFile = join(libDir, 'external-usage.js')
  if (!existsSync(parserFile)) {
    console.log(`skip: ${parserFile} not found (dsh-cost-meter not installed here)`)
  } else {
    type ParseFn = (value: unknown, config: unknown, nowMs?: number) => {
      stale?: boolean
      sources?: Array<{ source: string, total?: { calls?: number } }>
    } | null
    type ParserModule = { parseExternalUsageSnapshot?: ParseFn }
    type PricingModule = { buildPriceCatalog?: (currency?: string) => unknown }

    /** Import the real parser from its installed location. */
    const loadInstalled = async (): Promise<{ parser: ParseFn, pricing: PricingModule }> => {
      const parserModule = await import(pathToFileURL(parserFile).href) as ParserModule
      const pricingModule = await import(pathToFileURL(join(libDir, 'pricing.js')).href) as PricingModule
      if (typeof parserModule.parseExternalUsageSnapshot !== 'function') throw new Error('no parseExternalUsageSnapshot export')
      return { parser: parserModule.parseExternalUsageSnapshot, pricing: pricingModule }
    }

    /**
     * `dsh-cost-meter` is an installed DSH profile plugin: its two bare imports
     * (`@deepseek-ai/dsh-home-paths`, `@deepseek-ai/dsh-credentials`) are
     * provided by the running harness, so a plain node process cannot resolve
     * them from the profile directory. Copy the lib into a temp "profile" with
     * tiny stubs for exactly those two pure symbols and import from there. The
     * parser logic itself is the REAL installed code.
     */
    const loadFromShadowProfile = async (): Promise<{ parser: ParseFn, pricing: PricingModule }> => {
      const root = join(tempDir(), 'profile')
      const moduleDir = join(root, 'node_modules', 'dsh-cost-meter', 'lib')
      cpSync(libDir, moduleDir, { recursive: true })
      const stubs: Array<[string, string]> = [
        ['dsh-home-paths', 'export const resolveDshHome = () => process.env.DSH_HOME ?? "."\n'],
        ['dsh-credentials', 'export const credentialRef = (name) => ({ name: String(name ?? "") })\n'],
      ]
      for (const [pkgName, source] of stubs) {
        const dir = join(root, 'node_modules', '@deepseek-ai', pkgName)
        mkdirSync(dir, { recursive: true })
        writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `@deepseek-ai/${pkgName}`, type: 'module', main: 'index.js' }), 'utf8')
        writeFileSync(join(dir, 'index.js'), source, 'utf8')
      }
      const parserModule = await import(pathToFileURL(join(moduleDir, 'external-usage.js')).href) as ParserModule
      const pricingModule = await import(pathToFileURL(join(moduleDir, 'pricing.js')).href) as PricingModule
      if (typeof parserModule.parseExternalUsageSnapshot !== 'function') throw new Error('no parseExternalUsageSnapshot export')
      return { parser: parserModule.parseExternalUsageSnapshot, pricing: pricingModule }
    }

    let loaded: { parser: ParseFn, pricing: PricingModule } | undefined
    const problems: string[] = []
    try {
      loaded = await loadInstalled()
    } catch (error) {
      problems.push(`installed: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`)
      try {
        loaded = await loadFromShadowProfile()
      } catch (shadowError) {
        problems.push(`shadow: ${shadowError instanceof Error ? shadowError.message.split('\n')[0] : String(shadowError)}`)
      }
    }

    const buildConfig = (pricing: PricingModule): Record<string, unknown> | undefined => {
      if (typeof pricing.buildPriceCatalog !== 'function') return undefined
      return { prices: pricing.buildPriceCatalog('USD'), peakEnabled: false, exchangeRate: 1 }
    }
    const snapshotConfig = loaded === undefined ? undefined : buildConfig(loaded.pricing)

    if (loaded === undefined || snapshotConfig?.prices === undefined) {
      console.log(`skip: the real cost-meter parser cannot be loaded here (${problems.join(' | ')})`)
    } else {
      const composed = composeSnapshot({
        fetchedAt: Date.now(),
        sources: [{
          source: 'remote/default',
          records: [
            makeRecord(1, { at: Date.now() - 60_000, id: 'remote-98bb:1210' }),
            makeRecord(2, { at: Date.now() - 30_000, id: 'remote-98bb:1211' }),
          ],
        }],
      })
      const parsed = loaded.parser(composed.json, snapshotConfig, Date.now())
      check('the real cost-meter parser accepts the composed snapshot', parsed !== null, 'parser returned null')
      if (parsed !== null) {
        check('the parsed snapshot has our source', parsed.sources?.some(s => s.source === 'remote/default') === true,
          JSON.stringify(parsed.sources?.map(s => s.source)))
        const ours = parsed.sources?.find(s => s.source === 'remote/default')
        check('the parser priced and counted both calls', (ours?.total?.calls ?? 0) === 2, JSON.stringify(ours?.total))
      }

      // The preserved-other-producer path must also stay parseable: a `days`
      // source we did not write, next to our `records` source.
      const yesterday = new Date(Date.now() - 86_400_000).toISOString().slice(0, 10)
      const mixed = composeSnapshot({
        fetchedAt: Date.now(),
        sources: [{ source: 'remote/default', records: [makeRecord(1, { at: Date.now() - 60_000 })] }],
        preserved: [{
          source: 'hindsight',
          days: { [yesterday]: { input: 10, output: 20, cached: 0, calls: 1, costUsd: 0.01 } },
        }],
      })
      const parsedMixed = loaded.parser(mixed.json, snapshotConfig, Date.now())
      check('the real parser accepts our source beside a preserved days source', parsedMixed !== null, 'parser returned null')
      if (parsedMixed !== null) {
        check('both sources are reported by the parser', parsedMixed.sources?.length === 2,
          JSON.stringify(parsedMixed.sources?.map(s => s.source)))
      }
    }
  }
}

for (const dir of dirs) rmSync(dir, { recursive: true, force: true })
console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
