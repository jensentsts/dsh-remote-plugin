/**
 * Unit test for the usage extraction that feeds the controller's cost meter.
 *
 * No host, no network: `extractUsageRecords` is a pure function over an
 * event-shaped array, so every billing rule can be pinned down here. The two
 * properties worth protecting hardest are (a) a model call reported twice — a
 * streamed usage chunk plus the final message — is billed once, and (b) a
 * cursor landing between those two reports still bills once, not zero and not
 * two. Both are ledger-correctness bugs that would silently corrupt a bill.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/session-usage.test.ts
 */

import { extractUsageRecords, normalizeUsage } from '../src/session-usage.ts'
import type { SessionUsageSample } from '../src/session-usage.ts'

let failures = 0
let checks = 0

function check(label: string, condition: boolean, detail = ''): void {
  checks += 1
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}${detail === '' ? '' : ` — ${detail}`}`)
  }
}

function section(title: string): void {
  console.log(`\n== ${title} ==`)
}

/** A fixed epoch so timestamps are readable in failure output. */
const T0 = 1_792_269_000_000

/** Provider TokenUsage shape, as the session log actually stores it. */
function usage(
  input: number,
  output: number,
  cacheRead = 0,
  cacheWrite = 0,
  reasoning = 0,
): Record<string, number> {
  return {
    inputTokens: input,
    outputTokens: output,
    cacheReadTokens: cacheRead,
    cacheWriteTokens: cacheWrite,
    reasoningTokens: reasoning,
  }
}

type Json = Record<string, unknown>

function event(type: string, seq: number, data: Json, time = T0 + seq * 1000): Json {
  return { type, seq, time, data }
}

function headerEvent(seq: number, provider: string, model: string): Json {
  return event('request/header', seq, { header: { config: { provider, model } } })
}

function messageEvent(
  seq: number,
  turn: number,
  step: number,
  source: { provider: string, model: string } | undefined,
  rawUsage: unknown,
): Json {
  const message: Json = {}
  if (source !== undefined) message.source = { kind: 'model', provider: source.provider, model: source.model }
  return event('assistant/message', seq, { turn, step, message, usage: rawUsage })
}

function chunkEvent(seq: number, turn: number, step: number, rawUsage: unknown): Json {
  return event('assistant/chunk', seq, { turn, step, chunk: { type: 'usage', usage: rawUsage } })
}

function compactionEvent(
  seq: number,
  route: { provider: string, model: string } | undefined,
  rawUsage: unknown,
): Json {
  const data: Json = { usage: rawUsage, ...(route === undefined ? {} : route) }
  return event('compaction/summary', seq, data)
}

function seqs(records: SessionUsageSample[]): number[] {
  return records.map(record => record.seq)
}

function usageText(record: SessionUsageSample | undefined): string {
  return record === undefined ? 'undefined' : JSON.stringify(record.usage)
}

// ---------------------------------------------------------------------------
section('1. one assistant/message: usage buckets, route, time, coordinates')
{
  const events = [
    headerEvent(1, 'header-provider', 'header-model'),
    messageEvent(2, 1, 3, { provider: 'deepseek-official', model: 'deepseek-flash' }, usage(889, 92, 19_072)),
  ]
  const out = extractUsageRecords(events)
  const record = out.records[0]
  check('exactly one sample', out.records.length === 1, `got ${out.records.length}`)
  check('message.source beats the header route', record?.provider === 'deepseek-official'
    && record.model === 'deepseek-flash', `${record?.provider}/${record?.model}`)
  check('seq comes from the event', record?.seq === 2, String(record?.seq))
  check('at comes from event.time', record?.at === T0 + 2000, String(record?.at))
  check('turn/step preserved', record?.turn === 1 && record?.step === 3, `${record?.turn}/${record?.step}`)
  check('kind is call', record?.kind === 'call', String(record?.kind))
  check('all five buckets mapped', usageText(record) === JSON.stringify({
    input: 889, output: 92, cacheRead: 19_072, cacheWrite: 0, reasoning: 0,
  }), usageText(record))
  check('scanned counts every event', out.scanned === 2, String(out.scanned))
  check('nextSeq is the newest scanned seq', out.nextSeq === 2, String(out.nextSeq))
}

// ---------------------------------------------------------------------------
section('2. streamed usage chunk + final message of one step bill once')
{
  const shared = usage(10, 20, 30)
  const events = [
    headerEvent(1, 'deepseek-official', 'deepseek-flash'),
    chunkEvent(2, 1, 1, shared),
    messageEvent(3, 1, 1, { provider: 'deepseek-official', model: 'deepseek-flash' }, shared),
    // Same (turn, step) but a DIFFERENT token sample: that is not a duplicate.
    messageEvent(4, 1, 1, { provider: 'deepseek-official', model: 'deepseek-flash' }, usage(11, 20, 30)),
  ]
  const out = extractUsageRecords(events)
  check('identical repeat folded away', seqs(out.records).join(',') === '2,4', seqs(out.records).join(','))
  check('different buckets counted separately', out.records.length === 2, String(out.records.length))

  // The chunk has no message source, so without a header it cannot be routed
  // and must be dropped rather than attributed to a guessed model.
  const unrouted = extractUsageRecords([chunkEvent(1, 1, 1, shared)])
  check('chunk without a header route is dropped', unrouted.records.length === 0, String(unrouted.records.length))
}

// ---------------------------------------------------------------------------
section('3. distinct (turn, step) and compaction are separate billable samples')
{
  const events = [
    headerEvent(1, 'deepseek-official', 'deepseek-flash'),
    messageEvent(2, 1, 1, { provider: 'deepseek-official', model: 'deepseek-flash' }, usage(1, 2)),
    messageEvent(3, 1, 2, { provider: 'deepseek-official', model: 'deepseek-flash' }, usage(3, 4)),
    // Compaction routes through its own provider/model fields (older host shape).
    compactionEvent(4, { provider: 'deepseek-official', model: 'deepseek-flash' }, usage(100, 50)),
    // …and through data.message.source on the other shape.
    event('compaction/summary', 5, {
      usage: usage(7, 8),
      message: { source: { kind: 'model', provider: 'alt-provider', model: 'alt-model' } },
    }),
  ]
  const out = extractUsageRecords(events)
  check('two calls plus two compactions', seqs(out.records).join(',') === '2,3,4,5', seqs(out.records).join(','))
  check('same-step repeats are the only folded pair', out.records.length === 4, String(out.records.length))
  const compactions = out.records.filter(record => record.kind === 'compaction')
  check('compaction kind marked', compactions.length === 2, String(compactions.length))
  check('compaction has no turn/step', compactions.every(record => record.turn === null && record.step === null))
  check('compaction keeps its route (data.provider shape)', compactions[0]?.provider === 'deepseek-official')
  check('compaction keeps its route (message.source shape)', compactions[1]?.model === 'alt-model')
}

// ---------------------------------------------------------------------------
section('4. fromSeq cursor: no repeats and no gaps across the chunk/message seam')
{
  const shared = usage(10, 20)
  const events = [
    headerEvent(1, 'p', 'm'),
    chunkEvent(2, 1, 1, shared),
    messageEvent(3, 1, 1, { provider: 'p', model: 'm' }, shared),
    messageEvent(4, 1, 2, { provider: 'p', model: 'm' }, usage(11, 21)),
    compactionEvent(5, { provider: 'p', model: 'm' }, usage(30, 40)),
  ]
  const full = extractUsageRecords(events)
  check('full scan yields three samples', seqs(full.records).join(',') === '2,4,5', seqs(full.records).join(','))

  const after = extractUsageRecords(events, { fromSeq: 2 })
  check('cursor right after the chunk does not resurrect the message', seqs(after.records).join(',') === '4,5',
    seqs(after.records).join(','))
  const oldCursor = extractUsageRecords(events, { fromSeq: 1 })
  check('cursor before the pair still bills it once', seqs(oldCursor.records).join(',') === '2,4,5',
    seqs(oldCursor.records).join(','))

  // Page through with limit 1 and prove the union equals one full scan.
  const pages: number[] = []
  let cursor = 0
  for (let guard = 0; guard < 10; guard += 1) {
    const page = extractUsageRecords(events, { fromSeq: cursor, limit: 1 })
    pages.push(...seqs(page.records))
    if (page.nextSeq === cursor && page.records.length === 0) break
    cursor = page.nextSeq
    if (page.records.length === 0) break
  }
  check('paged union equals the full scan', pages.join(',') === '2,4,5', pages.join(','))
  check('paged result has no duplicates', new Set(pages).size === pages.length, pages.join(','))
  check('empty tail reports the newest seq as cursor', extractUsageRecords(events, { fromSeq: 5 }).nextSeq === 5)
}

// ---------------------------------------------------------------------------
section('5. limit truncation and the 2000-sample ceiling')
{
  const events: Json[] = []
  for (let index = 0; index < 2500; index += 1) {
    events.push(messageEvent(index + 1, index + 1, 1, { provider: 'p', model: 'm' }, usage(1, 1)))
  }
  const defaulted = extractUsageRecords(events)
  check('default limit is 500', defaulted.records.length === 500, String(defaulted.records.length))
  check('default page keeps the FIRST samples', defaulted.records[0]?.seq === 1
    && defaulted.records[499]?.seq === 500, `${defaulted.records[0]?.seq}..${defaulted.records[499]?.seq}`)
  check('truncated nextSeq is the last returned seq, not the newest scanned event',
    defaulted.nextSeq === 500, String(defaulted.nextSeq))

  const requested = extractUsageRecords(events, { limit: 2500 })
  check('limit above the ceiling clamps to 2000', requested.records.length === 2000, String(requested.records.length))

  const asked = extractUsageRecords(events, { limit: 7 })
  check('explicit limit honoured', asked.records.length === 7 && asked.nextSeq === 7,
    `${asked.records.length}/${asked.nextSeq}`)
}

// ---------------------------------------------------------------------------
section('6. hostile input is dropped, never thrown')
{
  const bad: unknown[] = [
    null,
    42,
    'not an event',
    { seq: 1, time: T0, data: {} }, // no type
    { type: 'assistant/message', time: T0, data: { usage: usage(1, 1) } }, // no seq
    { type: 'assistant/message', seq: 2, time: T0, data: { turn: 1, step: 1 } }, // no usage
    messageEvent(3, 1, 1, { provider: 'p', model: 'm' }, { outputTokens: 5 }), // missing input
    messageEvent(4, 1, 1, { provider: 'p', model: 'm' }, usage(-1, 5)), // negative
    messageEvent(5, 1, 1, { provider: 'p', model: 'm' }, { inputTokens: 1, outputTokens: '9' }), // string
    messageEvent(6, 1, 1, { provider: 'p', model: 'm' }, { inputTokens: 1, outputTokens: 2, cacheReadTokens: -3 }),
    // Valid tokens, but a zero event time makes the sample unbillable.
    { type: 'assistant/message', seq: 7, time: 0, data: { turn: 1, step: 1, message: { source: { provider: 'p', model: 'm' } }, usage: usage(1, 2) } },
    { type: 'assistant/message', seq: 8, time: T0, data: { turn: 1, step: 1, message: {}, usage: usage(1, 2) } }, // no route
    { type: 'assistant/message', seq: 9, time: T0, data: { turn: 1, step: 1, message: { source: { provider: '', model: 'm' } }, usage: usage(1, 2) } },
    event('assistant/chunk', 10, { turn: 1, step: 1, chunk: { type: 'text', usage: usage(1, 2) } }),
    event('assistant/chunk', 11, { turn: 1, step: 1, chunk: { type: 'usage', usage: null } }),
    event('compaction/summary', 12, { usage: { inputTokens: 1 } }),
    event('cost-meter/native-search-usage', 13, { usage: usage(1, 2) }),
    messageEvent(14, 1, 1, { provider: 'p', model: 'm' }, usage(5, 6)), // the only survivor
  ]
  let out: ReturnType<typeof extractUsageRecords> | undefined
  try {
    out = extractUsageRecords(bad)
  } catch (error) {
    check('bad input never throws', false, error instanceof Error ? error.message : String(error))
  }
  check('bad input never throws', out !== undefined)
  check('only the valid sample survives', out !== undefined && seqs(out.records).join(',') === '14',
    out === undefined ? 'threw' : seqs(out.records).join(','))
  check('all events were still scanned', out?.scanned === bad.length, String(out?.scanned))
  check('cursor advanced past dropped events', out?.nextSeq === 14, String(out?.nextSeq))
}

// ---------------------------------------------------------------------------
section('7. request/header state is replayed from the start of the log')
{
  const events = [
    headerEvent(1, 'alpha', 'model-a'),
    messageEvent(2, 1, 1, undefined, usage(1, 1)), // no message.source: header decides
    headerEvent(3, 'beta', 'model-b'),
    messageEvent(4, 1, 2, undefined, usage(2, 2)),
  ]
  const first = extractUsageRecords(events)
  check('first call uses header route alpha', first.records[0]?.provider === 'alpha'
    && first.records[0]?.model === 'model-a', `${first.records[0]?.provider}/${first.records[0]?.model}`)
  check('header switch applies to later messages', first.records[1]?.provider === 'beta'
    && first.records[1]?.model === 'model-b', `${first.records[1]?.provider}/${first.records[1]?.model}`)

  // A cursor AFTER the header must still be billed under the route that header
  // established: the scan starts at the beginning even when only later samples
  // are returned.
  const later = extractUsageRecords(events, { fromSeq: 3 })
  check('cursor after the switch keeps the new route', later.records.length === 1
    && later.records[0]?.provider === 'beta', `${later.records.length}/${later.records[0]?.provider}`)

  const again = extractUsageRecords(events)
  check('extraction is stateless across calls',
    JSON.stringify(again.records) === JSON.stringify(first.records))
}

// ---------------------------------------------------------------------------
section('8. normalizeUsage: required vs optional buckets')
{
  check('full shape round-trips', JSON.stringify(normalizeUsage(usage(1, 2, 3, 4, 5)))
    === JSON.stringify({ input: 1, output: 2, cacheRead: 3, cacheWrite: 4, reasoning: 5 }))
  check('optional counters absent becomes zero', JSON.stringify(normalizeUsage({ inputTokens: 1, outputTokens: 2 }))
    === JSON.stringify({ input: 1, output: 2, cacheRead: 0, cacheWrite: 0, reasoning: 0 }))
  check('missing required input is rejected', normalizeUsage({ outputTokens: 2 }) === undefined)
  check('fractional count is rejected', normalizeUsage({ inputTokens: 1.5, outputTokens: 2 }) === undefined)
  check('negative count is rejected', normalizeUsage(usage(-1, 2)) === undefined)
  check('non-object is rejected', normalizeUsage(null) === undefined && normalizeUsage('x') === undefined)
}

// ---------------------------------------------------------------------------
console.log(`\n${checks - failures}/${checks} checks passed`)
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`)
  process.exitCode = 1
}
