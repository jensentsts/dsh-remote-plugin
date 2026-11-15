/**
 * Extract per-model-call token usage from a session's event log.
 *
 * The controlling half runs a cost meter, but it cannot see this machine's
 * session events. Rather than price anything here — price tables and
 * peak/off-peak windows belong to whoever displays the bill, and shipping a
 * price list to a peer would mean redeploying it whenever prices change — this
 * module only reports WHAT the provider returned: five token buckets, the route
 * that produced them, and when.
 *
 * Everything is read from `unknown` data on purpose: the events come from a
 * different DSH version than the caller's. A malformed event must be dropped,
 * never thrown on, or one bad record would take down the whole read.
 *
 * The de-duplication rule replicates `dsh-cost-meter`'s backfill, because that
 * is the ledger the controller reconciles against: while scanning, remember the
 * last kept sample; a sample repeating the SAME (turn, step) key with the SAME
 * provider/model and all five token buckets is the same call reported twice
 * (an `assistant/chunk` usage chunk followed by the final `assistant/message`
 * of the same step) and is counted once.
 */

/** The five disjoint buckets the controller prices separately. */
export interface SessionUsageBuckets {
  input: number
  output: number
  cacheRead: number
  cacheWrite: number
  reasoning: number
}

/** One billable model call (or a compaction summary) as reported by this machine. */
export interface SessionUsageSample {
  /** Session event sequence number, strictly ascending within one full scan. */
  seq: number
  /** Event time in epoch milliseconds. */
  at: number
  provider: string
  model: string
  /** Step coordinates when the host identified them; null for compactions. */
  turn: number | null
  step: number | null
  kind: 'call' | 'compaction'
  usage: SessionUsageBuckets
}

/** What one extraction pass produced. */
export interface ExtractedUsage {
  /** Samples strictly newer than `fromSeq`, in event order, at most `limit` of them. */
  records: SessionUsageSample[]
  /** How many events were looked at (diagnostics only). */
  scanned: number
  /**
   * Cursor for the next read.
   *
   * When the result was truncated this is the seq of the last returned sample,
   * NOT the newest scanned event: advancing past unseen samples would silently
   * drop them. Only an untruncated pass may jump straight to the newest event
   * seq (or `fromSeq` when the log had nothing newer).
   */
  nextSeq: number
}

/** Samples returned when the caller does not ask for a size; also the server op default. */
const DEFAULT_LIMIT = 500

/** Hard ceiling: one response must stay small enough for a single link frame. */
const MAX_LIMIT = 2000

type RawRecord = Record<string, unknown>

/**
 * Narrow an untrusted value to a plain object.
 *
 * Arrays are rejected too: `typeof [] === 'object'`, but index-shaped data is
 * never a valid event.
 */
function asRecord(value: unknown): RawRecord | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  return value as RawRecord
}

/** A token bucket: non-negative safe integer or nothing. */
export function normalizeTokenCount(value: unknown): number | undefined {
  if (typeof value !== 'number') return undefined
  return Number.isSafeInteger(value) && value >= 0 ? value : undefined
}

/** A non-empty route name; an empty string would poison the controller's price lookup. */
function nonEmptyString(value: unknown): string | undefined {
  return typeof value === 'string' && value !== '' ? value : undefined
}

/**
 * An optional bucket: absent means "the adapter did not report it" and is
 * worth 0 (DSH's TokenUsage marks cache/reasoning counters optional). A value
 * that is PRESENT but malformed means the whole sample cannot be trusted.
 *
 * @returns the bucket, or null when the field exists but is not a valid count.
 */
function optionalBucket(value: unknown): number | null {
  if (value === undefined || value === null) return 0
  const count = normalizeTokenCount(value)
  return count === undefined ? null : count
}

/**
 * Convert one provider `TokenUsage`-shaped object into the wire buckets.
 *
 * `inputTokens` and `outputTokens` are required — without them there is nothing
 * to bill. `totalTokens` is deliberately ignored: it is an aggregate the
 * controller can recompute, and it is absent on some providers.
 *
 * @param raw - untrusted `data.usage` / `data.chunk.usage`.
 * @returns the buckets, or undefined when the sample must be dropped.
 */
export function normalizeUsage(raw: unknown): SessionUsageBuckets | undefined {
  const usage = asRecord(raw)
  if (usage === undefined) return undefined
  const input = normalizeTokenCount(usage.inputTokens)
  const output = normalizeTokenCount(usage.outputTokens)
  if (input === undefined || output === undefined) return undefined
  const cacheRead = optionalBucket(usage.cacheReadTokens)
  const cacheWrite = optionalBucket(usage.cacheWriteTokens)
  const reasoning = optionalBucket(usage.reasoningTokens)
  if (cacheRead === null || cacheWrite === null || reasoning === null) return undefined
  return { input, output, cacheRead, cacheWrite, reasoning }
}

/** Step coordinates of an `assistant/message` / `assistant/chunk` event. */
function readPosition(data: RawRecord): { turn: number | null, step: number | null } {
  return {
    turn: normalizeTokenCount(data.turn) ?? null,
    step: normalizeTokenCount(data.step) ?? null,
  }
}

/**
 * The dedup key of a call.
 *
 * `(turn, step)` identifies one model call, which is why the streaming usage
 * chunk and the final message collapse into one sample. When a host omitted the
 * coordinates there is no honest way to tell two calls apart, so each sample
 * gets a key unique to its own seq and is always counted.
 */
function callKey(seq: number, turn: number | null, step: number | null): string {
  return turn !== null && step !== null ? `call:${turn}:${step}` : `seq:${seq}`
}

/** Event time as epoch milliseconds, or undefined when unusable. */
function eventTime(event: RawRecord): number | undefined {
  const time = event.time
  return typeof time === 'number' && Number.isFinite(time) && time > 0 ? time : undefined
}

function sameUsage(a: SessionUsageBuckets, b: SessionUsageBuckets): boolean {
  return a.input === b.input
    && a.output === b.output
    && a.cacheRead === b.cacheRead
    && a.cacheWrite === b.cacheWrite
    && a.reasoning === b.reasoning
}

/** The last kept sample, replayed against the next one to fold duplicate reports. */
interface KeptSample {
  key: string
  provider: string
  model: string
  usage: SessionUsageBuckets
}

/**
 * Extract usage samples from a session's event array.
 *
 * The whole array is scanned on every call — the route state (`request/header`)
 * and the duplicate fold must be built up from the beginning, otherwise a read
 * starting mid-session could misattribute a model or count a repeated streaming
 * sample twice. Only insertion into the result is filtered by `fromSeq`, and
 * the filter runs AFTER de-duplication: a cursor landing between a usage chunk
 * and its final message must not resurrect the message as a second call.
 *
 * Array order is treated as the order of the call; seq is only used for the
 * cursor, never for sorting, because reordered/synthetic events are a host
 * detail this half must not crash on.
 *
 * @param events - `session.snapshotEvents()` or any event-shaped array.
 * @param options - `fromSeq` is an exclusive lower bound; `limit` is clamped to 1..2000.
 * @returns the page, plus diagnostics and the next cursor.
 */
export function extractUsageRecords(
  events: readonly unknown[],
  options: { fromSeq?: number, limit?: number } = {},
): ExtractedUsage {
  const fromSeq = normalizeTokenCount(options.fromSeq) ?? 0
  const requestedLimit = normalizeTokenCount(options.limit)
  const limit = requestedLimit === undefined || requestedLimit === 0
    ? DEFAULT_LIMIT
    : Math.min(requestedLimit, MAX_LIMIT)

  /** Route state built from `request/header` snapshots. */
  let routeProvider = ''
  let routeModel = ''

  let scanned = 0
  let maxSeq = fromSeq
  let last: KeptSample | undefined
  const all: SessionUsageSample[] = []

  for (const entry of events) {
    scanned += 1
    const event = asRecord(entry)
    if (event === undefined) continue
    const seq = normalizeTokenCount(event.seq)
    if (seq === undefined) continue
    if (seq > maxSeq) maxSeq = seq
    const type = typeof event.type === 'string' ? event.type : ''

    if (type === 'request/header') {
      // The header is the billing route state: a later `assistant/chunk` has no
      // message source of its own, and an old host's message may omit one too.
      // Update field by field so a partial snapshot does not erase the other half.
      const header = asRecord(asRecord(event.data)?.header)
      const config = asRecord(header?.config)
      const provider = nonEmptyString(config?.provider)
      const model = nonEmptyString(config?.model)
      if (provider !== undefined) routeProvider = provider
      if (model !== undefined) routeModel = model
      continue
    }

    const data = asRecord(event.data)
    if (data === undefined) continue

    if (type === 'assistant/message') {
      const usage = normalizeUsage(data.usage)
      if (usage === undefined) continue
      const at = eventTime(event)
      if (at === undefined) continue
      // `message.source` is stamped per call and beats the header: a model
      // switch can appear in a message before any new header is logged.
      const source = asRecord(asRecord(data.message)?.source)
      const provider = nonEmptyString(source?.provider) ?? (routeProvider === '' ? undefined : routeProvider)
      const model = nonEmptyString(source?.model) ?? (routeModel === '' ? undefined : routeModel)
      if (provider === undefined || model === undefined) continue
      const { turn, step } = readPosition(data)
      const key = callKey(seq, turn, step)
      if (last !== undefined && last.key === key && last.provider === provider && last.model === model
        && sameUsage(last.usage, usage)) {
        continue
      }
      all.push({ seq, at, provider, model, turn, step, kind: 'call', usage })
      last = { key, provider, model, usage }
      continue
    }

    if (type === 'assistant/chunk') {
      // Old and new hosts disagree on where streamed usage lives; both put it
      // under `data.chunk` as a `usage` chunk, and only a non-null usage makes
      // the chunk billable.
      const chunk = asRecord(data.chunk)
      if (chunk === undefined || chunk.type !== 'usage') continue
      const usage = normalizeUsage(chunk.usage)
      if (usage === undefined) continue
      const at = eventTime(event)
      if (at === undefined) continue
      // A streaming chunk carries no message source, so the header state is the
      // only route available — exactly why the header scan cannot start at the cursor.
      const provider = routeProvider === '' ? undefined : routeProvider
      const model = routeModel === '' ? undefined : routeModel
      if (provider === undefined || model === undefined) continue
      const { turn, step } = readPosition(data)
      const key = callKey(seq, turn, step)
      if (last !== undefined && last.key === key && last.provider === provider && last.model === model
        && sameUsage(last.usage, usage)) {
        continue
      }
      all.push({ seq, at, provider, model, turn, step, kind: 'call', usage })
      last = { key, provider, model, usage }
      continue
    }

    if (type === 'compaction/summary') {
      // Compaction is real billing (the summarizer is a model call) but has no
      // (turn, step); it is keyed by its own seq instead.
      const usage = normalizeUsage(data.usage)
      if (usage === undefined) continue
      const at = eventTime(event)
      if (at === undefined) continue
      const source = asRecord(asRecord(data.message)?.source)
      const provider = nonEmptyString(source?.provider) ?? nonEmptyString(data.provider)
      const model = nonEmptyString(source?.model) ?? nonEmptyString(data.model)
      if (provider === undefined || model === undefined) continue
      all.push({ seq, at, provider, model, turn: null, step: null, kind: 'compaction', usage })
      last = { key: `compaction:${seq}`, provider, model, usage }
      continue
    }

    // Everything else is out of scope on purpose. In particular the
    // `cost-meter/*-usage` events are a controller plugin's own bookkeeping;
    // this machine may not have that plugin, and its ledger does not accept
    // such a source as a model call.
  }

  const visible = fromSeq === 0 ? all : all.filter(sample => sample.seq > fromSeq)
  const records = visible.length > limit ? visible.slice(0, limit) : visible
  const newest = records[records.length - 1]
  const nextSeq = newest !== undefined && records.length < visible.length ? newest.seq : maxSeq
  return { records, scanned, nextSeq }
}
