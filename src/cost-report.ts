/**
 * Remote token-usage accounting for the controller half of dsh-remote.
 *
 * Every turn this side drives on the peer costs real tokens on the peer's
 * account. The local `dsh-cost-meter` plugin can show that spend, but only
 * through its ONE official third-party entry point:
 * `${DSH_HOME}/storages/cost-meter/external_usage.json`, a snapshot file the
 * producer replaces atomically and cost-meter re-reads whenever it refreshes
 * its state (see that plugin's `docs/external-usage.md`).
 *
 * So this module does two things and nothing else:
 *
 *  1. keeps a **local, persistent record store** of the peer's per-call usage
 *     (plus the read cursor per remote session), so a later turn only asks the
 *     peer for what is new;
 *  2. re-assembles the complete external-usage snapshot from that store (and
 *     from whatever sources OTHER producers already put in the file), then
 *     writes it atomically.
 *
 * ## Why records and not daily totals
 *
 * The peer reports one five-bucket token sample per model call: input/output/
 * cacheRead/cacheWrite/reasoning, plus provider, model and a timestamp. Daily
 * summaries would force *us* to price each call — including DeepSeek's peak /
 * off-peak and long-context rules — which is exactly the logic cost-meter
 * already owns and re-applies on every state refresh. Call-record mode lets
 * cost-meter price each sample at its `at` instant with the current local price
 * table, so this module never guesses a dollar amount.
 *
 * ## Fail-closed snapshot rules
 *
 * cost-meter ignores the WHOLE snapshot when any single part of it is invalid
 * (bad timestamp, duplicate id, unpriced provider/model, more than 5000 records,
 * over 512 KiB, …). The guards below are therefore deliberately strict, and the
 * sizes are kept well inside cost-meter's own limits: at most
 * {@link MAX_SNAPSHOT_RECORDS} of OUR records and {@link MAX_SNAPSHOT_BYTES}
 * serialized bytes. Every write is best-effort: a missing directory, a corrupt
 * sibling file or a filesystem error is logged (when a logger is supplied) and
 * otherwise ignored, never thrown at the caller.
 *
 * @module dsh-remote/cost-report
 */

import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'

/** Most call records this plugin keeps across all remote sessions. */
export const MAX_STORE_RECORDS = 2000

/** Most of OUR call records a single snapshot may carry (cost-meter allows 5000 total). */
export const MAX_SNAPSHOT_RECORDS = 2000

/**
 * Serialized-byte ceiling for the snapshot we write.
 *
 * cost-meter's hard cap is 512 KiB; staying at 450 KB leaves room for the
 * preserved sources of other producers while still failing safe (a snapshot
 * over the cap is ignored outright).
 */
export const MAX_SNAPSHOT_BYTES = 450_000

/** Longest source name cost-meter accepts. */
const MAX_SOURCE_NAME = 64

/** cost-meter refuses a snapshot fetched more than 30 days ago… */
const MAX_AGE_MS = 30 * 86_400_000

/** …or farther than 5 minutes in the future. */
const MAX_FUTURE_MS = 300_000

/** cost-meter's token-bucket range: a non-negative safe integer up to 1e12. */
const MAX_TOKEN_COUNT = 1e12

/** Longest record id cost-meter accepts within one source. */
const MAX_RECORD_ID = 128

/** Our store schema version; an unknown version is treated as "no data". */
const STORE_VERSION = 1

/**
 * Providers cost-meter classifies as local inference, copied from its
 * `pricing.js` (`LOCAL_PROVIDER_IDS` / `LOCAL_MODEL_PREFIXES`).
 *
 * An unpriced provider/model invalidates the entire snapshot, and local
 * inference has no price, so these samples must never be written. Keeping the
 * two lists in sync with cost-meter is the whole point; extending one side
 * without the other silently drops (or breaks) the whole file.
 */
const LOCAL_PROVIDER_IDS = new Set([
  'local', 'lmstudio', 'ollama', 'jan', 'gpt4all', 'koboldcpp', 'llamacpp', 'llama-cpp', 'localai',
  'vllm', 'sglang', 'tabbyapi', 'lmdeploy', 'oobabooga', 'text-generation-webui', 'llama-server',
])

/** Model prefixes cost-meter classifies as local inference. */
const LOCAL_MODEL_PREFIXES = [
  'lmstudio:', 'lmstudio/', 'ollama:', 'ollama/', 'jan:', 'jan/', 'gpt4all:', 'gpt4all/',
  'koboldcpp:', 'koboldcpp/', 'llamacpp:', 'llamacpp/', 'llama-cpp:', 'llama-cpp/',
  'localai:', 'localai/', 'vllm:', 'vllm/', 'sglang:', 'sglang/', 'tabbyapi:', 'tabbyapi/',
  'lmdeploy:', 'oobabooga/', 'text-generation-webui/', 'llama-server:', 'gguf:', 'local:',
]

/**
 * One completed remote model call, in the shape this plugin persists.
 *
 * `at` is **epoch milliseconds** (not ISO) so ordering, trimming and duplicate
 * handling are plain number compares; {@link composeSnapshot} converts it to
 * the ISO-8601 timestamp cost-meter requires. `id` is derived from the remote
 * session and the peer's event sequence, so re-reading a page can never
 * double-count.
 */
export interface RemoteUsageRecord {
  /** Stable id within our source: `<remoteSessionId>:<seq>`. */
  id: string
  /** Call timestamp, epoch milliseconds. */
  at: number
  provider: string
  model: string
  /** Uncached input tokens. */
  input: number
  /** Output tokens. */
  output: number
  /** Cache-read input tokens (cost-meter's `cached`). */
  cached: number
  /** Optional cache-write tokens. */
  cacheWrite?: number
  /** Optional reasoning tokens. */
  reasoning?: number
  /** The remote session the call belongs to. */
  sessionId: string
  /** Turn / step numbers are informational only. */
  turn: number
  step: number
}

/** One source in the snapshot we assemble. */
export interface SnapshotSource {
  source: string
  records: RemoteUsageRecord[]
}

/** Input to {@link composeSnapshot}. */
export interface ComposeSnapshotInput {
  /** Snapshot timestamp, epoch ms. Clamped into cost-meter's accepted window. */
  fetchedAt: number
  /** This plugin's own sources. Records are deduped, sorted and trimmed. */
  sources: SnapshotSource[]
  /** Sources of OTHER producers, preserved verbatim when legal. */
  preserved?: unknown[]
}

/** Result of {@link composeSnapshot}. */
export interface ComposedSnapshot {
  /** The full snapshot object (`fetchedAt` + `sources`), ready to serialize. */
  json: { fetchedAt: string, sources: Array<Record<string, unknown>> }
  /** Serialized UTF-8 byte length (the number {@link MAX_SNAPSHOT_BYTES} caps). */
  bytes: number
}

/** Options for {@link RemoteCostStore}. */
export interface RemoteCostStoreOptions {
  /** Where the persistent call-record store lives (`client-cost.json`). */
  storeFile: string
  /** Where the cost-meter snapshot is written (`…/storages/cost-meter/external_usage.json`). */
  snapshotFile: string
  /** Snapshot source name for this peer, e.g. `remote/default`. */
  sourceName: string
  /** Prefix reserved for this plugin's own sources, e.g. `remote/`. */
  sourcePrefix: string
  /** One-line sink for swallowed IO errors (default: silent). */
  log?: (message: string) => void
}

/** How much this plugin has recorded — the `remote_ping` summary. */
export interface RemoteCostSummary {
  source: string
  records: number
  /** Newest record timestamp as ISO-8601, or null when nothing is stored. */
  lastAt: string | null
}

/** Session data in the store file. */
interface StoredSession {
  cursor: number
  records: RemoteUsageRecord[]
}

/** Persisted store schema. */
interface StoreFile {
  version: number
  sessions: Record<string, StoredSession>
}

/** True for a non-null, non-array object. */
function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** cost-meter's token-bucket predicate: a safe integer in [0, 1e12]. */
function tokenCount(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_TOKEN_COUNT
    ? value
    : null
}

/** Epoch-ms from a number or an ISO-8601 string; null when unusable. */
function timestampMs(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) return Math.trunc(value)
  if (typeof value === 'string' && value !== '') {
    const parsed = Date.parse(value)
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null
  }
  return null
}

/** cost-meter's model cleaning (`modelNameText`) for local-prefix detection. */
function modelText(value: string): string {
  return value.normalize('NFKC').toLowerCase().trim()
}

/** True when cost-meter would classify this provider/model as local inference. */
export function isLocalInference(provider: string, model: string): boolean {
  const raw = provider.trim().toLowerCase()
  const normalized = raw.startsWith('llm-') ? raw.slice(4) : raw
  if (LOCAL_PROVIDER_IDS.has(normalized)) return true
  const name = modelText(model)
  return LOCAL_MODEL_PREFIXES.some(prefix => name.startsWith(prefix))
}

/**
 * Convert one `usage.read` sample into a persisted record.
 *
 * Returns null for anything that could not be written to a VALID snapshot:
 * a non-object, an empty provider/model, a local-inference provider (unpriced),
 * a bad timestamp, an invalid sequence, or a token bucket outside cost-meter's
 * accepted range. Bad samples are dropped one at a time on purpose — one odd
 * call must not cost the rest of the report.
 *
 * @param raw - one element of a `usage.read` reply's `records` array.
 * @param sessionId - the remote session the sample came from (used for the id).
 * @returns the record, or null when the sample must be skipped.
 */
export function sanitizeSample(raw: unknown, sessionId: string): RemoteUsageRecord | null {
  if (!isObject(raw)) return null
  if (typeof sessionId !== 'string' || sessionId === '') return null
  const provider = typeof raw.provider === 'string' ? raw.provider.trim() : ''
  const model = typeof raw.model === 'string' ? raw.model.trim() : ''
  if (provider === '' || model === '') return null
  if (isLocalInference(provider, model)) return null
  const seq = typeof raw.seq === 'number' ? raw.seq : Number.NaN
  if (!Number.isSafeInteger(seq) || seq < 0) return null
  const id = `${sessionId}:${seq}`
  if (id.length > MAX_RECORD_ID) return null
  const at = timestampMs(raw.at)
  if (at === null || at > Date.now() + MAX_FUTURE_MS) return null
  // The five token buckets arrive either nested under `usage` (the documented
  // `usage.read` record shape) or flat on the record itself (the shape of a raw
  // session event). Accept both so a peer that exposes its internal events
  // directly still reports correctly.
  const buckets = isObject(raw.usage) ? raw.usage : raw
  // `usage.read` reports cacheRead; accept a literal `cached` too so a slightly
  // different peer shape still maps onto the one bucket cost-meter wants.
  const cachedRaw = buckets.cacheRead ?? buckets.cached ?? 0
  const input = tokenCount(buckets.input)
  const output = tokenCount(buckets.output)
  const cached = tokenCount(cachedRaw)
  if (input === null || output === null || cached === null) return null
  const cacheWrite = buckets.cacheWrite === undefined ? undefined : tokenCount(buckets.cacheWrite)
  if (cacheWrite === null) return null
  const reasoning = buckets.reasoning === undefined ? undefined : tokenCount(buckets.reasoning)
  if (reasoning === null) return null
  return {
    id,
    at,
    provider,
    model,
    input,
    output,
    cached,
    ...(cacheWrite === undefined ? {} : { cacheWrite }),
    ...(reasoning === undefined ? {} : { reasoning }),
    sessionId,
    turn: safeSmallInt(raw.turn),
    step: safeSmallInt(raw.step),
  }
}

/** A bounded, non-negative integer for purely informational fields. */
function safeSmallInt(value: unknown): number {
  const number = typeof value === 'number' ? value : Number.NaN
  return Number.isFinite(number) && number >= 0 ? Math.trunc(number) : 0
}

/** Trim/validate a snapshot source name; returns null when it cannot be used. */
function sourceNameOf(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const name = value.trim()
  if (name.length < 1 || name.length > MAX_SOURCE_NAME) return null
  return name
}

/** Deterministic ISO-8601 timestamp cost-meter accepts (`.sssZ`). */
function isoAt(ms: number): string {
  return new Date(ms).toISOString()
}

/** Sort records by `at` ascending, then by id, so output is deterministic. */
function sortRecords(records: RemoteUsageRecord[]): RemoteUsageRecord[] {
  return [...records].sort((a, b) => (a.at === b.at ? (a.id < b.id ? -1 : a.id > b.id ? 1 : 0) : a.at - b.at))
}

/** Dedupe by id, keeping the first occurrence, then sort. */
function dedupeRecords(records: RemoteUsageRecord[]): RemoteUsageRecord[] {
  const seen = new Set<string>()
  const out: RemoteUsageRecord[] = []
  for (const record of records) {
    if (seen.has(record.id)) continue
    seen.add(record.id)
    out.push(record)
  }
  return sortRecords(out)
}

/**
 * Final pre-write guard: would cost-meter accept this record?
 *
 * The store normally only holds records that {@link sanitizeSample} passed, but
 * the snapshot is the file's last line of defence: a hand-edited store, an old
 * entry whose timestamp slid into the future, or a provider that started being
 * classified as local must not be able to invalidate the WHOLE file. One bad
 * record is dropped instead.
 */
function snapshotSafeRecord(record: RemoteUsageRecord, now: number): boolean {
  if (typeof record.id !== 'string' || record.id === '' || record.id.length > MAX_RECORD_ID) return false
  if (typeof record.provider !== 'string' || record.provider.trim() === '') return false
  if (typeof record.model !== 'string' || record.model.trim() === '') return false
  if (isLocalInference(record.provider, record.model)) return false
  if (!Number.isFinite(record.at) || record.at <= 0 || record.at > now + MAX_FUTURE_MS) return false
  if (tokenCount(record.input) === null || tokenCount(record.output) === null || tokenCount(record.cached) === null) return false
  if (record.cacheWrite !== undefined && tokenCount(record.cacheWrite) === null) return false
  if (record.reasoning !== undefined && tokenCount(record.reasoning) === null) return false
  return true
}

/** Keep only preserved source objects that cannot on their own invalidate the file. */
function normalizePreserved(raw: unknown, seen: Set<string>): Array<Record<string, unknown>> {
  if (!Array.isArray(raw)) return []
  const out: Array<Record<string, unknown>> = []
  for (const item of raw) {
    if (!isObject(item)) continue
    const source = sourceNameOf(item.source)
    if (source === null || seen.has(source)) continue
    const hasDays = isObject(item.days)
    const hasRecords = Array.isArray(item.records)
    // cost-meter: exactly one input mode per source.
    if (hasDays === hasRecords) continue
    seen.add(source)
    out.push(item)
  }
  return out
}

/** A validated own source at snapshot-assembly time. */
interface OwnSource {
  source: string
  records: RemoteUsageRecord[]
}

/** Snapshot object for a given set of sources (records mode for ours). */
function buildSnapshot(
  fetchedAt: string,
  ours: OwnSource[],
  preserved: Array<Record<string, unknown>>,
): { fetchedAt: string, sources: Array<Record<string, unknown>> } {
  const ourSources: Array<Record<string, unknown>> = ours.map(entry => ({
    source: entry.source,
    records: entry.records.map(record => ({
      id: record.id,
      at: isoAt(record.at),
      provider: record.provider,
      model: record.model,
      input: record.input,
      output: record.output,
      cached: record.cached,
      ...(record.cacheWrite === undefined ? {} : { cacheWrite: record.cacheWrite }),
      ...(record.reasoning === undefined ? {} : { reasoning: record.reasoning }),
    })),
  }))
  const sources = [...ourSources, ...preserved].sort((a, b) => {
    const left = String(a.source)
    const right = String(b.source)
    return left < right ? -1 : left > right ? 1 : 0
  })
  return { fetchedAt, sources }
}

/** Serialized UTF-8 byte length of a snapshot. */
function snapshotBytes(snapshot: { fetchedAt: string, sources: Array<Record<string, unknown>> }): number {
  return Buffer.byteLength(JSON.stringify(snapshot), 'utf8')
}

/** Flatten own sources into (source, record) pairs, at-ascending then by id. */
function flattenOwn(ours: OwnSource[]): Array<{ source: string, record: RemoteUsageRecord }> {
  const flat: Array<{ source: string, record: RemoteUsageRecord }> = []
  for (const entry of ours) {
    for (const record of entry.records) flat.push({ source: entry.source, record })
  }
  flat.sort((a, b) => (a.record.at === b.record.at
    ? (a.record.id < b.record.id ? -1 : a.record.id > b.record.id ? 1 : 0)
    : a.record.at - b.record.at))
  return flat
}

/** Rebuild per-source arrays from a flat, at-ascending list (order preserved). */
function regroupOwn(flat: Array<{ source: string, record: RemoteUsageRecord }>, sources: string[]): OwnSource[] {
  const grouped = new Map<string, RemoteUsageRecord[]>()
  for (const name of sources) grouped.set(name, [])
  for (const { source, record } of flat) grouped.get(source)?.push(record)
  return sources.map(source => ({ source, records: grouped.get(source) ?? [] }))
}

/** Keep the newest `count` entries of an at-ascending flat list. */
function keepNewest(flat: Array<{ source: string, record: RemoteUsageRecord }>, count: number): Array<{ source: string, record: RemoteUsageRecord }> {
  return count >= flat.length ? flat : flat.slice(flat.length - count)
}

/**
 * Assemble a complete `external_usage.json` snapshot.
 *
 * Applies every constraint that lets cost-meter trust the file:
 *
 *  - `fetchedAt` is clamped into "no older than 30 days, no more than 5 minutes
 *    ahead" and serialized as ISO-8601 with `Z`;
 *  - our source is always present (possibly with zero records, which is legal);
 *    its records are deduped by id and sorted by `at` ascending;
 *  - preserved sources from other producers are kept verbatim — but only legal
 *    object entries with exactly one of `days` / `records` and a unique source
 *    name;
 *  - at most 8 sources total (cost-meter's cap), ours plus the alphabetically
 *    first preserved ones;
 *  - at most {@link MAX_SNAPSHOT_RECORDS} of OUR records: the oldest are dropped
 *    first when over the count;
 *  - at most {@link MAX_SNAPSHOT_BYTES} serialized bytes: again the oldest of our
 *    records are dropped first (binary search on how many newest records fit),
 *    then preserved sources from the end as a last resort.
 *
 * The returned `bytes` is the exact serialized size, so callers can assert the
 * contract without re-serializing.
 *
 * @param input - fetchedAt, our sources and optional preserved sources.
 * @returns the snapshot object plus its serialized size.
 */
export function composeSnapshot(input: ComposeSnapshotInput): ComposedSnapshot {
  const now = Date.now()
  let fetchedAt = Number.isFinite(input.fetchedAt) ? Math.trunc(input.fetchedAt) : now
  if (fetchedAt > now + MAX_FUTURE_MS || now - fetchedAt > MAX_AGE_MS) fetchedAt = now
  const stamp = isoAt(fetchedAt)

  // Our sources: every legal entry, one per unique source name, records deduped,
  // final-validated and sorted. More than 8 (cost-meter's total cap) is trimmed
  // alphabetically so the choice is deterministic instead of input-order luck.
  const ours: OwnSource[] = []
  const seenOwn = new Set<string>()
  for (const entry of input.sources ?? []) {
    const name = sourceNameOf(entry.source)
    if (name === null || seenOwn.has(name) || !Array.isArray(entry.records)) continue
    seenOwn.add(name)
    const records = dedupeRecords(entry.records).filter(record => snapshotSafeRecord(record, now))
    ours.push({ source: name, records })
  }
  ours.sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : 0))
  if (ours.length === 0) ours.push({ source: 'remote/default', records: [] })
  if (ours.length > 8) ours.length = 8

  // Preserved sources of OTHER producers; only names not claimed by ours, and
  // only entries that are legal on their own (exactly one of days/records).
  const seenSources = new Set<string>(ours.map(entry => entry.source))
  const preserved = normalizePreserved(input.preserved, seenSources)
    .sort((a, b) => {
      const left = String(a.source)
      const right = String(b.source)
      return left < right ? -1 : left > right ? 1 : 0
    })
    .slice(0, Math.max(0, 8 - ours.length))

  // Count cap: keep the newest records across all our sources.
  const ownNames = ours.map(entry => entry.source)
  let flat = flattenOwn(ours)
  if (flat.length > MAX_SNAPSHOT_RECORDS) flat = keepNewest(flat, MAX_SNAPSHOT_RECORDS)

  // Byte cap: binary-search how many newest records fit (serialized size is
  // monotonic in that count), then drop preserved sources if they alone overrun.
  let built = buildSnapshot(stamp, regroupOwn(flat, ownNames), preserved)
  let bytes = snapshotBytes(built)
  if (bytes > MAX_SNAPSHOT_BYTES) {
    let low = 0
    let high = flat.length
    let keep = 0
    while (low <= high) {
      const mid = Math.floor((low + high) / 2)
      const candidate = buildSnapshot(stamp, regroupOwn(keepNewest(flat, mid), ownNames), preserved)
      if (snapshotBytes(candidate) <= MAX_SNAPSHOT_BYTES) {
        keep = mid
        low = mid + 1
      } else {
        high = mid - 1
      }
    }
    flat = keepNewest(flat, keep)
    built = buildSnapshot(stamp, regroupOwn(flat, ownNames), preserved)
    bytes = snapshotBytes(built)
  }

  // Last resort: our own (already-minimal) content cannot overrun on its own, so
  // a still-oversized file means preserved sources did. Drop them from the end.
  let removable = preserved.length
  while (bytes > MAX_SNAPSHOT_BYTES && removable > 0) {
    removable -= 1
    built = buildSnapshot(stamp, regroupOwn(flat, ownNames), preserved.slice(0, removable))
    bytes = snapshotBytes(built)
  }

  return { json: built, bytes }
}

/** Write JSON to `file` through a same-directory temp file + atomic rename. */
function writeJsonAtomic(file: string, value: unknown, log?: (message: string) => void): void {
  const dir = dirname(file)
  const temp = join(dir, `.${basename(file)}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`)
  try {
    mkdirSync(dir, { recursive: true })
    writeFileSync(temp, `${JSON.stringify(value)}\n`, 'utf8')
    renameSync(temp, file)
  } catch (error) {
    try {
      unlinkSync(temp)
    } catch {
      // The temp file may not exist; nothing else to clean up.
    }
    log?.(`cost-report: could not write ${file} (${error instanceof Error ? error.message : String(error)})`)
  }
}

/** Read and JSON-parse a file; null on any problem (missing, corrupt, oversized). */
function readJsonFile(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as unknown
  } catch {
    return null
  }
}

/** Validate one persisted record; unknown shapes are dropped, never fatal. */
function loadRecord(raw: unknown): RemoteUsageRecord | null {
  if (!isObject(raw)) return null
  const id = typeof raw.id === 'string' ? raw.id : ''
  const sessionId = typeof raw.sessionId === 'string' ? raw.sessionId : ''
  const provider = typeof raw.provider === 'string' ? raw.provider : ''
  const model = typeof raw.model === 'string' ? raw.model : ''
  if (id === '' || id.length > MAX_RECORD_ID || sessionId === '' || provider === '' || model === '') return null
  const at = timestampMs(raw.at)
  const input = tokenCount(raw.input)
  const output = tokenCount(raw.output)
  const cached = tokenCount(raw.cached)
  if (at === null || input === null || output === null || cached === null) return null
  const cacheWrite = raw.cacheWrite === undefined ? undefined : tokenCount(raw.cacheWrite)
  if (cacheWrite === null) return null
  const reasoning = raw.reasoning === undefined ? undefined : tokenCount(raw.reasoning)
  if (reasoning === null) return null
  return {
    id, at, provider, model, input, output, cached,
    ...(cacheWrite === undefined ? {} : { cacheWrite }),
    ...(reasoning === undefined ? {} : { reasoning }),
    sessionId,
    turn: safeSmallInt(raw.turn),
    step: safeSmallInt(raw.step),
  }
}

/**
 * Persistent call-record store + snapshot writer for one peer.
 *
 * The store keeps a cursor per remote session so each prompt asks only for new
 * events, and at most {@link MAX_STORE_RECORDS} records across all sessions
 * (newest by `at`). Every write is serialized through one promise chain: two
 * prompts finishing at the same time must not overwrite each other's snapshot.
 *
 * All IO is best effort. A missing, corrupt or stale store degrades to "no
 * data"; a failed snapshot write is logged and skipped. Nothing in this class
 * rejects — callers can `void` its promises without a risk of an unhandled
 * rejection reaching the model.
 */
export class RemoteCostStore {
  /** The peer's snapshot source name, normalized to a legal value. */
  readonly sourceName: string
  /** Prefix that marks a snapshot source as ours (exact by convention). */
  readonly sourcePrefix: string
  private readonly storeFile: string
  private readonly snapshotFile: string
  private readonly log: ((message: string) => void) | undefined
  private readonly sessions = new Map<string, StoredSession>()
  private loaded = false
  private chain: Promise<void> = Promise.resolve()

  /**
   * @param options - file locations, source naming and an optional logger.
   */
  constructor(options: RemoteCostStoreOptions) {
    this.storeFile = options.storeFile
    this.snapshotFile = options.snapshotFile
    this.log = options.log
    // An empty prefix would claim every source in the file; fall back to the
    // documented default so foreign sources are never swallowed.
    const prefix = options.sourcePrefix === '' ? 'remote/' : options.sourcePrefix
    this.sourcePrefix = prefix
    const name = sourceNameOf(options.sourceName)
    this.sourceName = name ?? 'remote/default'
  }

  /** Load the store, tolerating a missing, corrupt or future-version file. */
  load(): void {
    this.loaded = true
    this.sessions.clear()
    const parsed = readJsonFile(this.storeFile)
    if (!isObject(parsed) || parsed.version !== STORE_VERSION || !isObject(parsed.sessions)) return
    for (const [sessionId, rawSession] of Object.entries(parsed.sessions)) {
      if (sessionId === '' || !isObject(rawSession) || !Array.isArray(rawSession.records)) continue
      const cursor = safeSmallInt(rawSession.cursor)
      const records: RemoteUsageRecord[] = []
      for (const rawRecord of rawSession.records) {
        const record = loadRecord(rawRecord)
        if (record !== null && record.sessionId === sessionId) records.push(record)
      }
      if (cursor === 0 && records.length === 0) continue
      this.sessions.set(sessionId, { cursor, records })
    }
    this.trim()
  }

  /** The last peer event sequence accounted for in a session (0 when new). */
  cursorOf(sessionId: string): number {
    this.ensureLoaded()
    return this.sessions.get(sessionId)?.cursor ?? 0
  }

  /** How much this plugin has recorded for this peer (no IO, no network). */
  summary(): RemoteCostSummary {
    this.ensureLoaded()
    let records = 0
    let newest = 0
    for (const session of this.sessions.values()) {
      records += session.records.length
      for (const record of session.records) {
        if (record.at > newest) newest = record.at
      }
    }
    return {
      source: this.sourceName,
      records,
      lastAt: newest === 0 ? null : isoAt(newest),
    }
  }

  /**
   * Merge one page of samples, advance the session cursor, persist the store,
   * then rewrite the snapshot. Dedupes by record id, so replaying a page (or a
   * `usage.read` that returns a slightly older `fromSeq`) cannot double-count.
   *
   * @param sessionId - the remote session the samples belong to.
   * @param samples - sanitized records (see {@link sanitizeSample}).
   * @param nextSeq - the peer's event sequence after this page.
   * @returns a promise that settles when both writes are done; never rejects.
   */
  record(sessionId: string, samples: RemoteUsageRecord[], nextSeq: number): Promise<void> {
    return this.enqueue(async () => {
      this.ensureLoaded()
      const session = this.sessions.get(sessionId) ?? { cursor: 0, records: [] }
      const known = new Set(session.records.map(record => record.id))
      let changed = false
      for (const sample of samples) {
        if (known.has(sample.id)) continue
        known.add(sample.id)
        session.records.push(sample)
        changed = true
      }
      const cursor = Number.isFinite(nextSeq) && nextSeq > session.cursor ? Math.trunc(nextSeq) : session.cursor
      const cursorMoved = cursor !== session.cursor
      if (!changed && !cursorMoved) return
      session.cursor = cursor
      this.sessions.set(sessionId, session)
      this.trim()
      this.writeStore()
      await this.writeSnapshot()
    })
  }

  /**
   * Re-assemble the snapshot from the current store without adding records.
   *
   * Called once at plugin start so a snapshot left by the previous process is
   * refreshed (cost-meter marks one older than 24 hours as stale) even if no
   * remote prompt runs in this session.
   *
   * @returns a promise that settles when the write is attempted; never rejects.
   */
  refreshSnapshot(): Promise<void> {
    return this.enqueue(async () => {
      this.ensureLoaded()
      await this.writeSnapshot()
    })
  }

  /** Trim the persisted records to the newest {@link MAX_STORE_RECORDS} by `at`. */
  private trim(): void {
    const all: Array<{ sessionId: string, record: RemoteUsageRecord }> = []
    for (const [sessionId, session] of this.sessions) {
      for (const record of session.records) all.push({ sessionId, record })
    }
    if (all.length <= MAX_STORE_RECORDS) return
    all.sort((a, b) => (a.record.at === b.record.at ? (a.record.id < b.record.id ? 1 : -1) : b.record.at - a.record.at))
    const kept = all.slice(0, MAX_STORE_RECORDS)
    // Trimming must not reset a session's cursor: the cursor is what keeps the
    // next prompt from re-fetching (and re-deduping) the whole history.
    const cursors = new Map<string, number>()
    for (const [sessionId, session] of this.sessions) cursors.set(sessionId, session.cursor)
    this.sessions.clear()
    for (const { sessionId, record } of kept) {
      const session = this.sessions.get(sessionId) ?? { cursor: cursors.get(sessionId) ?? 0, records: [] }
      session.records.push(record)
      this.sessions.set(sessionId, session)
    }
  }

  /** Serialize and atomically replace the store file. */
  private writeStore(): void {
    const sessions: Record<string, StoredSession> = {}
    for (const sessionId of [...this.sessions.keys()].sort()) {
      const session = this.sessions.get(sessionId)
      if (session === undefined) continue
      sessions[sessionId] = { cursor: session.cursor, records: sortRecords(session.records) }
    }
    const file: StoreFile = { version: STORE_VERSION, sessions }
    writeJsonAtomic(this.storeFile, file, this.log)
  }

  /** Assemble and atomically replace the external-usage snapshot. */
  private async writeSnapshot(): Promise<void> {
    try {
      const existing = readJsonFile(this.snapshotFile)
      const preserved = this.preservedSources(existing)
      const records = this.allRecords()
      const snapshot = composeSnapshot({
        fetchedAt: Date.now(),
        sources: [{ source: this.sourceName, records }],
        preserved,
      })
      writeJsonAtomic(this.snapshotFile, snapshot.json, this.log)
    } catch (error) {
      // writeJsonAtomic already swallows filesystem errors; this guard is for
      // the (unlikely) failure of snapshot assembly itself.
      this.log?.(`cost-report: snapshot assembly failed (${error instanceof Error ? error.message : String(error)})`)
    }
  }

  /** Every stored record across sessions, at-ascending and id-deduped. */
  private allRecords(): RemoteUsageRecord[] {
    const out: RemoteUsageRecord[] = []
    for (const session of this.sessions.values()) out.push(...session.records)
    return dedupeRecords(out)
  }

  /**
   * Foreign sources already in the snapshot file.
   *
   * Only sources that do NOT use this plugin's prefix are preserved: our own
   * source is replaced wholesale by the fresh store contents. Both the
   * `sources` array shape and cost-meter's single-top-level-source shape are
   * accepted, so a file written by an older/more lenient producer still
   * contributes instead of being clobbered.
   */
  private preservedSources(existing: unknown): unknown[] {
    if (!isObject(existing)) return []
    const raw = Array.isArray(existing.sources) ? existing.sources : [existing]
    const out: unknown[] = []
    for (const item of raw) {
      if (!isObject(item)) continue
      const source = typeof item.source === 'string' ? item.source : ''
      if (source === this.sourceName || source.startsWith(this.sourcePrefix)) continue
      out.push(item)
    }
    return out
  }

  /** Ensure the store was read before the first use (load() is idempotent-ish). */
  private ensureLoaded(): void {
    if (!this.loaded) this.load()
  }

  /** Run one task after every previously enqueued task; never rejects. */
  private enqueue(task: () => Promise<void>): Promise<void> {
    const next = this.chain.then(task).catch((error: unknown) => {
      this.log?.(`cost-report: ${error instanceof Error ? error.message : String(error)}`)
    })
    this.chain = next
    return next
  }
}
