/**
 * The remote's **trajectory journal**: a durable, LLM-free record of everything
 * this half did or saw.
 *
 * A normal session's trajectory is `user → model → tools → model → …`. This one
 * is the other loop: `controller → plugin → machine`, appended by the plugin
 * itself, so recording an operation costs storage and validation only — never a
 * model call. That is the point: keep every trace (commands, file writes, driven
 * turns, model calls of the sessions this half drives, and the human interrupts
 * on this machine) while spending nothing to collect them.
 *
 * It is deliberately a plain append-only JSONL file plus an in-memory ring,
 * rather than a DSH session: the session store documents that a session
 * published outside the agent lifecycle persists nothing, and a journal that
 * evaporates on restart would defeat its own purpose. A DSH session view can be
 * layered on later; this file is the source of truth either way.
 *
 * Reading is the other half of the design. Entries carry a monotonic `seq`, so a
 * controller asks for "everything after N" and gets only what is new — the cheap
 * form of context. `full` opts into the detail; the default is one line per
 * entry, which is what an agent should be reading into its context.
 *
 * @module dsh-remote/journal
 */

import { appendFileSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** What one entry records. */
export type JournalKind =
  /** A request this half served (exec, fs.*, agent.*, …). */
  | 'op'
  /** A turn of a session this half drives ended. */
  | 'turn'
  /** A human on this machine stopped something, or a controller asked to. */
  | 'interrupt'
  /** A model call observed in a session this half drives. */
  | 'model'
  /** Journal lifecycle: start, rotation. */
  | 'note'

/** One journal entry. `summary` is the cheap, always-present form. */
export interface JournalEntry {
  /** Monotonic across rotations and restarts. */
  seq: number
  /** ISO-8601 instant. */
  at: string
  kind: JournalKind
  /** One line, bounded — this is what belongs in an agent's context. */
  summary: string
  /** The op name for `kind: 'op'`. */
  op?: string
  /** Outcome for `kind: 'op'`. */
  ok?: boolean
  /** Duration in milliseconds, for `kind: 'op'`. */
  ms?: number
  /** The remote session this belongs to, when there is one. */
  sessionId?: string
  /** Extra detail; only returned when a reader asks for `full`. */
  detail?: Record<string, unknown>
}

/** What a reader gets back. */
export interface JournalRead {
  /** The seq actually read from (clamped to what exists). */
  fromSeq: number
  /** Pass this as `fromSeq` next time to read only what is new. */
  nextSeq: number
  /** Total entries this journal currently holds. */
  total: number
  /** Entries returned. */
  count: number
  entries: JournalEntry[]
}

/** Where the journal lives and how big it may get. */
export interface JournalOptions {
  /** JSONL file path. */
  file: string
  /** Rotate once the file passes this size (default 8 MiB). */
  maxBytes?: number
  /** Entries kept in memory for cheap tail reads (default 5000). */
  ringSize?: number
  /** Clock, for tests. */
  now?: () => Date
}

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024
const DEFAULT_RING = 5000
/** Detail strings are clipped so one runaway command cannot bloat the file. */
const DETAIL_LIMIT = 2000

/** Clip a string for storage. */
export function clip(value: string, limit = DETAIL_LIMIT): string {
  return value.length <= limit ? value : `${value.slice(0, limit)}…(+${value.length - limit})`
}

/** Replace values that must never be journalled verbatim. */
export function safeDetail(value: unknown, depth = 0): unknown {
  if (typeof value === 'string') return clip(value)
  if (value === null || typeof value === 'number' || typeof value === 'boolean') return value
  if (Array.isArray(value)) return depth > 3 ? `[${value.length} items]` : value.slice(0, 20).map(item => safeDetail(item, depth + 1))
  if (typeof value === 'object') {
    if (depth > 3) return '[deep]'
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      // Bulk payloads are summarized, never stored: a base64 file write is not
      // context, it is noise, and the journal is context.
      if (key === 'dataB64' || key === 'content' || key === 'stdout' || key === 'stderr') {
        out[key] = typeof item === 'string' ? `${item.length} chars` : safeDetail(item, depth + 1)
        continue
      }
      out[key] = safeDetail(item, depth + 1)
    }
    return out
  }
  return undefined
}

/** One line describing a served request, for the journal. */
export function summarizeOp(
  op: string,
  args: Record<string, unknown>,
  outcome: { ok: boolean, ms: number, result?: Record<string, unknown>, error?: string },
): { summary: string, detail: Record<string, unknown> } {
  const bits: string[] = []
  if (op === 'exec') bits.push(String(args.cmd ?? '').split('\n')[0]?.slice(0, 120) ?? '')
  else if (op === 'caps.call') bits.push(String(args.name ?? '').slice(0, 120))
  else if (typeof args.path === 'string') bits.push(clip(args.path, 200))
  else if (typeof args.sessionId === 'string') bits.push(String(args.sessionId))
  else if (typeof args.execId === 'string') bits.push(String(args.execId))
  const target = bits.filter(part => part !== '').join(' ')
  const result = outcome.result ?? {}
  const facts: string[] = []
  if (outcome.ok) {
    if (typeof result.exit === 'number' || result.exit === null) facts.push(`exit ${String(result.exit)}`)
    if (result.cancelled === true) facts.push('cancelled')
    if (result.timedOut === true) facts.push('timed out')
    if (typeof result.reply === 'string') facts.push(`${result.reply.length} chars reply`)
    if (typeof result.count === 'number') facts.push(`${result.count} items`)
    if (typeof result.written === 'number') facts.push(`${result.written} bytes`)
    if (typeof result.sessionId === 'string') facts.push(`session ${result.sessionId}`)
    if (result.created === true) facts.push('created')
    if (result.interrupted === true) facts.push('interrupted')
  } else {
    facts.push(`FAILED ${clip(outcome.error ?? '', 160)}`)
  }
  const summary = `${op}${target === '' ? '' : ` ${target}`} → ${facts.length === 0 ? (outcome.ok ? 'ok' : 'failed') : facts.join(', ')}`
  return {
    summary: clip(summary, 400),
    detail: { args: safeDetail(args), ...(outcome.result === undefined ? {} : { result: safeDetail(outcome.result) }) },
  }
}

/** One line describing something the journal observed in a driven session. */
export function summarizeEvent(
  type: string,
  data: unknown,
): { kind: JournalKind, summary: string, detail: Record<string, unknown> } | undefined {
  const payload = (data ?? {}) as Record<string, unknown>
  if (type === 'turn/end') {
    const reason = payload.reason as { kind?: string, reason?: { kind?: string } } | undefined
    const cause = reason?.reason?.kind
    return {
      kind: reason?.kind === 'aborted' ? 'interrupt' : 'turn',
      summary: `turn ${String(payload.turn ?? '?')} ended: ${String(reason?.kind ?? 'unknown')}${cause === undefined ? '' : ` (${cause})`}`,
      detail: { reason: safeDetail(reason) },
    }
  }
  if (type === 'assistant/message') {
    const message = (payload as { message?: { content?: Array<{ type?: string, text?: string, name?: string }> } }).message
    const blocks = message?.content ?? []
    const text = blocks.filter(block => block.type === 'text').map(block => block.text ?? '').join('')
    const calls = blocks.filter(block => block.type === 'tool-call').map(block => String(block.name ?? '?')).filter(name => name !== '?')
    return {
      kind: 'model',
      summary: `model replied: ${text.length} chars${calls.length === 0 ? '' : `, tools: ${calls.slice(0, 6).join(', ')}`}`,
      detail: { text: clip(text, 800) },
    }
  }
  if (type === 'user/message') {
    const blocks = (payload.content ?? []) as Array<{ type?: string, text?: string }>
    const text = blocks.filter(block => block.type === 'text').map(block => block.text ?? '').join('')
    const source = payload.source as { kind?: string, rpcId?: unknown } | undefined
    const human = source?.kind === 'user' && typeof source.rpcId === 'string'
    return {
      kind: 'note',
      summary: `${human ? 'this machine\'s user' : 'injected'} message: ${clip(text.replace(/\s+/gu, ' '), 160)}`,
      detail: { text: clip(text, 800) },
    }
  }
  return undefined
}

/**
 * An append-only journal with an in-memory tail.
 *
 * Writes are best effort by construction: recording must never break the work it
 * records. A failed append is swallowed, and the in-memory ring still holds the
 * entry for this process.
 */
export class Journal {
  private readonly file: string
  private readonly maxBytes: number
  private readonly ringSize: number
  private readonly now: () => Date
  private ring: JournalEntry[] = []
  private next = 1
  private written = 0
  private bytes = 0

  /** @param options - file location, rotation ceiling, ring size, clock. */
  constructor(options: JournalOptions) {
    this.file = options.file
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES
    this.ringSize = options.ringSize ?? DEFAULT_RING
    this.now = options.now ?? (() => new Date())
  }

  /** Resume `seq` and `count` from the file; never throws. */
  load(): void {
    try {
      const size = statSync(this.file).size
      this.bytes = size
      const text = readFileSync(this.file, 'utf8')
      const lines = text.split('\n').filter(line => line.trim() !== '')
      for (const line of lines.slice(-this.ringSize)) {
        try {
          const entry = JSON.parse(line) as JournalEntry
          if (typeof entry?.seq === 'number') this.ring.push(entry)
        } catch {
          // A torn last line (crash mid-append) is expected; skip it.
        }
      }
      const last = this.ring.at(-1)
      this.next = (last?.seq ?? 0) + 1
      this.written = lines.length
    } catch {
      // No journal yet.
    }
  }

  /** Append one entry, assigning its seq and instant. */
  append(entry: Omit<JournalEntry, 'seq' | 'at'> & { at?: string }): JournalEntry {
    const full: JournalEntry = {
      seq: this.next,
      at: entry.at ?? this.now().toISOString(),
      ...entry,
    }
    this.next += 1
    this.written += 1
    this.ring.push(full)
    while (this.ring.length > this.ringSize) this.ring.shift()
    try {
      mkdirSync(dirname(this.file), { recursive: true })
      const line = `${JSON.stringify(full)}\n`
      if (this.bytes + line.length > this.maxBytes) this.rotate()
      appendFileSync(this.file, line, 'utf8')
      this.bytes += Buffer.byteLength(line)
    } catch {
      // Best effort: the ring still carries it for this process.
    }
    return full
  }

  /** Keep one previous file so a reader can still walk back one generation. */
  private rotate(): void {
    try {
      renameSync(this.file, `${this.file}.1`)
      writeFileSync(this.file, '', 'utf8')
      this.bytes = 0
    } catch {
      // If the rename fails the file simply keeps growing; still correct.
    }
  }

  /** Highest seq assigned so far. */
  get lastSeq(): number {
    return this.next - 1
  }

  /** Entries this process has written (including rotated-away ones). */
  get writtenCount(): number {
    return this.written
  }

  /**
   * Read entries after `fromSeq`.
   *
   * Served from the in-memory tail when possible, otherwise by scanning the file
   * (and its one rotated predecessor), so a fresh process can still answer a read
   * for history it did not write.
   *
   * @param fromSeq - exclusive lower bound; 0 means "from the beginning".
   * @param limit - maximum entries to return.
   * @param full - include `detail`.
   */
  read(fromSeq: number, limit: number, full: boolean): JournalRead {
    const start = Number.isFinite(fromSeq) && fromSeq > 0 ? Math.floor(fromSeq) : 0
    const cap = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 500) : 100
    const source = this.ring.some(entry => entry.seq > start)
      ? this.ring
      : this.readFileEntries()
    const selected = source.filter(entry => entry.seq > start).slice(0, cap)
    const entries = full ? selected : selected.map(entry => stripDetail(entry))
    return {
      fromSeq: start,
      nextSeq: entries.at(-1)?.seq ?? start,
      total: this.written,
      count: entries.length,
      entries,
    }
  }

  private readFileEntries(): JournalEntry[] {
    const out: JournalEntry[] = []
    for (const path of [`${this.file}.1`, this.file]) {
      try {
        for (const line of readFileSync(path, 'utf8').split('\n')) {
          if (line.trim() === '') continue
          try {
            const entry = JSON.parse(line) as JournalEntry
            if (typeof entry?.seq === 'number') out.push(entry)
          } catch { /* torn line */ }
        }
      } catch {
        // Absent generation.
      }
    }
    return out.sort((a, b) => a.seq - b.seq).slice(-this.ringSize)
  }
}

/** Detail is opt-in: the default read is context-sized. */
function stripDetail(entry: JournalEntry): JournalEntry {
  if (entry.detail === undefined) return entry
  const { detail: _detail, ...rest } = entry
  return rest
}

/**
 * What a reader sends back to the model: `journal.read`'s reply, or the news
 * that the peer is too old to have the op.
 */
export interface JournalView {
  entries?: Array<{ seq?: number, at?: string, kind?: string, summary?: string }>
  count?: number
  nextSeq?: number
  lastSeq?: number
  written?: number
  tail?: boolean
  /** Set by the caller when the peer answered "unknown op". */
  unsupported?: boolean
}

/**
 * Render a journal page as the lines a model should actually read.
 *
 * Kept as a pure function (and tested) because this is the whole point of the
 * journal's context economy: one line per operation, a visible cursor, and an
 * explicit statement when there is nothing new — so a model that polls it often
 * pays almost nothing and still knows where it stands.
 */
export function formatJournal(view: JournalView): string[] {
  if (view.unsupported === true) {
    return [
      '对端还没有 journal.read（需要受控端 r14+）。',
      '现在能用的替代：remote_agent_events 读某个会话的事件流，或 remote_exec 直接看文件。',
    ]
  }
  const entries = Array.isArray(view.entries) ? view.entries : []
  const lines = [
    `remote journal — 共记录 ${view.written ?? '?'} 条，本次 ${view.count ?? entries.length} 条`
    + `${view.tail === true ? '（尾部）' : ''}，游标 nextSeq=${view.nextSeq ?? '?'}`,
  ]
  if (entries.length === 0) lines.push('（没有新条目）')
  for (const entry of entries) {
    const time = typeof entry.at === 'string' ? entry.at.slice(11, 19) : '--:--:--'
    const kind = String(entry.kind ?? '?')
    lines.push(`#${entry.seq ?? '?'} ${time} ${kind.padEnd(9)} ${String(entry.summary ?? '')}`)
  }
  lines.push('下次省略 from_seq 即从这里继续；要细节加 full=true。')
  return lines
}
