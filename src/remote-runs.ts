/**
 * Background runs against the remote harness: the run registry and the four
 * model-facing control-plane tools.
 *
 * `remote_agent_prompt` blocks until the peer's turn ends, which is exactly
 * right for "one turn, one reply" — and exactly wrong for a long task the local
 * chat does not want to sit on. A background run is the same peer prompt, but
 * the tool returns as soon as the request is on the wire; the registry keeps
 * the outcome, and the model collects it later with `remote_run_status`. This
 * is the remote half of what the official subagent seam gives a local run:
 * start, inspect, append instructions, interrupt.
 *
 * Kept free of cordis and of the transport by taking a dependency facade: the
 * client supplies session resolution, the parked prompt, the peer's note op and
 * interruption; this module only owns run bookkeeping and the tool surface, so
 * it unit-tests against fake dependencies.
 *
 * @module dsh-remote/remote-runs
 */

import { randomUUID } from 'node:crypto'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import { renderRemoteReplies } from './reply-codec.ts'
import type { RemoteReply, ReplyFormat } from './reply-codec.ts'
import { inputMode } from './agent-delivery.ts'
import type { RemoteInputMode } from './agent-delivery.ts'

/** Where one background run is, from the model's point of view. */
export type RemoteRunStatus = 'running' | 'cancelling' | 'completed' | 'error' | 'aborted'

/** How one run ended: the terminal states only. */
export interface RunSettlement {
  status: 'completed' | 'error' | 'aborted'
  /** The peer's assistant reply, when it produced one. */
  reply?: string
  replies?: RemoteReply[]
  replyFormat?: ReplyFormat
  /** True when the peer's own user stopped the turn. */
  interrupted?: boolean
  /** The peer's turn reason (`completed`, `aborted`, `error`, …). */
  reason?: string | null
  /** Short failure detail, already fit to show the model. */
  diagnostic?: string
}

/** The one record the registry keeps per run. */
export interface RemoteRunRecord {
  id: string
  sessionId: string
  /** The label the caller gave (`remote_run_start.description`). */
  description: string
  /** First characters of the injected text, so a list is readable. */
  textPreview: string
  status: RemoteRunStatus
  startedAt: number
  settledAt?: number
  reply?: string
  replies?: RemoteReply[]
  replyFormat?: ReplyFormat
  interrupted?: boolean
  reason?: string | null
  diagnostic?: string
  durationMs?: number
}

/** One row of the compact list `remote_run_status` returns without an id. */
export interface RemoteRunRow {
  runId: string
  sessionId: string
  status: RemoteRunStatus
  description: string
  startedAt: number
  settledAt?: number
  replyPreview?: string
}

/** What a caller hands the registry to start one run. */
export interface RunStartInput {
  sessionId: string
  description: string
  text: string
}

/** Registry knobs. The clock and id factory are injectable for unit tests. */
export interface RunRegistryOptions {
  /** Concurrent-run ceiling, read live so a settings edit takes effect. */
  maxRuns: () => number
  /** Settled records kept at all (default 32, newest first). */
  maxSettled?: number
  /** Settled records older than this are dropped (default 24 h). */
  settledTtlMs?: number
  /** Clock override (default `Date.now`). */
  now?: () => number
  /** Run-id factory (default `run-<uuid>`). */
  makeRunId?: () => string
  /** One-line logger for settlements (default silent). */
  log?: (message: string) => void
}

/** The run registry, as the tools (and tests) use it. */
export interface RunRegistry {
  /** Register a run, enforcing the concurrency ceiling; throws a readable error. */
  start(input: RunStartInput): RemoteRunRecord
  /** Record the terminal outcome; a no-op for an already-settled run. */
  settle(id: string, outcome: RunSettlement): RemoteRunRecord | undefined
  /** Current snapshot, or undefined when unknown/pruned. */
  get(id: string): RemoteRunRecord | undefined
  /** Active runs first (newest first), then settled (newest first). */
  list(): RemoteRunRecord[]
  /** Mark a running run `cancelling`; false when it was not running. */
  cancel(id: string): boolean
  /** Drop expired surplus settled records; returns how many were dropped. */
  prune(): number
  /** Resolve when the run settles, or with its current state after `waitMs`. */
  waitFor(id: string, waitMs: number): Promise<RemoteRunRecord | undefined>
  /** Number of runs still running or cancelling. */
  activeCount(): number
}

/** Settled records kept by default. */
export const DEFAULT_MAX_SETTLED = 32
/** Settled records older than this are pruned. */
export const DEFAULT_SETTLED_TTL_MS = 24 * 60 * 60 * 1000
/** Longest `remote_run_status.wait_ms` honoured (10 minutes). */
export const MAX_STATUS_WAIT_MS = 600_000

/** True when the record still represents work on the peer. */
function isActive(record: RemoteRunRecord): boolean {
  return record.status === 'running' || record.status === 'cancelling'
}

/** One-line preview of arbitrary text. */
function previewOf(value: string, limit: number): string {
  const flat = value.replace(/\s+/gu, ' ').trim()
  if (flat.length <= limit) return flat
  return `${flat.slice(0, Math.max(0, limit - 1))}…`
}

/** Copy a record so a caller can never mutate registry state through it. */
function snapshotOf(record: RemoteRunRecord): RemoteRunRecord {
  return { ...record, ...(record.replies === undefined ? {} : { replies: structuredClone(record.replies) }) }
}

/** The compact row `remote_run_status` lists. */
export function toRunRow(record: RemoteRunRecord, previewLimit = 160): RemoteRunRow {
  const row: RemoteRunRow = {
    runId: record.id,
    sessionId: record.sessionId,
    status: record.status,
    description: record.description,
    startedAt: record.startedAt,
  }
  if (record.settledAt !== undefined) row.settledAt = record.settledAt
  if (record.reply !== undefined && record.reply !== '') {
    row.replyPreview = previewOf(record.reply, previewLimit)
  } else if (record.diagnostic !== undefined && record.diagnostic !== '') {
    row.replyPreview = previewOf(record.diagnostic, previewLimit)
  }
  return row
}

/** Clamp a requested status wait into the range the tool accepts. */
export function clampStatusWait(waitMs: number | undefined): number {
  if (waitMs === undefined || !Number.isFinite(waitMs) || waitMs <= 0) return 0
  return Math.min(MAX_STATUS_WAIT_MS, Math.floor(waitMs))
}

/**
 * Build the run registry.
 *
 * Two limits are enforced here rather than in the tools, so every entry point
 * (tool, test, future caller) sees the same ceiling and the same retention:
 * {@link RunRegistryOptions.maxRuns} concurrent runs, and at most
 * `maxSettled` finished records younger than `settledTtlMs`.
 *
 * @param options - ceiling, retention, clock and id factory.
 * @returns the registry.
 */
export function createRunRegistry(options: RunRegistryOptions): RunRegistry {
  const now = options.now ?? ((): number => Date.now())
  const maxSettled = Math.max(1, Math.floor(options.maxSettled ?? DEFAULT_MAX_SETTLED))
  const settledTtlMs = Math.max(0, Math.floor(options.settledTtlMs ?? DEFAULT_SETTLED_TTL_MS))
  const makeRunId = options.makeRunId ?? ((): string => `run-${randomUUID()}`)
  const records = new Map<string, RemoteRunRecord>()
  const waiters = new Map<string, Set<(record: RemoteRunRecord) => void>>()

  /** Drop settled records past the TTL, then past the count limit (oldest first). */
  const prune = (at: number): number => {
    let dropped = 0
    const settled: RemoteRunRecord[] = []
    for (const record of records.values()) {
      if (isActive(record)) continue
      if (record.settledAt !== undefined && at - record.settledAt > settledTtlMs) {
        records.delete(record.id)
        dropped += 1
        continue
      }
      settled.push(record)
    }
    settled.sort((left, right) => (left.settledAt ?? left.startedAt) - (right.settledAt ?? right.startedAt))
    while (settled.length > maxSettled) {
      const oldest = settled.shift()
      if (oldest === undefined) break
      records.delete(oldest.id)
      dropped += 1
    }
    return dropped
  }

  /** Wake every caller parked on this run's outcome. */
  const wake = (id: string): void => {
    const parked = waiters.get(id)
    if (parked === undefined) return
    const record = records.get(id)
    waiters.delete(id)
    if (record === undefined) return
    for (const resolve of [...parked]) resolve(snapshotOf(record))
  }

  const get = (id: string): RemoteRunRecord | undefined => {
    prune(now())
    const record = records.get(id)
    return record === undefined ? undefined : snapshotOf(record)
  }

  const list = (): RemoteRunRecord[] => {
    prune(now())
    const active: RemoteRunRecord[] = []
    const settled: RemoteRunRecord[] = []
    for (const record of records.values()) {
      if (isActive(record)) active.push(record)
      else settled.push(record)
    }
    active.sort((left, right) => right.startedAt - left.startedAt)
    settled.sort((left, right) => (right.settledAt ?? right.startedAt) - (left.settledAt ?? left.startedAt))
    return [...active, ...settled].map(snapshotOf)
  }

  const activeCount = (): number => {
    let count = 0
    for (const record of records.values()) if (isActive(record)) count += 1
    return count
  }

  const start = (input: RunStartInput): RemoteRunRecord => {
    const at = now()
    prune(at)
    const ceiling = Math.max(1, Math.floor(options.maxRuns()))
    const active = activeCount()
    if (active >= ceiling) {
      throw new Error(
        `remote_run_start: 已有 ${active} 个后台远端运行（上限 ${ceiling}），`
        + '先 remote_run_status 收一个，或调大 maxBackgroundRuns。',
      )
    }
    const sessionId = input.sessionId.trim()
    if (sessionId === '') throw new Error('remote_run_start: sessionId must not be empty')
    if (input.description.trim() === '') throw new Error('remote_run_start: description must not be empty')
    const record: RemoteRunRecord = {
      id: makeRunId(),
      sessionId,
      description: input.description.trim(),
      textPreview: previewOf(input.text, 120),
      status: 'running',
      startedAt: at,
    }
    records.set(record.id, record)
    return snapshotOf(record)
  }

  const settle = (id: string, outcome: RunSettlement): RemoteRunRecord | undefined => {
    const record = records.get(id)
    if (record === undefined || !isActive(record)) return undefined
    const at = now()
    record.status = outcome.status
    record.settledAt = at
    record.durationMs = Math.max(0, at - record.startedAt)
    if (outcome.reply !== undefined) record.reply = outcome.reply
    if (outcome.replies !== undefined) record.replies = structuredClone(outcome.replies)
    if (outcome.replyFormat !== undefined) record.replyFormat = outcome.replyFormat
    if (outcome.interrupted !== undefined) record.interrupted = outcome.interrupted
    if (outcome.reason !== undefined) record.reason = outcome.reason
    if (outcome.diagnostic !== undefined) record.diagnostic = outcome.diagnostic
    options.log?.(
      `dsh-remote-client: background run ${id} ${record.status} `
      + `(session ${record.sessionId}, ${record.durationMs} ms)`,
    )
    wake(id)
    prune(at)
    return snapshotOf(record)
  }

  const cancel = (id: string): boolean => {
    const record = records.get(id)
    if (record === undefined || record.status !== 'running') return false
    record.status = 'cancelling'
    return true
  }

  const waitFor = (id: string, waitMs: number): Promise<RemoteRunRecord | undefined> => {
    const current = get(id)
    if (current === undefined || !isActive(current) || waitMs <= 0) return Promise.resolve(current)
    return new Promise<RemoteRunRecord | undefined>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | undefined
      const done = (record: RemoteRunRecord): void => {
        if (timer !== undefined) clearTimeout(timer)
        const parked = waiters.get(id)
        parked?.delete(done)
        if (parked !== undefined && parked.size === 0) waiters.delete(id)
        resolve(record)
      }
      const parked = waiters.get(id) ?? new Set<(record: RemoteRunRecord) => void>()
      parked.add(done)
      waiters.set(id, parked)
      timer = setTimeout(() => {
        timer = undefined
        // A wait that times out is not an error: report the state as it is.
        done(get(id) ?? current)
      }, Math.floor(waitMs))
    })
  }

  return {
    start,
    settle,
    get,
    list,
    cancel,
    prune: () => prune(now()),
    waitFor,
    activeCount,
  }
}

// ---------------------------------------------------------------------------
// The model-facing control plane
// ---------------------------------------------------------------------------

/** What a run-start hands the client so it can park the peer prompt. */
export interface RunPromptRequest {
  runId: string
  sessionId: string
  text: string
  /** Peer-side turn deadline; 0 means "wait as long as the turn takes". */
  timeoutMs: number
  /** The local tool call's cancellation (a local Stop). */
  signal?: AbortSignal
  /** Called when the run is asked to stop but has not settled yet. */
  onCancelling(): void
  /** Called exactly once, when the peer's turn reached a terminal outcome. */
  onSettled(outcome: RunSettlement): void
}

/** Everything the tools need from the client, kept deliberately thin. */
export interface RunToolDeps {
  /**
   * Resolve the conversation a call targets, using the very same policy as
   * `remote_agent_prompt`: explicit id wins, otherwise the calling chat's
   * remembered/anchor conversation.
   */
  resolveSession(args: { session_id?: string }, exec: unknown): Promise<{ sessionId: string, origin: string }>
  /** Put one prompt on the wire and return; settlement arrives via callbacks. */
  startPrompt(request: RunPromptRequest): void
  /** Inject a user message without waiting for the peer's turn. */
  sendMessage(request: { sessionId: string, text: string, mode?: RemoteInputMode, signal?: AbortSignal }): Promise<{
    accepted: boolean
    method?: string
    mode?: 'queue' | 'steer'
    processing?: string
    note?: string
  }>
  /** Stop the peer's current turn through its own plugin surface. */
  interrupt(sessionId: string): Promise<void>
  /** Record which conversation a scope now continues (same memory as the prompt tool). */
  rememberScope(exec: unknown, sessionId: string): void
  /** One-line logger. */
  log(message: string): void
  /** Concurrent-run ceiling, read live from the volatile config. */
  maxRuns(): number
  /** Clock override for tests. */
  now?(): number
  /** Run-id factory for tests. */
  makeRunId?(): string
}

/** Render text the way every tool in this plugin does. */
function renderText(value: string): Array<{ type: 'text', text: string }> {
  return [{ type: 'text', text: value }]
}

/** Validate/trim a string parameter, treating blank as absent. */
function clean(value: string | undefined): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed === '' ? undefined : trimmed
}

/** A run id parsed out of a tool argument. */
function runIdOf(args: { run_id?: string }): string | undefined {
  return clean(args.run_id)
}

/**
 * Build the four control-plane tools over one client facade.
 *
 * The registry is created here, so every tool shares one view of the runs, and
 * the client only has to supply the transport-facing callbacks.
 *
 * @param deps - session resolution, prompt/note/interrupt wiring, logging.
 * @returns the tools to append to the plugin's tool array.
 */
export function createRunTools(deps: RunToolDeps): ToolDefinition[] {
  const registry = createRunRegistry({
    maxRuns: deps.maxRuns,
    log: deps.log,
    ...(deps.now === undefined ? {} : { now: deps.now }),
    ...(deps.makeRunId === undefined ? {} : { makeRunId: deps.makeRunId }),
  })

  const runStart = defineTool({
    name: 'remote_run_start',
    description:
      '在**远端 harness 后台**启动一个任务：立即返回 runId，不阻塞本轮；'
      + '适合跑得久、或本机不需要一直等着的远端工作。\n'
      + '会话规则与 `remote_agent_prompt` **完全一致**：省略 session_id 时续接本 chat 自己那段远端对话，'
      + '所以不要为了「隔离」传 session_id。\n'
      + '与 `subagent_remote` 的分工：要**交付进本对话**、值得等待结果的整块子任务用 subagent_remote；'
      + '长任务 / 想并行推进 / 不想占用本轮的用 remote_run_start。\n'
      + '取结果用 `remote_run_status(run_id=...)`（可带 wait_ms 等待），'
      + '追加指示用 `remote_send_message(run_id=...)`，打断用 `remote_run_cancel(run_id=...)`。',
    parameters: {
      description: { type: 'string', required: true, description: '这次后台运行的简短标题（3-5 个词）。' },
      text: { type: 'string', required: true, description: '交给对端 agent 的用户发言 / 任务描述。' },
      session_id: { type: 'string', description: '对端会话 id。一般**不要传**：省略即复用本 chat 自己那一个对话。' },
      timeout_ms: { type: 'number', description: '对端这一轮的超时毫秒数；0（默认）= 不限。' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => {
        const v = value as unknown as {
          runId: string, sessionId: string, origin?: string, status: string,
        }
        return renderText([
          `已启动后台远端运行 ${v.runId}`,
          `session: ${v.sessionId}${v.origin === undefined ? '' : `  (${v.origin})`}`,
          'status : running（本轮不必等它）',
          `取结果：remote_run_status(run_id="${v.runId}")`,
          '追加指示：remote_send_message；打断：remote_run_cancel。',
        ].join('\n'))
      },
    },
    async execute(
      args: { description: string, text: string, session_id?: string, timeout_ms?: number },
      exec?: { agent?: { session?: { id?: unknown } }, signal?: AbortSignal },
    ): Promise<JsonValue> {
      const description = clean(args.description)
      if (description === undefined) throw new Error('remote_run_start: description must not be empty')
      if (clean(args.text) === undefined) throw new Error('remote_run_start: text must not be empty')
      const explicit = clean(args.session_id)
      const resolved = await deps.resolveSession(
        explicit === undefined ? {} : { session_id: explicit },
        exec,
      )
      const record = registry.start({
        sessionId: resolved.sessionId,
        description,
        text: args.text,
      })
      const timeoutMs = typeof args.timeout_ms === 'number' && Number.isFinite(args.timeout_ms) && args.timeout_ms > 0
        ? Math.floor(args.timeout_ms)
        : 0
      try {
        deps.startPrompt({
          runId: record.id,
          sessionId: record.sessionId,
          text: args.text,
          timeoutMs,
          ...(exec?.signal === undefined ? {} : { signal: exec.signal }),
          onCancelling: () => { registry.cancel(record.id) },
          onSettled: (outcome) => { registry.settle(record.id, outcome) },
        })
      } catch (error) {
        registry.settle(record.id, {
          status: 'error',
          diagnostic: error instanceof Error ? error.message : String(error),
        })
        throw error
      }
      deps.rememberScope(exec, record.sessionId)
      return {
        runId: record.id,
        sessionId: record.sessionId,
        origin: resolved.origin,
        status: 'running',
      } as unknown as JsonValue
    },
  })

  const runStatus = defineTool({
    name: 'remote_run_status',
    description:
      '查后台远端运行：无 run_id 时返回最近的运行列表（先 running 后已结束）；'
      + '有 run_id 时返回该运行的完整状态（含 reply 全文 / 错误信息 / interrupted / reason）。'
      + 'wait_ms>0 时最多等这么久（上限 600000）；到点仍在运行就返回 status:"running"，不报错。'
      + '**结果不会自动注入本对话**——必须由你调用本工具取回。',
    parameters: {
      run_id: { type: 'string', description: 'remote_run_start 返回的 runId；省略则列出最近运行。' },
      wait_ms: { type: 'number', description: '最多等待多少毫秒（0..600000）；仅在有 run_id 时生效。' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => {
        const v = value as unknown as {
          runId?: string
          runs?: RemoteRunRow[]
          running?: number
          settled?: number
          status?: string
          sessionId?: string
          description?: string
          startedAt?: number
          settledAt?: number
          durationMs?: number
          reply?: string
          replies?: RemoteReply[]
          replyFormat?: ReplyFormat
          interrupted?: boolean
          reason?: string | null
          diagnostic?: string
        }
        if (Array.isArray(v.runs)) {
          if (v.runs.length === 0) {
            return renderText('（没有后台远端运行）用 remote_run_start 启动一个。')
          }
          const lines = [
            `后台远端运行：${v.running ?? 0} 个进行中，${v.settled ?? 0} 个已结束`,
          ]
          for (const row of v.runs) {
            const mark = row.status === 'running'
              ? '▶'
              : row.status === 'cancelling' ? '⏹' : row.status === 'completed' ? '✔' : '✖'
            const elapsed = row.settledAt === undefined
              ? '（进行中）'
              : `${Math.max(0, row.settledAt - row.startedAt)} ms`
            lines.push(`${mark} ${row.runId}  [${row.status}]  ${row.sessionId}  ${row.description}  ${elapsed}`)
            if (row.replyPreview !== undefined && row.replyPreview !== '') lines.push(`    ${row.replyPreview}`)
          }
          lines.push('用 remote_run_status(run_id="...") 取完整交付；remote_run_cancel 打断；remote_send_message 追加指示。')
          return renderText(lines.join('\n'))
        }
        const head = [
          `run    : ${v.runId ?? '?'}`,
          `session: ${v.sessionId ?? '?'}`,
          `status : ${v.status ?? '?'}${v.interrupted === true ? '  (interrupted)' : ''}`
          + `${v.durationMs === undefined ? '' : `   ${v.durationMs} ms`}`,
          `title  : ${v.description ?? ''}`,
        ]
        if (v.reason !== undefined && v.reason !== null && v.reason !== '') head.push(`reason : ${v.reason}`)
        if (v.diagnostic !== undefined && v.diagnostic !== '') head.push(`error  : ${v.diagnostic}`)
        if (v.status === 'running' || v.status === 'cancelling') {
          head.push('（仍在运行；可用 remote_run_status(run_id, wait_ms) 等待，或 remote_run_cancel 打断）')
          return renderText(head.join('\n'))
        }
        if (v.interrupted === true) {
          head.push('⚠️ 这一轮在远端被用户打断，没有可用的交付。不要重试、不要自动继续，把状态交给用户。')
        }
        head.push(renderRemoteReplies(value))
        return renderText(head.join('\n'))
      },
    },
    async execute(args: { run_id?: string, wait_ms?: number }): Promise<JsonValue> {
      const runId = runIdOf(args)
      if (runId === undefined) {
        const all = registry.list()
        const running = all.filter(record => isActive(record)).length
        return {
          runs: all.map(record => toRunRow(record)),
          running,
          settled: all.length - running,
          maxRuns: deps.maxRuns(),
        } as unknown as JsonValue
      }
      const wait = clampStatusWait(args.wait_ms)
      const record = wait > 0
        ? await registry.waitFor(runId, wait)
        : registry.get(runId)
      if (record === undefined) {
        throw new Error(
          `remote_run_status: 没有 id 为 "${runId}" 的后台远端运行`
          + '（可能已结算并被清理，或 id 写错了）。不带 run_id 可列出最近的运行。',
        )
      }
      // The record's own field is `id`; the render and the model read `runId`.
      return { ...record, runId: record.id } as unknown as JsonValue
    },
  })

  const runCancel = defineTool({
    name: 'remote_run_cancel',
    description:
      '打断一个后台远端运行当前正在跑的轮次：对它的远端会话调 `agent.interrupt`，'
      + '把运行标记为 cancelling 并立即返回（不等待结算）。'
      + '之后用 remote_run_status 查看最终状态；已结束的运行不会被再次打断。',
    parameters: {
      run_id: { type: 'string', required: true, description: 'remote_run_start 返回的 runId。' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => {
        const v = value as unknown as {
          cancelled: boolean, runId: string, sessionId?: string, status?: string,
        }
        if (v.cancelled) {
          return renderText(
            `已请求取消 ${v.runId}（session ${v.sessionId ?? '?'}）；`
            + '用 remote_run_status 查看结算，不要立即重试同一个任务。',
          )
        }
        return renderText(`${v.runId} 当前状态是 ${v.status ?? '?'}，没有需要取消的运行。`)
      },
    },
    async execute(args: { run_id: string }): Promise<JsonValue> {
      const runId = runIdOf(args)
      if (runId === undefined) throw new Error('remote_run_cancel: run_id must not be empty')
      const record = registry.get(runId)
      if (record === undefined) {
        throw new Error(`remote_run_cancel: 没有 id 为 "${runId}" 的后台远端运行`)
      }
      if (!registry.cancel(runId)) {
        return { cancelled: false, runId, sessionId: record.sessionId, status: record.status } as unknown as JsonValue
      }
      // Best effort: the cancel tool returns at once, and a peer that is already
      // gone must not turn "cancel" into a wait.
      void deps.interrupt(record.sessionId).catch((error: unknown) => {
        deps.log(
          `dsh-remote-client: could not interrupt ${record.sessionId} for ${runId} `
          + `(${error instanceof Error ? error.message : String(error)})`,
        )
      })
      return { cancelled: true, runId, sessionId: record.sessionId, status: 'cancelling' } as unknown as JsonValue
    },
  })

  const sendMessage = defineTool({
    name: 'remote_send_message',
    description:
      '给**正在跑的远端任务追加指示**，或给空闲的远端会话发一条新消息；'
      + '与 `remote_agent_prompt` 的区别是**不阻塞等交付**：消息塞进对端的收件箱就返回，'
      + '默认在忙时送到下一步、闲时开始新轮；mode可显式排下一轮或steer当前轮。\n'
      + '定位会话的优先级：run_id（该运行所用的远端会话）→ session_id → 本 chat 自己那段远端对话。'
      + '多条不同指示可以连续发，但前提是真有必要；不要用它重复 `remote_agent_prompt` 已经发过的任务。',
    parameters: {
      message: { type: 'string', required: true, description: '要追加给对端 agent 的用户消息。' },
      session_id: { type: 'string', description: '对端会话 id。省略则用本 chat 自己的远端对话。' },
      run_id: { type: 'string', description: '后台运行的 runId；给了就发给该运行所用的会话。' },
      mode: { type: 'string', enum: ['queue', 'steer', 'auto'], description: 'auto（默认）忙时steer、闲时queue；queue下一轮，steer下一已准入step。旧peer不支持显式steer则拒绝。' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => {
        const v = value as unknown as {
          sessionId: string, accepted?: boolean, method?: string, mode?: string, processing?: string, note?: string,
        }
        const lines = [
          `已向远端会话 ${v.sessionId} 追加消息（method: ${v.method ?? '?'}; mode: ${v.mode ?? '?'}; processing: ${v.processing ?? '?'}）`,
        ]
        if (v.note !== undefined && v.note !== '') lines.push(v.note)
        lines.push('用 remote_run_status / remote_agent_prompt 查看对端如何消化这条消息。')
        return renderText(lines.join('\n'))
      },
    },
    async execute(
      args: { message: string, session_id?: string, run_id?: string, mode?: RemoteInputMode },
      exec?: { agent?: { session?: { id?: unknown } }, signal?: AbortSignal },
    ): Promise<JsonValue> {
      const message = clean(args.message)
      if (message === undefined) throw new Error('remote_send_message: message must not be empty')
      const runId = runIdOf(args)
      let sessionId: string
      if (runId !== undefined) {
        const record = registry.get(runId)
        if (record === undefined) {
          throw new Error(`remote_send_message: 没有 id 为 "${runId}" 的后台远端运行`)
        }
        sessionId = record.sessionId
      } else {
        const explicit = clean(args.session_id)
        const resolved = await deps.resolveSession(
          explicit === undefined ? {} : { session_id: explicit },
          exec,
        )
        sessionId = resolved.sessionId
      }
      // Map BEFORE sending: an asynchronous note can produce its first frame
      // before this tool call's own acceptance reply returns. A note is a
      // deliberate association from this local chat to that remote conversation.
      deps.rememberScope(exec, sessionId)
      const result = await deps.sendMessage({
        sessionId,
        text: message,
        mode: inputMode(args.mode),
        ...(exec?.signal === undefined ? {} : { signal: exec.signal }),
      })
      return {
        sessionId,
        accepted: result.accepted !== false,
        ...(result.method === undefined ? {} : { method: result.method }),
        ...(result.mode === undefined ? {} : { mode: result.mode }),
        ...(result.processing === undefined ? {} : { processing: result.processing }),
        ...(result.note === undefined ? {} : { note: result.note }),
        ...(runId === undefined ? {} : { runId }),
      } as unknown as JsonValue
    },
  })

  return [runStart, runStatus, runCancel, sendMessage]
}
