/**
 * 多 peer 的**前端 worker 池**：一条会话一个 peer，一次派发并行跑。
 *
 * ## 它与单 peer 主路径的关系
 *
 * `client.ts` 的主路径是“一个 chat ⇄ 一个远端对话”，面向单个默认 peer。worker
 * 池是它的多 peer 版本：部署在 `peers` 里声明了几个 peer，就有几个远端 worker，
 * 每个 peer 拥有**自己的一段确定性会话**，同一个 chat 反复派发时各自续接。
 *
 * ## 会话 id
 *
 * 严格沿用仓库的会话规则，只是把 peer 名并入 seed：
 *
 * ```text
 * seed = `${peer}\u0000${localSessionId ?? ''}`
 * id   = anchorSessionId(prefix, seed)        // = `${prefix}-${sha256(seed).slice(0,12)}`
 * ```
 *
 * seed 里必须有 peer 名，否则同一 chat 在两个 peer 上会拿到**同一个 id 字符串**
 * ——功能上不冲突（id 只在对端本地解析），但日志、看板、排障会彻底混淆。
 * 具体实现见 {@link peerSessionId}。
 *
 * ## 生命周期
 *
 * - 只有 `remote_workers` / `remote_worker_prompt` / `remote_pool_dispatch` 三个
 *   模型可见工具，没有后台 run（那是 `remote-runs.ts` 的职责）。
 * - `remote_pool_dispatch` 是**并行前台**：`Promise.allSettled` 等所有 worker
 *   结束后返回；单个 worker 失败只出现在它自己的结果行里，不抛错。
 * - 取消：`exec.signal` 一响，对**所有在途 worker** 尽力发 `agent.interrupt`，
 *   已发出的请求不重试，整体以 `AbortError` 结束（与仓库既有取消语义一致）。
 *
 * ## 依赖注入
 *
 * 本模块不 import cordis、不碰 `client.ts`：peer 声明、链接、本机 chat id、日志、
 * Team 记账全部由接线方通过 {@link PoolDeps} 注入，因此纯逻辑可以单测。
 *
 * @module dsh-remote/remote-pool
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'

import { abortError, raceAbort } from './async.ts'
import { LinkClient } from './link.ts'
import type { EndpointConfig } from './link.ts'
import { assertPeerOperation, levelName, normalizePermission } from './peers.ts'
import { anchorSessionId } from './reuse.ts'
import type { TeamAgent, TeamTaskHooks, TeamTaskToken } from './remote-team.ts'
import { renderRemoteReplies, replyFields } from './reply-codec.ts'
import type { RemoteReply, ReplyFormat } from './reply-codec.ts'

/**
 * 一个 peer 的声明，结构上是 `peers.ts` 的 `PeerProfile` 加显式名字。
 *
 * `name` 与 `Record` 的键重复是有意的：键是查找路径，`name` 是展示/日志路径，
 * 接线方把现有声明映射进来时补上即可。
 */
export interface PoolPeerProfile {
  /** peer 名（与 `peers()` 返回对象的键一致）。 */
  name: string
  /** 对端地址；未配置时远端请求会给出可读错误。 */
  host?: string
  /** 对端端口。 */
  port?: number
  /** Optional node reached through this installation's mesh connection. */
  relayTarget?: string
  /** 内联 X25519 私钥。 */
  privateKey?: string
  /** 私钥文件。 */
  privateKeyFile?: string
  /** 没有密钥时是否自动生成。 */
  autoGenerateKey?: boolean
  /** 内联 pin 的对端公钥。 */
  peerPublicKey?: string
  /** 对端公钥文件。 */
  peerPublicKeyFile?: string
  /** 单请求超时毫秒数。 */
  timeoutMs?: number
  /** 显式允许旧握手；默认拒绝自动降级。 */
  allowLegacyHandshake?: boolean
  /** 已鉴权连接最长生命周期（毫秒）。 */
  maxSessionMs?: number
  /** 权限上限 `1 < 2 < 3`；缺省按 `normalizePermission` 视为只读。 */
  maxPermission?: number
  /** level 2 的写入边界。 */
  workspaceRoot?: string
}

/**
 * 一条 peer 链接里本模块用到的部分（`LinkClient` 结构上满足它）。
 *
 * 只声明需要的成员，测试可以注入一个纯假对象，接线方也可以换成任何复用连接的实现。
 */
export interface PoolLink {
  /** 发一个请求；`args` 是线上参数对象。 */
  request(
    op: string,
    args: Record<string, unknown>,
    timeoutMs?: number,
  ): Promise<Record<string, unknown>>
  /** 关闭链接。 */
  close(): void
  /** 当前是否认为连接仍然活着。 */
  readonly connected: boolean
}

/** {@link createPoolTools} 的注入面。 */
export interface PoolDeps {
  /** 当前部署声明的 peers（含单 peer legacy 名字）。 */
  peers(): Record<string, PoolPeerProfile>
  /** 会话前缀，默认 `remote`。 */
  prefix(): string
  /** 从工具 `exec` 取本机 chat id（没有时返回 undefined）。 */
  localSessionOf(exec: unknown): string | undefined
  /**
   * 取某个 peer 的链接。
   *
   * **每个 peer 复用同一个对象**：接线方负责按 peer 缓存 `LinkClient`，不要每次
   * 新建（否则每次调用都要重新握手）。同步返回，首次 `request` 时才拨号。
   */
  linkFor(peer: string): PoolLink
  /** 一行日志。 */
  log(message: string): void
  /** 可选：Agent Teams 记账 hooks（来自 `./remote-team.ts`）。 */
  teamTask?: TeamTaskHooks
}

/** 每次派发最多几个 worker。超过就报错，绝不静默截断。 */
export const MAX_POOL_WORKERS = 8

/** `remote_workers` 的工具名。 */
export const REMOTE_WORKERS_TOOL = 'remote_workers'

/** `remote_worker_prompt` 的工具名。 */
export const REMOTE_WORKER_PROMPT_TOOL = 'remote_worker_prompt'

/** `remote_pool_dispatch` 的工具名。 */
export const REMOTE_POOL_DISPATCH_TOOL = 'remote_pool_dispatch'

/** `remote_team_dispatch` 的工具名。 */
export const REMOTE_TEAM_DISPATCH_TOOL = 'remote_team_dispatch'

/** 一个 worker 的执行结果（也是工具返回数组的元素）。 */
export interface PoolWorkerResult {
  /** peer 名。 */
  peer: string
  /** 这个 peer 在本 chat 上的确定性会话 id。 */
  sessionId: string
  /** 是否拿到了可用的交付。 */
  ok: boolean
  /** 对端的 assistant 回复（没有则为空串）。 */
  reply: string
  replies?: RemoteReply[]
  replyFormat?: ReplyFormat
  /** 这一轮怎么结束的：`completed` / `aborted` / `error` / 对端自报的原因。 */
  stopReason: string
  /** 耗时毫秒数。 */
  durationMs: number
  /** 对端用户打断了这一轮。 */
  interrupted?: boolean
  /** 本机取消导致这次 worker 提前结束。 */
  aborted?: boolean
  /** 失败原因（请求失败、权限拒绝、对端 turn error 等）。 */
  error?: string
}

/** 一次派发的聚合摘要。 */
export interface PoolDispatchSummary {
  /** worker 总数。 */
  total: number
  /** 成功的 worker 数。 */
  ok: number
  /** 失败的 worker 数。 */
  failed: number
}

/** 错误 → 一行文本。 */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** 取消错误（名字必须是 `AbortError`，工具运行时据此识别取消）。 */
function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError'
}

/** 一个永远不会 abort 的信号，供没有 `exec.signal` 的调用方使用。 */
const NEVER_ABORT = new AbortController().signal

/** 渲染成模型可读的文本块。 */
function renderText(text: string): Array<{ type: 'text', text: string }> {
  return [{ type: 'text', text }]
}

/** 单行摘要：折叠换行并截断。 */
function excerpt(value: string, max = 100): string {
  const flat = value.replace(/\s+/gu, ' ').trim()
  if (flat === '') return '(empty)'
  return flat.length <= max ? flat : `${flat.slice(0, Math.max(0, max - 1))}…`
}

/** 取一段文本的首个非空行，用作任务标题。 */
function firstLine(value: string): string {
  for (const line of value.split(/\r?\n/u)) {
    const trimmed = line.trim()
    if (trimmed !== '') return trimmed
  }
  return ''
}

/**
 * 一个 chat 在某个 peer 上的**确定性**远端会话 id。
 *
 * 纯函数：同样的 `(prefix, peer, localSessionId)` 永远得到同一个 id，不同 peer
 * 一定得到不同 id（peer 名在 seed 里），没有本机 chat 时也按 peer 区分。
 *
 * @param prefix - 会话 id 家族（空串按 `remote` 处理）。
 * @param peer - peer 名（空串按 `peer` 处理）。
 * @param localSessionId - 本机 chat id；工具调用没有 agent 时为 undefined。
 * @returns `<prefix>-<12 位 sha256>` 形式的远端会话 id。
 */
export function peerSessionId(
  prefix: string,
  peer: string,
  localSessionId: string | undefined,
): string {
  const family = typeof prefix === 'string' && prefix.trim() !== '' ? prefix.trim() : 'remote'
  const name = typeof peer === 'string' && peer.trim() !== '' ? peer.trim() : 'peer'
  const local = typeof localSessionId === 'string' ? localSessionId : ''
  // 分隔符用 NUL，避免 peer 名与 chat id 拼接产生歧义（`a`+`bc` vs `ab`+`c`）。
  return anchorSessionId(family, `${name}\u0000${local}`)
}

/**
 * 校验并排列本次要用的 peer 名。
 *
 * 纯函数，不依赖 cordis；所有拒绝都是可读的 `Error`：
 *
 * - 省略 `requested`：返回全部已声明的 peer（声明顺序）；一个都没有时报错。
 * - 给了 `requested`：保持调用方顺序；未知名字、重复名字、空名字都报错。
 * - 显式给空数组也报错（省略表示“全部”，`[]` 几乎总是模型笔误）。
 *
 * @param peers - 当前部署声明的 peers（只用到键）。
 * @param requested - 调用方点名要的 peer；undefined 表示全部。
 * @returns 去重校验后的 peer 名列表（保持声明顺序或调用方顺序）。
 * @throws Error 当列表非法（未声明 / 重复 / 为空）。
 */
export function orderedPeerNames(
  peers: Record<string, unknown>,
  requested?: readonly string[],
): string[] {
  const declared = Object.keys(peers)

  if (requested === undefined) {
    if (declared.length === 0) {
      throw new Error(
        '没有声明任何 peer：先在 dsh-remote-client 的 `peers` 里声明至少一个 peer '
        + '（或配置单 peer 的 host/port）。',
      )
    }
    return declared
  }

  if (requested.length === 0) {
    throw new Error('peers 为空：请至少给一个 peer 名；省略 peers 表示使用全部已声明的 peer。')
  }

  const seen = new Set<string>()
  const ordered: string[] = []
  for (const raw of requested) {
    const name = typeof raw === 'string' ? raw.trim() : ''
    if (name === '') throw new Error('peers 里有空名字：每个 peer 名都必须非空。')
    if (seen.has(name)) {
      throw new Error(`peer "${name}" 在 peers 里重复了：每个 peer 只能出现一次。`)
    }
    if (!Object.hasOwn(peers, name)) {
      throw new Error(
        `未知 peer "${name}"：`
        + (declared.length === 0
          ? '当前没有声明任何 peer。'
          : `已声明的 peer 是 ${declared.join(', ')}。`),
      )
    }
    seen.add(name)
    ordered.push(name)
  }
  return ordered
}

/** 当前前缀，空串按 `remote`。 */
function normalizedPrefix(deps: PoolDeps): string {
  const value = deps.prefix()
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : 'remote'
}

/** 取一个确定已声明的 peer 的声明；调用前应已通过 {@link orderedPeerNames} 校验。 */
function profileOf(peers: Record<string, PoolPeerProfile>, name: string): PoolPeerProfile {
  const profile = peers[name]
  if (profile === undefined) {
    throw new Error(`未知 peer "${name}"：它不在当前声明的 peers 里。`)
  }
  return profile
}

/** 从工具 `exec` 里取调用方 agent（Agent Teams 记账用）。 */
function teamAgentOf(exec: unknown): TeamAgent | undefined {
  const agent = (exec as { agent?: unknown } | undefined)?.agent
  if (agent === undefined || agent === null || typeof agent !== 'object') return undefined
  return agent as TeamAgent
}

/** 逐 worker 的结果正文：写进看板任务描述。 */
function summaryTextOf(workers: readonly PoolWorkerResult[]): string {
  const lines: string[] = []
  for (const worker of workers) {
    if (worker.ok) {
      lines.push(`${worker.peer}: 成功（${worker.durationMs} ms）— ${excerpt(worker.reply, 160)}`)
      continue
    }
    const reason = worker.error ?? (worker.interrupted === true ? '被远端用户打断' : '未知错误')
    lines.push(`${worker.peer}: 失败 — ${reason}`)
  }
  return lines.join('\n')
}

/** 派发任务的标题：优先用调用方给的 description，否则用 prompt 首行。 */
function dispatchSubject(description: string, prompt: string): string {
  const fromDescription = description.trim()
  if (fromDescription !== '') return fromDescription
  const fromPrompt = firstLine(prompt)
  return fromPrompt === '' ? '远端 worker 池并行派发' : fromPrompt
}

/** 派发任务的描述：任务目标 + 参与 peer 列表 + 原始 prompt。 */
function dispatchTaskDescription(
  description: string,
  prompt: string,
  peers: readonly string[],
): string {
  const parts: string[] = []
  const trimmed = description.trim()
  if (trimmed !== '') parts.push(`说明: ${trimmed}`)
  parts.push(`参与 peer（${peers.length}）: ${peers.join(', ')}`)
  parts.push(`prompt:\n${prompt}`)
  return parts.join('\n\n')
}

/**
 * 建三个模型可见工具：`remote_workers`、`remote_worker_prompt`、
 * `remote_pool_dispatch`。
 *
 * 工具永远注册（单 peer 部署也能拿到可读提示），只有部署声明了多个 peer 时才
 * 真正发挥作用。所有 peer 名/会话 id/权限判定都在执行时读取 `deps`，所以配置
 * 热更新后不需要重新注册。
 *
 * @param deps - peer 声明、按 peer 缓存的链接、本机 chat 定位、日志与 Team hooks。
 * @returns 三个 `defineTool` 定义，接线方在 `ctx.inject(['tools'], ...)` 里注册。
 */
export function createPoolTools(deps: PoolDeps): Array<ToolDefinition> {
  /**
   * 尽力中断一个 peer 上的远端轮次。
   *
   * 从不 await、从不抛错：本机取消已经发生，中断是“尽量让对端也停下来”的
   * 附带动作，不能拖慢本地 settle。短超时（10s）避免链接已断时长期挂起。
   */
  const interruptWorker = (link: PoolLink, peer: string, sessionId: string): void => {
    void link.request('agent.interrupt', { sessionId }, 10_000)
      .then(() => {
        deps.log(`dsh-remote-pool: 已向 peer "${peer}" 发送 agent.interrupt（${sessionId}）`)
      })
      .catch((error: unknown) => {
        deps.log(
          `dsh-remote-pool: 中断 peer "${peer}" 上的 ${sessionId} 失败（${messageOf(error)}）`,
        )
      })
  }

  /**
   * 用与单 peer 主路径完全相同的栅栏检查权限。
   *
   * 失败信息（`FS_PERMISSION_DENIED` + 两边等级）与 `client.ts` 一致，模型看到的
   * 解释不会因为走 worker 池而变样。
   */
  const assertCanPrompt = (peer: string, profile: PoolPeerProfile): void => {
    assertPeerOperation(normalizePermission(profile.maxPermission), 'agent.prompt', {
      peer,
      path: undefined,
      workspaceRoot: typeof profile.workspaceRoot === 'string' ? profile.workspaceRoot : '',
    })
  }

  /** 一次 worker 的执行输入。 */
  interface WorkerTask {
    peer: string
    profile: PoolPeerProfile
    link: PoolLink
    sessionId: string
    text: string
    signal: AbortSignal | undefined
  }

  /**
   * 在一个 peer 的确定性会话上跑一次前台 prompt。
   *
   * 永不抛错（取消除外——取消以 `aborted: true` 的结果返回，由 dispatch 统一
   * 决定抛 `AbortError`）：worker 的失败是数据，不是工具的失败。
   *
   * 取消路径：signal 一响就对**这个** worker 发 `agent.interrupt`，同时
   * `raceAbort` 让本地立即 settle，不等待对端慢慢收尾。
   */
  const runWorker = async (task: WorkerTask): Promise<PoolWorkerResult> => {
    const startedAt = Date.now()
    const base = (patch: Partial<PoolWorkerResult>): PoolWorkerResult => ({
      peer: task.peer,
      sessionId: task.sessionId,
      ok: false,
      reply: '',
      stopReason: 'error',
      durationMs: Math.max(0, Date.now() - startedAt),
      ...patch,
    })

    try {
      assertCanPrompt(task.peer, task.profile)
    } catch (error) {
      return base({ error: messageOf(error) })
    }

    let pending: Promise<Record<string, unknown>>
    try {
      pending = task.link.request('agent.prompt', {
        sessionId: task.sessionId,
        text: task.text,
        // 0 = 不设对端侧超时：worker 轮次可以跑很久，前台等它结束。
        timeoutMs: 0,
      })
    } catch (error) {
      return base({ error: messageOf(error) })
    }

    const onAbort = (): void => { interruptWorker(task.link, task.peer, task.sessionId) }
    const signal = task.signal
    if (signal?.aborted === true) onAbort()
    else signal?.addEventListener('abort', onAbort, { once: true })

    try {
      const response = await raceAbort(pending, signal ?? NEVER_ABORT)
      const reply = typeof response.reply === 'string' ? response.reply : ''
      const interrupted = response.interrupted === true
      const peerError = typeof response.error === 'string' && response.error.trim() !== ''
        ? response.error
        : undefined
      const reason = typeof response.reason === 'string' && response.reason !== ''
        ? response.reason
        : undefined
      // 被远端用户打断、或对端自报 turn error：都没有可用交付，算失败。
      const ok = !interrupted && peerError === undefined
      return base({
        ok,
        reply,
        ...replyFields(response),
        stopReason: interrupted ? 'aborted' : peerError !== undefined ? 'error' : reason ?? 'completed',
        ...(interrupted ? { interrupted: true } : {}),
        ...(peerError === undefined ? {} : { error: peerError }),
      })
    } catch (error) {
      if (isAbortError(error)) {
        return base({ stopReason: 'aborted', aborted: true, error: '本机取消' })
      }
      return base({ error: messageOf(error) })
    } finally {
      signal?.removeEventListener('abort', onAbort)
    }
  }

  /** 共享的“当前配置”快照：前缀、本机 chat、peer 声明。 */
  const contextOf = (exec: unknown): {
    peers: Record<string, PoolPeerProfile>
    prefix: string
    localSessionId: string | undefined
  } => ({
    peers: deps.peers(),
    prefix: normalizedPrefix(deps),
    localSessionId: deps.localSessionOf(exec),
  })

  /**
   * 两个 dispatch 工具共享的执行体：建任务（可选）→ 前台并行/单个跑 → 收任务 → 聚合。
   *
   * `strictTeam` 是 `remote_team_dispatch` 与 `remote_pool_dispatch` 唯一的语义差别：
   * - `false`（pool）：看板只是附带记账，`begin` 拿不到 token（没有 Team、调用方不是
   *   成员）就静默继续，远端工作照跑；
   * - `true`（team）：看板是**这次调用的目的**，拿不到 token 就在发出任何远端请求前
   *   抛可读错误，绝不静默退化成一次普通 dispatch（那只会浪费一次远端轮次）。
   *
   * @param request - 已通过 peer 列表校验的 peer 名、prompt、标题、exec、是否强依赖 Team。
   * @returns 聚合结果 + 看板任务 id（没有任务时为 undefined）。
   */
  const runDispatch = async (request: {
    names: string[]
    text: string
    description: string
    exec: { agent?: unknown, signal?: AbortSignal }
    strictTeam: boolean
    toolName: string
  }): Promise<{
    description: string
    workers: PoolWorkerResult[]
    summary: PoolDispatchSummary
    taskId: string | undefined
  }> => {
    const { peers, prefix, localSessionId } = contextOf(request.exec)
    const signal = request.exec.signal
    // 链接先建好：linkFor 的配置错误属于接线错误，应在建任务之前暴露。
    const tasks: WorkerTask[] = request.names.map((peer) => {
      const profile = profileOf(peers, peer)
      return {
        peer,
        profile,
        link: deps.linkFor(peer),
        sessionId: peerSessionId(prefix, peer, localSessionId),
        text: request.text,
        signal,
      }
    })

    const teamAgent = teamAgentOf(request.exec)
    const hooks = deps.teamTask
    let token: TeamTaskToken | undefined
    let beginError: string | undefined
    if (hooks !== undefined) {
      try {
        token = await hooks.begin(teamAgent, {
          subject: dispatchSubject(request.description, request.text),
          description: dispatchTaskDescription(request.description, request.text, request.names),
        })
      } catch (error) {
        beginError = messageOf(error)
        // 严格模式下马上会抛错，不需要“继续派发”的日志。
        if (!request.strictTeam) {
          deps.log(`dsh-remote-pool: 看板任务 begin 失败（${beginError}）；继续派发`)
        }
      }
    }

    if (request.strictTeam && token === undefined) {
      throw new Error(
        `${request.toolName}: 当前会话不在 Agent Teams 里（或没有 agentTeams 服务），`
        + '请用 remote_pool_dispatch / remote_worker_prompt'
        + (beginError === undefined ? '' : `；begin 失败：${beginError}`),
      )
    }

    deps.log(
      `dsh-remote-pool: 并行派发到 ${request.names.length} 个 peer（${request.names.join(', ')}）`
      + (token === undefined ? '' : `；看板任务 ${token.taskId}`),
    )

    const settled = await Promise.allSettled(tasks.map(task => runWorker(task)))
    const workers: PoolWorkerResult[] = []
    let aborted = signal?.aborted === true
    for (let index = 0; index < tasks.length; index += 1) {
      const task = tasks[index]
      if (task === undefined) continue
      const outcome = settled[index]
      if (outcome === undefined) continue
      if (outcome.status === 'fulfilled') {
        workers.push(outcome.value)
        if (outcome.value.aborted === true) aborted = true
        continue
      }
      // runWorker 只在取消路径上抛出；其余失败已经变成结果行，这里只是兜底。
      if (isAbortError(outcome.reason)) aborted = true
      workers.push({
        peer: task.peer,
        sessionId: task.sessionId,
        ok: false,
        reply: '',
        stopReason: 'error',
        durationMs: 0,
        error: messageOf(outcome.reason),
      })
    }

    const okCount = workers.filter(worker => worker.ok).length
    const failedCount = workers.length - okCount
    const summary: PoolDispatchSummary = { total: workers.length, ok: okCount, failed: failedCount }
    const summaryText = aborted
      ? `本机取消：已向所有在途 worker 发送 agent.interrupt\n${summaryTextOf(workers)}`
      : summaryTextOf(workers)

    if (hooks !== undefined) {
      try {
        await hooks.finish(teamAgent, token, {
          ok: okCount,
          failed: failedCount,
          summary: summaryText,
        })
      } catch (error) {
        deps.log(`dsh-remote-pool: 看板任务 finish 失败（${messageOf(error)}）；结果不受影响`)
      }
    }

    if (aborted) {
      throw abortError(
        `${request.toolName}: 本机取消，已向所有在途 worker 发送 agent.interrupt；`
        + '已发出的请求不会重试',
      )
    }

    deps.log(
      `dsh-remote-pool: 派发完成：${okCount} 成功 / ${failedCount} 失败（共 ${workers.length}）`,
    )
    return { description: request.description, workers, summary, taskId: token?.taskId }
  }

  return [
    defineTool({
      name: REMOTE_WORKERS_TOOL,
      description:
        '列出部署声明的所有远端 peer（worker 池）：`{ name, host, port, connected, maxPermission, sessionForThisChat }`。\n'
        + '`sessionForThisChat` 是本 chat（调用方会话）在每个 peer 上固定复用的远端会话 id —— '
        + '一个本机 chat 在每个 peer 上各有一段对话，不同 peer 的 id 不同。\n'
        + '边界：远端 peer **不在 Agent Teams roster 里**，它不是本机 teammate；'
        + 'worker 池的任务只会以**调用方（Lead/成员）名义**出现在看板上，owner 是调用方而不是远端。',
      parameters: {},
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            count: number
            workers: Array<{
              name: string
              host: string
              port: number
              connected: boolean
              maxPermission: number
              sessionForThisChat: string | null
            }>
          }
          const workers = Array.isArray(v.workers) ? v.workers : []
          if (workers.length === 0) {
            return renderText('没有声明任何 peer：先在 dsh-remote-client 的 `peers` 里声明至少一个。')
          }
          const lines = [`远端 worker 池：${workers.length} 个 peer`]
          for (const worker of workers) {
            const endpoint = worker.host === '' ? '(未配置 host)' : `${worker.host}:${worker.port}`
            lines.push(
              `- ${worker.name}  ${endpoint}  ${levelName(worker.maxPermission)}  `
              + `${worker.connected ? '已连接' : '未连接'}  `
              + `session=${worker.sessionForThisChat ?? '(无调用方 chat)'}`,
            )
          }
          lines.push('远端 peer 不在 Team roster 里：看板任务只记在调用方名下。')
          return renderText(lines.join('\n'))
        },
      },
      async execute(
        _args: Record<string, never>,
        exec: { agent?: unknown, signal?: AbortSignal },
      ): Promise<JsonValue> {
        const { peers, prefix, localSessionId } = contextOf(exec)
        const names = Object.keys(peers)
        if (names.length === 0) {
          throw new Error(
            '没有声明任何 peer：先在 dsh-remote-client 的 `peers` 里声明至少一个 peer '
            + '（或配置单 peer 的 host/port）。',
          )
        }
        const workers = names.map((name) => {
          const profile = peers[name] ?? { name }
          let connected = false
          try {
            connected = deps.linkFor(name).connected
          } catch (error) {
            deps.log(`dsh-remote-pool: 读取 peer "${name}" 链接失败（${messageOf(error)}）`)
          }
          return {
            name,
            host: typeof profile.host === 'string' ? profile.host : '',
            port: typeof profile.port === 'number' && Number.isFinite(profile.port) ? profile.port : 0,
            connected,
            maxPermission: normalizePermission(profile.maxPermission),
            // 没有调用方 chat 时给 null：此时 id 在 peer 内共享，必须让调用方看得见。
            sessionForThisChat: localSessionId === undefined || localSessionId === ''
              ? null
              : peerSessionId(prefix, name, localSessionId),
          }
        })
        return { count: workers.length, workers } as unknown as JsonValue
      },
    }),

    defineTool({
      name: REMOTE_WORKER_PROMPT_TOOL,
      description:
        '在**某个指定 peer** 的确定性会话上做一次**前台** `agent.prompt`，等这一轮结束并取回回复。\n'
        + '会话 id 由（本机 chat, peer 名）共同推导：同一个 chat 反复调用同一个 peer 会续接同一段远端对话，'
        + '不同 peer 各自一段。\n'
        + '用途：明确知道该找哪台机器时单独派活；要同时问多个 peer 用 remote_pool_dispatch。\n'
        + '权限：调用前按该 peer 的 maxPermission 检查 `agent.prompt`（需要 level 3 / danger-full-access），'
        + '失败信息与单 peer 主路径一致。\n'
        + '打断：本机用户中断时，会对该 peer 发 `agent.interrupt` 并以 AbortError 结束。\n'
        + '边界：远端 peer **不在 Agent Teams roster 里**；若调用方在 Team 中，任务只会以调用方名义出现。',
      parameters: {
        peer: { type: 'string', required: true, description: '要派活的 peer 名（用 remote_workers 查看）。' },
        text: { type: 'string', required: true, description: '交给该 peer agent 的用户发言。' },
        description: { type: 'string', description: '这次派活的简短标题，只用于日志/看板任务标题。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            peer: string
            sessionId: string
            reply: string
            interrupted: boolean
            reason: string | null
            durationMs: number
          }
          const lines = [
            `peer   : ${v.peer}`,
            `session: ${v.sessionId}`,
            `reason : ${v.reason ?? '(none)'}${v.interrupted ? '  (interrupted)' : ''}   ${v.durationMs} ms`,
          ]
          if (v.interrupted) {
            lines.push('⚠️ 这一轮在远端被用户打断，没有可用的回复。立刻停止：不要重试、不要自动继续，等用户的新指示。')
          }
          lines.push(renderRemoteReplies(value))
          return renderText(lines.join('\n'))
        },
      },
      async execute(
        args: { peer: string, text: string, description?: string },
        exec: { agent?: unknown, signal?: AbortSignal },
      ): Promise<JsonValue> {
        const { peers, prefix, localSessionId } = contextOf(exec)
        // 复用同一套校验：未声明/空名字都是可读错误，且发生在任何网络请求之前。
        const [peer] = orderedPeerNames(peers, [args.peer])
        if (peer === undefined) throw new Error('remote_worker_prompt: peer 名无效。')
        const profile = profileOf(peers, peer)
        const sessionId = peerSessionId(prefix, peer, localSessionId)
        if (typeof args.text !== 'string' || args.text.trim() === '') {
          throw new Error('remote_worker_prompt: text 不能为空。')
        }
        const label = typeof args.description === 'string' && args.description.trim() !== ''
          ? args.description.trim()
          : firstLine(args.text)
        deps.log(`dsh-remote-pool: 派活给 peer "${peer}"（${sessionId}）：${excerpt(label, 80)}`)

        const result = await runWorker({
          peer,
          profile,
          link: deps.linkFor(peer),
          sessionId,
          text: args.text,
          signal: exec?.signal,
        })
        if (result.aborted === true) {
          throw abortError(`remote_worker_prompt: 本机取消，已向 peer "${peer}" 发送 agent.interrupt`)
        }
        if (!result.ok) {
          throw new Error(
            `remote_worker_prompt: peer "${peer}" 上的远端轮次失败：${result.error ?? '未知错误'}`,
          )
        }
        return {
          peer,
          sessionId,
          reply: result.reply,
          ...(result.replies === undefined ? {} : { replies: result.replies }),
          ...(result.replyFormat === undefined ? {} : { replyFormat: result.replyFormat }),
          interrupted: result.interrupted === true,
          reason: result.stopReason,
          durationMs: result.durationMs,
        } as unknown as JsonValue
      },
    }),

    defineTool({
      name: REMOTE_POOL_DISPATCH_TOOL,
      description:
        '把同一个 prompt **并行**派发给多个远端 peer（默认全部已声明的 peer），等所有 worker 结束后聚合结果。\n'
        + '每个 worker 有自己独立的确定性会话（seed 同时含 peer 名和本机 chat），互不干扰；'
        + '单个 worker 失败只出现在它自己的结果行里，不会让整个工具失败，也不影响其他 worker。\n'
        + '最多 8 个 worker（超过直接报错，不静默截断）；peers 未声明/重复/为空都报可读错误。\n'
        + '权限：每个 worker 调用前按该 peer 的 maxPermission 检查 `agent.prompt`（level 3）。\n'
        + '打断：本机取消时对所有在途 worker 尽力发 `agent.interrupt`，整体以 AbortError 结束，已发的请求不重试。\n'
        + '这是**前台并行**，没有后台 run；需要后台任务用 remote_run_start。\n'
        + '边界：远端 peer **不在 Agent Teams roster 里**。若启用 Agent Teams 且调用方是成员，'
        + '本次派发会记成一条看板任务（subject 前缀 `远端: `），但 owner 是**调用方**，不是远端 worker。',
      parameters: {
        prompt: { type: 'string', required: true, description: '要并行派发给所有 worker 的完整任务描述。' },
        peers: {
          type: 'array',
          items: { type: 'string' },
          description: `要参与的 peer 名列表（最多 ${MAX_POOL_WORKERS} 个）；省略表示全部已声明的 peer。`,
        },
        description: { type: 'string', description: '这次派发的简短标题，只用于日志/看板任务标题。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            description: string
            workers: PoolWorkerResult[]
            summary: PoolDispatchSummary
          }
          const workers = Array.isArray(v.workers) ? v.workers : []
          const total = v.summary?.total ?? workers.length
          const okCount = v.summary?.ok ?? workers.filter(worker => worker.ok).length
          const failedCount = v.summary?.failed ?? total - okCount
          const title = v.description?.trim() === '' || v.description === undefined
            ? '远端 worker 池并行派发'
            : `远端 worker 池并行派发：${v.description.trim()}`
          const lines = [
            `${title}（${total} 个 worker，${okCount} 成功 / ${failedCount} 失败）`,
          ]
          for (const worker of workers) {
            const status = worker.ok ? '[ok]  ' : '[fail]'
            const head = `- ${status} ${worker.peer}  session=${worker.sessionId}  ${worker.durationMs} ms`
            if (worker.ok) {
              lines.push(`${head}  reply: ${excerpt(worker.reply)}`)
            } else if (worker.error !== undefined && worker.error !== '') {
              lines.push(`${head}  error: ${excerpt(worker.error, 160)}`)
            } else if (worker.interrupted === true) {
              lines.push(`${head}  interrupted: 远端用户打断`)
            } else {
              lines.push(head)
            }
          }
          if (failedCount > 0) {
            lines.push('失败的 worker 不阻塞其他 worker；需要时对失败 peer 单独重试（remote_worker_prompt）。')
          }
          lines.push('远端 peer 不在 Team roster 里：看板任务只记在调用方名下。')
          return renderText(lines.join('\n'))
        },
      },
      async execute(
        args: { prompt: string, peers?: string[], description?: string },
        exec: { agent?: unknown, signal?: AbortSignal },
      ): Promise<JsonValue> {
        if (typeof args.prompt !== 'string' || args.prompt.trim() === '') {
          throw new Error('remote_pool_dispatch: prompt 不能为空。')
        }
        const { peers } = contextOf(exec)
        // peer 列表非法（未知/重复/为空）是工具级错误：在任何请求发出前就失败。
        const names = orderedPeerNames(peers, args.peers)
        if (names.length > MAX_POOL_WORKERS) {
          throw new Error(
            `remote_pool_dispatch: 一次最多 ${MAX_POOL_WORKERS} 个 worker，`
            + `这次点名了 ${names.length} 个（${names.join(', ')}）；请拆成多次派发。`,
          )
        }
        const description = typeof args.description === 'string' ? args.description : ''
        const result = await runDispatch({
          names,
          text: args.prompt,
          description,
          exec,
          strictTeam: false,
          toolName: REMOTE_POOL_DISPATCH_TOOL,
        })
        return {
          description: result.description,
          workers: result.workers,
          summary: result.summary,
        } as unknown as JsonValue
      },
    }),

    defineTool({
      name: REMOTE_TEAM_DISPATCH_TOOL,
      description:
        '在 **Agent Teams 看板**上显式登记一次远端工作（单 peer）：用**调用方身份**建任务并 claim，'
        + '在远端跑一次前台 prompt，结束后把结果摘要写回任务描述并 complete，'
        + '返回 `taskId` 便于之后用 `team_task_get` 查。\n'
        + '要求当前会话真的在 Agent Teams 里（有 agentTeams 服务且调用方是 lead/teammate）；'
        + '否则**直接报错**，不会静默退化成普通派发——那只会白花一次远端轮次。\n'
        + '`peer` 省略时使用第一个已声明的 peer；要并行多个 peer 请用 remote_pool_dispatch。\n'
        + '权限与打断语义同 remote_worker_prompt：按该 peer 的 maxPermission 检查 `agent.prompt`（level 3），'
        + '本机取消时发 `agent.interrupt` 并以 AbortError 结束。\n'
        + '边界：远端 peer **不在 Agent Teams roster 里**，不是本机 teammate；'
        + '看板任务 owner 是**调用方**，不是远端 worker。',
      parameters: {
        description: { type: 'string', required: true, description: '看板任务标题（会自动加 `远端: ` 前缀）。' },
        prompt: { type: 'string', required: true, description: '交给该 peer agent 的完整任务描述。' },
        peer: { type: 'string', description: '要派活的 peer 名；省略表示第一个已声明的 peer。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            taskId?: string
            workers: PoolWorkerResult[]
            summary: PoolDispatchSummary
          }
          const workers = Array.isArray(v.workers) ? v.workers : []
          const total = v.summary?.total ?? workers.length
          const okCount = v.summary?.ok ?? workers.filter(worker => worker.ok).length
          const failedCount = v.summary?.failed ?? total - okCount
          const task = typeof v.taskId === 'string' && v.taskId !== '' ? `task ${v.taskId}` : '(没有 taskId)'
          const lines = [
            `远端 Team 派发已登记：${task}（${total} 个 worker，${okCount} 成功 / ${failedCount} 失败）`,
          ]
          for (const worker of workers) {
            const status = worker.ok ? '[ok]  ' : '[fail]'
            const head = `- ${status} ${worker.peer}  session=${worker.sessionId}  ${worker.durationMs} ms`
            if (worker.ok) {
              lines.push(`${head}  reply: ${excerpt(worker.reply)}`)
            } else if (worker.error !== undefined && worker.error !== '') {
              lines.push(`${head}  error: ${excerpt(worker.error, 160)}`)
            } else if (worker.interrupted === true) {
              lines.push(`${head}  interrupted: 远端用户打断`)
            } else {
              lines.push(head)
            }
          }
          if (failedCount > 0) {
            lines.push('失败的 worker 不阻塞其他 worker；需要时对该 peer 单独重试（remote_worker_prompt）。')
          }
          lines.push('远端 peer 不在 roster 里；看板任务 owner 是调用方（不是远端 worker）。')
          return renderText(lines.join('\n'))
        },
      },
      async execute(
        args: { description: string, prompt: string, peer?: string },
        exec: { agent?: unknown, signal?: AbortSignal },
      ): Promise<JsonValue> {
        if (typeof args.description !== 'string' || args.description.trim() === '') {
          throw new Error('remote_team_dispatch: description 不能为空。')
        }
        if (typeof args.prompt !== 'string' || args.prompt.trim() === '') {
          throw new Error('remote_team_dispatch: prompt 不能为空。')
        }
        const { peers } = contextOf(exec)
        const requested = typeof args.peer === 'string' && args.peer.trim() !== ''
          ? [args.peer]
          : undefined
        // 省略 peer → 第一个已声明的 peer；显式 peer → 走同一套未知/重复校验。
        const selected = orderedPeerNames(peers, requested)
        const peer = selected[0]
        if (peer === undefined) throw new Error('remote_team_dispatch: 没有可用的 peer。')

        // strictTeam：begin 拿不到 token 时在 runDispatch 里抛可读错误，不会发出远端请求。
        const result = await runDispatch({
          names: [peer],
          text: args.prompt,
          description: args.description.trim(),
          exec,
          strictTeam: true,
          toolName: REMOTE_TEAM_DISPATCH_TOOL,
        })
        if (result.taskId === undefined) {
          throw new Error(`${REMOTE_TEAM_DISPATCH_TOOL}: 看板任务没有登记成功。`)
        }
        return {
          taskId: result.taskId,
          workers: result.workers,
          summary: result.summary,
        } as unknown as JsonValue
      },
    }),
  ]
}

/** {@link createPeerLinks} 的注入面。 */
export interface PeerLinksDeps {
  /** 当前部署声明的 peers。 */
  peers(): Record<string, PoolPeerProfile>
  /** 一行日志。 */
  log(message: string): void
}

/**
 * 为当前声明的每个 peer 建一个 `LinkClient`，按 peer 名放进 Map。
 *
 * 这是给“声明在启动时固定”的部署用的便捷 helper；地址/密钥仍通过访问器
 * **按需重读**，所以设置热更新后下一次拨号会用新值。运行期才新增的 peer 不会
 * 自动出现在这个 Map 里——那种场景请由接线方自己维护懒缓存（见接线说明），
 * 或者重新调用本函数。
 *
 * @param deps - peer 声明与日志。
 * @returns `peer 名 → LinkClient`，构造时不拨号。
 */
export function createPeerLinks(deps: PeerLinksDeps): Map<string, LinkClient> {
  const links = new Map<string, LinkClient>()
  for (const name of Object.keys(deps.peers())) {
    const read = (): EndpointConfig => {
      const profile = deps.peers()[name]
      if (profile === undefined) return {}
      return {
        host: profile.host,
        port: profile.port,
        relayTarget: profile.relayTarget,
        privateKey: profile.privateKey,
        privateKeyFile: profile.privateKeyFile,
        autoGenerateKey: profile.autoGenerateKey,
        peerPublicKey: profile.peerPublicKey,
        peerPublicKeyFile: profile.peerPublicKeyFile,
        timeoutMs: profile.timeoutMs,
        allowLegacyHandshake: profile.allowLegacyHandshake,
        maxSessionMs: profile.maxSessionMs,
      }
    }
    links.set(name, new LinkClient(read, deps.log, `dsh-remote:peer ${name}`))
  }
  return links
}
