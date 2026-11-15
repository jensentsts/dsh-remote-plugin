/**
 * Agent Teams 看板的薄桥：把一次远端 worker 派发记录成一条队内任务。
 *
 * ## 为什么是 facade 而不是直接 import
 *
 * Agent Teams（`ctx.agentTeams`）来自 DSH 的 experimental 包，而本插件必须能在
 * **没有启用 Agent Teams 的环境**里正常加载（对端、精简 profile、旧版本都可能是
 * 这种状态）。所以这里不 import 任何 `@deepseek-ai/experimental*` 或
 * `@deepseek-ai/dsh-agent-team`：{@link TeamFacade} 只声明本模块用到的那几个方法，
 * 由接线方（`client.ts`）把真实的 `ctx.agentTeams` 注进来。
 *
 * ## 语义边界（重要）
 *
 * 远端 peer **不在 Team 的 roster 里**，它不是本机 `spawn_teammate` 创建的成员，
 * 因此永远不能 `claim`/`edit`/`complete` 任务。看板上能出现的是
 * “**调用方（Lead 或某个 teammate）名下的远端工作**”：
 *
 * - `begin` 用**调用方的 agent** 建任务（unowned、pending）并立刻 claim，
 *   于是 owner 是调用方而不是远端；
 * - `finish` 也用调用方的 agent 把结果摘要写进任务描述，再 complete。
 *
 * 这些只是看板记账：hooks 的**任何**失败都只写一行日志，绝不影响远端工作本身，
 * 也绝不让工具调用失败（远端任务已经派出去了，看板记不上不是它的错）。
 *
 * ## CAS（expectedRevision）
 *
 * Team 的任务变更是 compare-and-set：每一步都必须带上一步返回的 `revision`。
 * `begin` 返回 claim 之后的 revision；`finish` 用 `token.revision` 做 `edit`，
 * 再用 edit 返回的新 revision 做 `complete`。用旧 revision 会得到
 * `TEAM_STALE_REVISION`，而这里把它降级成一行日志。
 *
 * @module dsh-remote/remote-team
 */

/**
 * 结构上就是 `exec.agent`。
 *
 * 只声明本模块读取的字段（`id` 与 `session.id`），所以真实的 `Agent` 天然满足它，
 * 而本模块不需要 import `@deepseek-ai/dsh-agent` 的任何运行时值。
 */
export interface TeamAgent {
  /** 本机会话/成员 id（真实 `Agent` 上是 `SessionId`）。 */
  id?: unknown
  /** 调用方会话，用来在日志里定位（真实 `Agent` 上有 `session.id`）。 */
  session?: { id?: unknown }
}

/** `begin` 要建的任务内容。 */
export interface TeamTaskCreateRequest {
  /** 任务标题（本模块会加上 `远端: ` 前缀并截断到 200 字符）。 */
  subject: string
  /** 任务描述：任务目标 + 参与 peer 列表（本模块截断到 2000 字符）。 */
  description: string
  /** 可选的写入范围，原样透传给 Team。 */
  writeScopes?: string[]
}

/** 一次 CAS 任务变更。 */
export interface TeamTaskUpdateRequest {
  /** 任务 id。 */
  taskId: string
  /** 上一步返回的 revision（CAS 前置条件）。 */
  expectedRevision: number
  /** 要执行的动作。 */
  action: 'claim' | 'edit' | 'complete' | 'release'
  /** `edit` 时的新标题。 */
  subject?: string
  /** `edit` 时的新描述。 */
  description?: string
}

/**
 * `ctx.agentTeams`（`TeamService`）里本模块用到的那一小块。
 *
 * 结构化的好处：本模块没有 Agent Teams 也能加载；接真实服务时把
 * `ctx.get('agentTeams')` 直接传进来（必要时 `as unknown as TeamFacade`）即可。
 *
 * 所有方法都以**调用方 agent** 作为第一个参数，这正是 Team 的权限模型：
 * 谁调用，任务就以谁的身份/权限操作。远端 peer 不是成员，所以这里永远只传本机 agent。
 */
export interface TeamFacade {
  /** 当前 agent 的队内身份；不是成员时真实实现会抛 `TEAM_NOT_MEMBER`。 */
  membership(agent: TeamAgent): { role: 'lead' | 'teammate', id?: unknown }
  /** 建一条 unowned、pending 的任务。 */
  createTask(
    agent: TeamAgent,
    request: TeamTaskCreateRequest,
  ): Promise<{ id: string, revision: number }>
  /** CAS 变更一条任务；`revision`/`status` 以最新任务视图为准。 */
  updateTask(
    agent: TeamAgent,
    request: TeamTaskUpdateRequest,
  ): Promise<{ id: string, revision: number, status?: string }>
}

/** `begin` 成功后交回给 `finish` 的凭据。 */
export interface TeamTaskToken {
  /** 任务 id。 */
  taskId: string
  /** claim 之后的 revision，`finish` 的 `edit` 必须用它做 CAS。 */
  revision: number
}

/** `finish` 收到的结果摘要。 */
export interface TeamTaskResultSummary {
  /** 成功的 worker 数。 */
  ok: number
  /** 失败的 worker 数。 */
  failed: number
  /** 一行一段的结果正文（由 pool 生成，含每个 worker 的结果/错误）。 */
  summary: string
}

/**
 * 一次远端派发的 Team 记账钩子。
 *
 * 两个方法都**不会抛错**（实现内部吞掉并记录所有失败），所以调用方可以放心地
 * 在派发路径上 `await` 它们，不需要 try/catch。
 */
export interface TeamTaskHooks {
  /**
   * 派发开始：调用方在 Team 里时建任务并 claim。
   *
   * @param agent - 调用方 agent（工具 `exec.agent`）；缺席或不是成员时返回 undefined。
   * @param request - 任务标题与描述。
   * @returns `{ taskId, revision }`，或 undefined 表示“这次不记账”。
   */
  begin(
    agent: TeamAgent | undefined,
    request: { subject: string, description: string },
  ): Promise<TeamTaskToken | undefined>

  /**
   * 派发结束：把结果摘要追加进任务描述（`edit`），再 `complete`。
   *
   * @param agent - 调用方 agent，必须与 `begin` 的是同一个。
   * @param token - `begin` 的返回值；undefined 表示本次没有任务可收。
   * @param result - 成功/失败计数与结果正文。
   */
  finish(
    agent: TeamAgent | undefined,
    token: TeamTaskToken | undefined,
    result: TeamTaskResultSummary,
  ): Promise<void>
}

/** {@link createTeamTaskHooks} 的注入面。 */
export interface TeamTaskHookDeps {
  /** 取当前 Agent Teams 服务；没有启用时返回 undefined。允许返回 undefined，也可以抛错。 */
  team(): TeamFacade | undefined
  /** 一行日志（失败时唯一的表现）。 */
  log(message: string): void
  /** `finish` 追加的结果摘要最多保留多少字符（默认 800，最小 80）。 */
  maxSummaryChars?: number
}

/** 任务标题前缀：一眼看出这是远端工作，而不是本机 teammate 的任务。 */
export const TEAM_SUBJECT_PREFIX = '远端: '

/** Team 的标题上限（字符数，UTF-16）。超过会被真实服务拒绝，所以先截断。 */
export const MAX_TEAM_SUBJECT_CHARS = 200

/** 本模块写入任务描述的上限（字符数，UTF-16）。 */
export const MAX_TEAM_DESCRIPTION_CHARS = 2000

/** 结果摘要的默认上限。 */
const DEFAULT_MAX_SUMMARY_CHARS = 800

/** 记住“任务 id → 原始描述”的上限：`edit` 是整段替换，追加必须知道原文。 */
const MAX_REMEMBERED_DESCRIPTIONS = 64

/** 把任意错误降级成一行可读文本。 */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * 截断文本到 `max` 个 UTF-16 字符，超长时补一个省略号。
 * @param value - 原始文本。
 * @param max - 上限（至少 1）。
 * @returns 原文本或截断后的文本。
 */
function clampText(value: string, max: number): string {
  const limit = Math.max(1, Math.trunc(max))
  if (value.length <= limit) return value
  return `${value.slice(0, Math.max(0, limit - 1))}…`
}

/**
 * 建一套 Team 记账 hooks。
 *
 * 没有 Agent Teams 的环境（`team()` 返回 undefined）下两个方法都是 no-op，
 * 因此 pool 可以无条件地接上它。
 *
 * @param deps - 服务访问器、日志与摘要上限。
 * @returns 不会抛错的 {@link TeamTaskHooks}。
 */
export function createTeamTaskHooks(deps: TeamTaskHookDeps): TeamTaskHooks {
  /**
   * 任务 id → `begin` 时写入的描述。
   *
   * `edit` 会整段替换 description，所以“追加结果”必须自己记住原文。这里只在
   * 本 hooks 实例内记账（同一进程、同一派发路径），丢失它最多让结果摘要覆盖原文，
   * 不会影响任务状态机。
   */
  const remembered = new Map<string, string>()

  /** FIFO 上限，防止一个长期进程里只 begin 不 finish 的路径无限增长。 */
  const remember = (taskId: string, description: string): void => {
    remembered.delete(taskId)
    remembered.set(taskId, description)
    while (remembered.size > MAX_REMEMBERED_DESCRIPTIONS) {
      const oldest = remembered.keys().next()
      if (oldest.done === true) break
      remembered.delete(oldest.value)
    }
  }

  const summaryLimit = ((): number => {
    const configured = deps.maxSummaryChars
    if (configured === undefined || !Number.isFinite(configured)) return DEFAULT_MAX_SUMMARY_CHARS
    return Math.max(80, Math.trunc(configured))
  })()

  /** 取 facade；`team()` 抛错也只是“这次不记账”。 */
  const activeFacade = (): TeamFacade | undefined => {
    try {
      return deps.team()
    } catch (error) {
      deps.log(`dsh-remote-team: 读取 agentTeams 失败（${messageOf(error)}）；这次不记看板`)
      return undefined
    }
  }

  /** 调用方是否在 Team 里；不是成员时真实 `membership` 会抛。 */
  const isTeamMember = (facade: TeamFacade, agent: TeamAgent): boolean => {
    try {
      const membership = facade.membership(agent)
      return membership.role === 'lead' || membership.role === 'teammate'
    } catch (error) {
      deps.log(`dsh-remote-team: 调用方不在 Agent Teams 里（${messageOf(error)}）；这次不记看板`)
      return false
    }
  }

  return {
    async begin(agent, request) {
      if (agent === undefined) return undefined
      const facade = activeFacade()
      if (facade === undefined) return undefined
      if (!isTeamMember(facade, agent)) return undefined

      // 标题必须非空且不超过 Team 的上限；前缀在截断之后仍要保留，所以先拼再截。
      const rawSubject = typeof request.subject === 'string' ? request.subject.trim() : ''
      const subject = clampText(
        `${TEAM_SUBJECT_PREFIX}${rawSubject === '' ? '远端 worker 派发' : rawSubject}`,
        MAX_TEAM_SUBJECT_CHARS,
      )
      const description = clampText(
        typeof request.description === 'string' ? request.description : '',
        MAX_TEAM_DESCRIPTION_CHARS,
      )

      let created: { id: string, revision: number }
      try {
        created = await facade.createTask(agent, { subject, description })
      } catch (error) {
        deps.log(`dsh-remote-team: 创建看板任务失败（${messageOf(error)}）；远端工作继续`)
        return undefined
      }
      if (typeof created?.id !== 'string' || created.id === '') {
        deps.log('dsh-remote-team: createTask 没有返回任务 id；远端工作继续')
        return undefined
      }

      // 先记住描述，claim 之后 finish 才可能把它补全。
      remember(created.id, description)

      try {
        const claimed = await facade.updateTask(agent, {
          taskId: created.id,
          expectedRevision: created.revision,
          action: 'claim',
        })
        return { taskId: created.id, revision: claimed.revision }
      } catch (error) {
        // 任务已建但认领失败：本模块不是 owner，没法 edit/complete，只能不再处理它。
        remembered.delete(created.id)
        deps.log(`dsh-remote-team: 认领看板任务 ${created.id} 失败（${messageOf(error)}）；远端工作继续`)
        return undefined
      }
    },

    async finish(agent, token, result) {
      if (agent === undefined || token === undefined) return
      const facade = activeFacade()
      if (facade === undefined) {
        remembered.delete(token.taskId)
        return
      }

      const summary = clampText(
        [
          `远端结果：成功 ${result.ok} 个，失败 ${result.failed} 个`,
          typeof result.summary === 'string' ? result.summary : '',
        ].filter(part => part !== '').join('\n'),
        summaryLimit,
      )
      const original = remembered.get(token.taskId) ?? ''
      const description = clampText(
        original === '' ? summary : `${original}\n\n${summary}`,
        MAX_TEAM_DESCRIPTION_CHARS,
      )

      let edited: { id: string, revision: number, status?: string }
      try {
        edited = await facade.updateTask(agent, {
          taskId: token.taskId,
          expectedRevision: token.revision,
          action: 'edit',
          description,
        })
      } catch (error) {
        remembered.delete(token.taskId)
        deps.log(`dsh-remote-team: 写结果摘要失败（${messageOf(error)}）；看板任务保持原状`)
        return
      }

      const nextRevision = Number(edited?.revision)
      if (!Number.isFinite(nextRevision)) {
        remembered.delete(token.taskId)
        deps.log(`dsh-remote-team: edit 没有返回有效 revision（${String(edited?.revision)}）；不 complete`)
        return
      }

      try {
        await facade.updateTask(agent, {
          taskId: token.taskId,
          expectedRevision: nextRevision,
          action: 'complete',
        })
        deps.log(`dsh-remote-team: 看板任务 ${token.taskId} 已完成（成功 ${result.ok} / 失败 ${result.failed}）`)
      } catch (error) {
        deps.log(`dsh-remote-team: complete 看板任务 ${token.taskId} 失败（${messageOf(error)}）`)
      } finally {
        remembered.delete(token.taskId)
      }
    },
  }
}
