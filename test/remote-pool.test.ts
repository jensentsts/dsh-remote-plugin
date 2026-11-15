/**
 * 自测：多 peer worker 池 + Agent Teams 看板记账（无 peer、无 cordis、无网络）。
 *
 * 覆盖三块纯逻辑：
 *
 * 1. `remote-pool.ts` —— peer 列表校验、每 peer 确定性会话 id、四个工具的成功/
 *    失败/权限拒绝/并行聚合/取消路径；
 * 2. `remote-team.ts` —— begin/finish 的顺序、CAS revision、没有任何 Team 时的
 *    no-op、失败只 log；
 * 3. 两者接起来：dispatch 会在正确时机建/收看板任务，且看板失败不影响结果。
 *
 * 用假 link 与假 TeamFacade 注入，所以不依赖对端，也不 import `client.ts`。
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/remote-pool.test.ts
 */

import {
  MAX_POOL_WORKERS,
  REMOTE_POOL_DISPATCH_TOOL,
  REMOTE_TEAM_DISPATCH_TOOL,
  REMOTE_WORKER_PROMPT_TOOL,
  REMOTE_WORKERS_TOOL,
  createPoolTools,
  orderedPeerNames,
  peerSessionId,
} from '../src/remote-pool.ts'
import type { PoolDeps, PoolLink, PoolPeerProfile, PoolWorkerResult } from '../src/remote-pool.ts'
import {
  MAX_TEAM_DESCRIPTION_CHARS,
  MAX_TEAM_SUBJECT_CHARS,
  TEAM_SUBJECT_PREFIX,
  createTeamTaskHooks,
} from '../src/remote-team.ts'
import type {
  TeamFacade,
  TeamTaskCreateRequest,
  TeamTaskHooks,
  TeamTaskUpdateRequest,
} from '../src/remote-team.ts'

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

/** 同步调用返回的错误文本；不抛则返回空串。 */
function errorMessage(fn: () => unknown): string {
  try {
    fn()
    return ''
  } catch (error) {
    return error instanceof Error ? error.message : String(error)
  }
}

/** 让已排队的 promise 回调跑一轮。 */
function tick(): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, 0) })
}

// ---------------------------------------------------------------------------
// 假 peer 链接
// ---------------------------------------------------------------------------

interface RecordedRequest {
  op: string
  args: Record<string, unknown>
  timeoutMs?: number
}

interface FakeLink extends PoolLink {
  requests: RecordedRequest[]
}

type Handler = (
  op: string,
  args: Record<string, unknown>,
) => Record<string, unknown> | Promise<Record<string, unknown>>

/**
 * 假 link：记录每个请求，`agent.prompt` 交给 handler，`agent.interrupt` 直接成功。
 */
function createFakeLink(handler?: Handler, connected = true): FakeLink {
  const requests: RecordedRequest[] = []
  const link: FakeLink = {
    connected,
    requests,
    close() { /* no-op */ },
    request(op, args, timeoutMs) {
      requests.push({ op, args, ...(timeoutMs === undefined ? {} : { timeoutMs }) })
      if (op === 'agent.interrupt') return Promise.resolve({ interrupted: true })
      if (handler === undefined) return Promise.resolve({ reply: 'ok', reason: 'completed' })
      return Promise.resolve(handler(op, args))
    },
  }
  return link
}

/** 一个必须由测试手动 settle 的 link，用来证明 dispatch 是并行的。 */
interface BarrierLink {
  link: FakeLink
  pending: Array<{
    resolve: (value: Record<string, unknown>) => void
    reject: (error: Error) => void
  }>
  promptsStarted: () => number
}

function createBarrierLink(): BarrierLink {
  const requests: RecordedRequest[] = []
  const pending: BarrierLink['pending'] = []
  let started = 0
  const link: FakeLink = {
    connected: true,
    requests,
    close() { /* no-op */ },
    request(op, args, timeoutMs) {
      requests.push({ op, args, ...(timeoutMs === undefined ? {} : { timeoutMs }) })
      if (op === 'agent.interrupt') return Promise.resolve({ interrupted: true })
      started += 1
      return new Promise<Record<string, unknown>>((resolve, reject) => {
        pending.push({ resolve, reject })
      })
    },
  }
  return { link, pending, promptsStarted: () => started }
}

// ---------------------------------------------------------------------------
// 假 PoolDeps
// ---------------------------------------------------------------------------

interface PoolHarness {
  deps: PoolDeps
  links: Map<string, FakeLink>
  logs: string[]
  requestsFor: (peer: string) => RecordedRequest[]
}

/** 与 client.ts 的 `localSessionOf` 同形：从 `exec.agent.session.id` 取 chat id。 */
function localSessionOf(exec: unknown): string | undefined {
  const id = (exec as { agent?: { session?: { id?: unknown } } } | undefined)?.agent?.session?.id
  return typeof id === 'string' && id !== '' ? id : undefined
}

function createHarness(
  peers: Record<string, PoolPeerProfile>,
  options: {
    prefix?: string
    handlerFor?: (peer: string) => Handler | undefined
    connectedFor?: (peer: string) => boolean
    teamTask?: TeamTaskHooks
  } = {},
): PoolHarness {
  const logs: string[] = []
  const links = new Map<string, FakeLink>()
  for (const peer of Object.keys(peers)) {
    links.set(peer, createFakeLink(
      options.handlerFor?.(peer),
      options.connectedFor?.(peer) ?? true,
    ))
  }
  const deps: PoolDeps = {
    peers: () => peers,
    prefix: () => options.prefix ?? 'remote',
    localSessionOf,
    linkFor(peer) {
      const link = links.get(peer)
      if (link === undefined) throw new Error(`test harness: no fake link for peer "${peer}"`)
      return link
    },
    log(message) { logs.push(message) },
    ...(options.teamTask === undefined ? {} : { teamTask: options.teamTask }),
  }
  return {
    deps,
    links,
    logs,
    requestsFor: (peer) => links.get(peer)?.requests ?? [],
  }
}

type PoolTools = ReturnType<typeof createPoolTools>
type PoolTool = PoolTools[number]

function toolOf(tools: PoolTools, name: string): PoolTool {
  const found = tools.find(tool => tool.name === name)
  if (found === undefined) throw new Error(`test: tool ${name} not registered`)
  return found
}

/** 调一次工具；失败时返回错误而不是抛出。 */
async function callTool(
  tool: PoolTool,
  args: Record<string, unknown>,
  exec: unknown = {},
): Promise<{ value?: Record<string, unknown>, error?: Error }> {
  try {
    const value = await tool.execute(args, exec as never)
    return { value: value as Record<string, unknown> }
  } catch (error) {
    return { error: error instanceof Error ? error : new Error(String(error)) }
  }
}

/** 渲染结果的首个文本块。 */
function renderTool(
  tool: PoolTool,
  args: Record<string, unknown>,
  value: Record<string, unknown>,
): string {
  const rendered = tool.output.render(args as never, value as never) as Array<{ type: string, text?: string }>
  return String(rendered[0]?.text ?? '')
}

// ---------------------------------------------------------------------------
// 假 TeamFacade
// ---------------------------------------------------------------------------

interface FakeTeam {
  facade: TeamFacade
  calls: string[]
  creates: TeamTaskCreateRequest[]
  updates: TeamTaskUpdateRequest[]
}

function createFakeTeam(options: {
  failOn?: 'membership' | 'create' | 'claim' | 'edit' | 'complete'
  role?: 'lead' | 'teammate'
} = {}): FakeTeam {
  const calls: string[] = []
  const creates: TeamTaskCreateRequest[] = []
  const updates: TeamTaskUpdateRequest[] = []
  let revision = 0
  const facade: TeamFacade = {
    membership(agent) {
      calls.push('membership')
      if (options.failOn === 'membership') throw new Error('TEAM_NOT_MEMBER')
      return { role: options.role ?? 'lead', ...(agent.id === undefined ? {} : { id: agent.id }) }
    },
    async createTask(_agent, request) {
      calls.push('create')
      creates.push(request)
      if (options.failOn === 'create') throw new Error('create refused')
      revision = 1
      return { id: 'task-1', revision }
    },
    async updateTask(_agent, request) {
      calls.push(request.action)
      updates.push(request)
      if (options.failOn !== undefined && options.failOn === request.action) {
        throw new Error(`${request.action} refused`)
      }
      revision += 1
      return {
        id: request.taskId,
        revision,
        ...(request.action === 'complete' ? { status: 'completed' } : {}),
      }
    },
  }
  return { facade, calls, creates, updates }
}

/** 两个 worker 的 peer 声明。 */
const twoPeers: Record<string, PoolPeerProfile> = {
  alpha: { name: 'alpha', host: '10.0.0.2', port: 50000, maxPermission: 3 },
  beta: { name: 'beta', host: '10.0.0.3', port: 50001, maxPermission: 3 },
}

async function main(): Promise<void> {
  // ------------------------------------------------------------------ session id
  section('peerSessionId：确定性 + 每 peer 独立')
  {
    const a1 = peerSessionId('remote', 'alpha', 'chat-1')
    const a2 = peerSessionId('remote', 'alpha', 'chat-1')
    const b = peerSessionId('remote', 'beta', 'chat-1')
    const otherChat = peerSessionId('remote', 'alpha', 'chat-2')
    const noChatA = peerSessionId('remote', 'alpha', undefined)
    check('same inputs → same id', a1 === a2, `${a1} vs ${a2}`)
    check('id stays in the prefix family', a1.startsWith('remote-'), a1)
    check('different peers get different ids', a1 !== b, `${a1} vs ${b}`)
    check('different chats get different ids', a1 !== otherChat, `${a1} vs ${otherChat}`)
    check('no chat still distinguishes peers',
      noChatA !== peerSessionId('remote', 'beta', undefined))
    check('empty prefix defaults to remote', peerSessionId('', 'alpha', 'chat-1').startsWith('remote-'))
    check('empty chat string equals undefined',
      peerSessionId('remote', 'alpha', '') === peerSessionId('remote', 'alpha', undefined))
    check('an empty peer name still gets a distinct id',
      peerSessionId('remote', '', 'chat-1') !== peerSessionId('remote', 'beta', 'chat-1'))
  }

  // ------------------------------------------------------------------ peer list
  section('orderedPeerNames：校验未知/重复/为空')
  {
    const declared = { alpha: {}, beta: {}, gamma: {} }
    check('omitted → declaration order',
      orderedPeerNames(declared).join(',') === 'alpha,beta,gamma',
      orderedPeerNames(declared).join(','))
    check('requested order is kept',
      orderedPeerNames(declared, ['gamma', 'alpha']).join(',') === 'gamma,alpha')
    const unknown = errorMessage(() => orderedPeerNames(declared, ['delta']))
    check('unknown peer names the offender and the declared list',
      unknown.includes('未知 peer "delta"') && unknown.includes('alpha'), unknown)
    const duplicate = errorMessage(() => orderedPeerNames(declared, ['alpha', 'alpha']))
    check('duplicate peer is refused, not silently de-duplicated',
      duplicate.includes('重复'), duplicate)
    const empty = errorMessage(() => orderedPeerNames(declared, []))
    check('an explicit empty list is refused', empty.includes('peers 为空'), empty)
    const none = errorMessage(() => orderedPeerNames({}))
    check('no declared peers is a readable error', none.includes('没有声明任何 peer'), none)
    const noneRequested = errorMessage(() => orderedPeerNames({}, ['x']))
    check('no declared peers + requested peer says so',
      noneRequested.includes('当前没有声明任何 peer'), noneRequested)
    const blank = errorMessage(() => orderedPeerNames(declared, ['  ']))
    check('blank peer name is refused', blank.includes('空名字'), blank)
  }

  // ------------------------------------------------------------------ registration
  section('createPoolTools：四个工具注册')
  {
    const tools = createPoolTools(createHarness(twoPeers).deps)
    check('four tools', tools.length === 4, String(tools.length))
    check('names are the documented ones',
      tools.map(tool => tool.name).join(',') ===
        [REMOTE_WORKERS_TOOL, REMOTE_WORKER_PROMPT_TOOL, REMOTE_POOL_DISPATCH_TOOL, REMOTE_TEAM_DISPATCH_TOOL].join(','),
      tools.map(tool => tool.name).join(','))
    const dispatch = toolOf(tools, REMOTE_POOL_DISPATCH_TOOL)
    check('dispatch description states the Team-roster boundary',
      dispatch.description.includes('Agent Teams roster'), dispatch.description.slice(0, 120))
    check('dispatch description states the max worker count',
      dispatch.description.includes(String(MAX_POOL_WORKERS)), dispatch.description.slice(0, 200))
    const teamDispatch = toolOf(tools, REMOTE_TEAM_DISPATCH_TOOL)
    check('team dispatch description requires an Agent Teams context',
      teamDispatch.description.includes('Agent Teams') && teamDispatch.description.includes('不会静默退化'),
      teamDispatch.description.slice(0, 160))
    check('every tool declares an output renderer',
      tools.every(tool => typeof tool.output.render === 'function'))
  }

  // ------------------------------------------------------------------ remote_workers
  section('remote_workers：列出声明与每 chat 会话')
  {
    const harness = createHarness({
      alpha: { name: 'alpha', host: '10.0.0.2', port: 50000, maxPermission: 3 },
      beta: { name: 'beta', host: '10.0.0.3', port: 50001, maxPermission: 2 },
    }, { connectedFor: (peer) => peer === 'alpha' })
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_WORKERS_TOOL)
    const exec = { agent: { session: { id: 'chat-1' } } }
    const { value, error } = await callTool(tool, {}, exec)
    check('call succeeds', error === undefined && value !== undefined, String(error))
    const workers = (value?.workers ?? []) as Array<{
      name: string, host: string, port: number, connected: boolean,
      maxPermission: number, sessionForThisChat: string | null,
    }>
    check('one row per declared peer', workers.length === 2, String(workers.length))
    const alpha = workers.find(worker => worker.name === 'alpha')
    const beta = workers.find(worker => worker.name === 'beta')
    check('host/port surfaced', alpha?.host === '10.0.0.2' && alpha?.port === 50000,
      JSON.stringify(alpha))
    check('connected is read off the link', alpha?.connected === true && beta?.connected === false,
      `${String(alpha?.connected)}/${String(beta?.connected)}`)
    check('permission is normalized', alpha?.maxPermission === 3 && beta?.maxPermission === 2)
    check('sessionForThisChat matches peerSessionId',
      alpha?.sessionForThisChat === peerSessionId('remote', 'alpha', 'chat-1'), String(alpha?.sessionForThisChat))
    check('different peers get different sessions',
      alpha?.sessionForThisChat !== beta?.sessionForThisChat)
    const rendered = renderTool(tool, {}, value ?? {})
    check('render names each peer and the session',
      rendered.includes('alpha') && rendered.includes(peerSessionId('remote', 'alpha', 'chat-1')),
      rendered.slice(0, 200))
    check('render mentions the Team-roster boundary',
      rendered.includes('Team roster'), rendered.slice(-120))

    const noChat = await callTool(tool, {}, {})
    const noChatWorkers = (noChat.value?.workers ?? []) as Array<{ sessionForThisChat: string | null }>
    check('no calling chat → null session', noChatWorkers[0]?.sessionForThisChat === null,
      String(noChatWorkers[0]?.sessionForThisChat))

    const emptyHarness = createHarness({})
    const empty = await callTool(toolOf(createPoolTools(emptyHarness.deps), REMOTE_WORKERS_TOOL), {})
    check('no peers declared → readable error',
      empty.error !== undefined && empty.error.message.includes('没有声明任何 peer'),
      String(empty.error))
  }

  // ------------------------------------------------------------------ worker_prompt
  section('remote_worker_prompt：成功 / 失败 / 权限拒绝')
  {
    const harness = createHarness(twoPeers, {
      handlerFor: () => () => Promise.resolve({ reply: 'done it', reason: 'completed', interrupted: false }),
    })
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_WORKER_PROMPT_TOOL)
    const exec = { agent: { session: { id: 'chat-1' } }, signal: new AbortController().signal }
    const { value, error } = await callTool(tool, { peer: 'alpha', text: 'please work', description: 'demo' }, exec)
    check('call succeeds', error === undefined && value !== undefined, String(error))
    check('reply returned', value?.reply === 'done it', String(value?.reply))
    check('peer/session returned', value?.peer === 'alpha'
      && value?.sessionId === peerSessionId('remote', 'alpha', 'chat-1'), JSON.stringify(value))
    check('reason/duration returned', value?.reason === 'completed' && typeof value?.durationMs === 'number',
      JSON.stringify(value))
    check('not interrupted', value?.interrupted === false)
    const promptRequests = harness.requestsFor('alpha').filter(request => request.op === 'agent.prompt')
    check('one agent.prompt issued', promptRequests.length === 1, String(promptRequests.length))
    check('prompt carries the deterministic session id',
      promptRequests[0]?.args.sessionId === peerSessionId('remote', 'alpha', 'chat-1'),
      JSON.stringify(promptRequests[0]?.args))
    check('prompt asks the peer for no turn timeout (timeoutMs: 0)',
      promptRequests[0]?.args.timeoutMs === 0, JSON.stringify(promptRequests[0]?.args))
    check('prompt carries the text', promptRequests[0]?.args.text === 'please work')
    check('beta was not touched', harness.requestsFor('beta').length === 0)
    const rendered = renderTool(tool, { peer: 'alpha', text: 'please work' }, value ?? {})
    check('render includes reply and session',
      rendered.includes('done it') && rendered.includes('remote-'), rendered.slice(0, 160))

    const failing = createHarness(twoPeers, {
      handlerFor: () => () => Promise.reject(new Error('peer exploded')),
    })
    const failingTool = toolOf(createPoolTools(failing.deps), REMOTE_WORKER_PROMPT_TOOL)
    const failed = await callTool(failingTool, { peer: 'alpha', text: 'x' }, exec)
    check('worker failure surfaces as a readable tool error',
      failed.error !== undefined && failed.error.message.includes('peer exploded'), String(failed.error))

    const denied = createHarness({
      alpha: { name: 'alpha', host: 'h', port: 1, maxPermission: 1 },
    })
    const deniedTool = toolOf(createPoolTools(denied.deps), REMOTE_WORKER_PROMPT_TOOL)
    const refused = await callTool(deniedTool, { peer: 'alpha', text: 'x' }, exec)
    check('read-only peer is refused before any request',
      refused.error !== undefined
      && refused.error.message.includes('refusing agent.prompt')
      && refused.error.message.includes('level 3'),
      String(refused.error))
    check('the refusal spent no round trip', denied.requestsFor('alpha').length === 0)

    const unknown = await callTool(tool, { peer: 'nope', text: 'x' }, exec)
    check('unknown peer is refused', unknown.error !== undefined
      && unknown.error.message.includes('未知 peer "nope"'), String(unknown.error))
    const blankText = await callTool(tool, { peer: 'alpha', text: '   ' }, exec)
    check('blank prompt is refused', blankText.error !== undefined
      && blankText.error.message.includes('text 不能为空'), String(blankText.error))
  }

  // ------------------------------------------------------------------ dispatch parallel
  section('remote_pool_dispatch：并行聚合与部分失败')
  {
    const harness = createHarness(twoPeers)
    const first = createBarrierLink()
    const second = createBarrierLink()
    harness.links.set('alpha', first.link)
    harness.links.set('beta', second.link)
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_POOL_DISPATCH_TOOL)
    const run = tool.execute(
      { prompt: 'audit the tree', description: 'tree audit' },
      { agent: { session: { id: 'chat-1' } }, signal: new AbortController().signal } as never,
    )
    await tick()
    check('both workers started before either settled (parallel)',
      first.promptsStarted() === 1 && second.promptsStarted() === 1,
      `${first.promptsStarted()}/${second.promptsStarted()}`)
    const firstPending = first.pending[0]
    const secondPending = second.pending[0]
    firstPending?.resolve({ reply: 'alpha result', reason: 'completed' })
    secondPending?.reject(new Error('beta unavailable'))
    const value = await run as unknown as {
      description: string
      workers: PoolWorkerResult[]
      summary: { total: number, ok: number, failed: number }
    }
    check('tool itself does not fail', true)
    check('description passed through', value.description === 'tree audit', value.description)
    check('summary counts', value.summary.total === 2 && value.summary.ok === 1
      && value.summary.failed === 1, JSON.stringify(value.summary))
    const okWorker = value.workers.find(worker => worker.peer === 'alpha')
    const failedWorker = value.workers.find(worker => worker.peer === 'beta')
    check('successful worker keeps its reply', okWorker?.ok === true && okWorker?.reply === 'alpha result',
      JSON.stringify(okWorker))
    check('failed worker has an error field', failedWorker?.ok === false
      && failedWorker?.error?.includes('beta unavailable') === true, JSON.stringify(failedWorker))
    check('each worker has its own deterministic session',
      okWorker?.sessionId === peerSessionId('remote', 'alpha', 'chat-1')
      && failedWorker?.sessionId === peerSessionId('remote', 'beta', 'chat-1')
      && okWorker?.sessionId !== failedWorker?.sessionId,
      `${String(okWorker?.sessionId)} / ${String(failedWorker?.sessionId)}`)
    check('one prompt per worker',
      harness.requestsFor('alpha').filter(request => request.op === 'agent.prompt').length === 1
      && harness.requestsFor('beta').filter(request => request.op === 'agent.prompt').length === 1)
    const rendered = renderTool(tool, { prompt: 'audit the tree' }, value as unknown as Record<string, unknown>)
    check('render shows one line per worker',
      rendered.includes('alpha') && rendered.includes('beta')
      && rendered.includes('1 成功 / 1 失败'), rendered.slice(0, 240))
    check('render flags the failed worker', rendered.includes('[fail]'), rendered.slice(0, 240))
  }

  // ------------------------------------------------------------------ dispatch validation
  section('remote_pool_dispatch：peer 列表与权限')
  {
    const many: Record<string, PoolPeerProfile> = {}
    for (let index = 1; index <= MAX_POOL_WORKERS + 1; index += 1) {
      many[`peer-${index}`] = { name: `peer-${index}`, host: 'h', port: index, maxPermission: 3 }
    }
    const tooManyHarness = createHarness(many)
    const tooManyTool = toolOf(createPoolTools(tooManyHarness.deps), REMOTE_POOL_DISPATCH_TOOL)
    const tooMany = await callTool(tooManyTool, { prompt: 'x' })
    check('more than the max worker count is a readable error',
      tooMany.error !== undefined
      && tooMany.error.message.includes(`最多 ${MAX_POOL_WORKERS} 个 worker`)
      && tooMany.error.message.includes(String(MAX_POOL_WORKERS + 1)),
      String(tooMany.error))
    const spent = [...tooManyHarness.links.values()]
      .reduce((count, link) => count + link.requests.length, 0)
    check('an illegal peer list spends no round trip', spent === 0, String(spent))

    const harness = createHarness({
      good: { name: 'good', host: 'h', port: 1, maxPermission: 3 },
      limited: { name: 'limited', host: 'h', port: 2, maxPermission: 1 },
    })
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_POOL_DISPATCH_TOOL)
    const duplicate = await callTool(tool, { prompt: 'x', peers: ['good', 'good'] })
    check('duplicate peers is refused', duplicate.error !== undefined
      && duplicate.error.message.includes('重复'), String(duplicate.error))
    const unknown = await callTool(tool, { prompt: 'x', peers: ['nope'] })
    check('unknown peer is refused', unknown.error !== undefined
      && unknown.error.message.includes('未知 peer'), String(unknown.error))
    const empty = await callTool(tool, { prompt: 'x', peers: [] })
    check('empty peers list is refused', empty.error !== undefined
      && empty.error.message.includes('peers 为空'), String(empty.error))

    const mixed = await callTool(tool, { prompt: 'x' })
    check('a permission-denied worker does not fail the dispatch',
      mixed.error === undefined && mixed.value !== undefined, String(mixed.error))
    const mixedWorkers = (mixed.value?.workers ?? []) as PoolWorkerResult[]
    const goodWorker = mixedWorkers.find(worker => worker.peer === 'good')
    const limitedWorker = mixedWorkers.find(worker => worker.peer === 'limited')
    check('the permitted peer still ran', goodWorker?.ok === true, JSON.stringify(goodWorker))
    check('the denied peer reports the same permission error',
      limitedWorker?.ok === false && limitedWorker?.error?.includes('refusing agent.prompt') === true,
      JSON.stringify(limitedWorker))
    check('the denied peer spent no round trip', harness.requestsFor('limited').length === 0)
  }

  // ------------------------------------------------------------------ dispatch abort
  section('remote_pool_dispatch：本机取消 → 所有在途 worker 中断')
  {
    const harness = createHarness(twoPeers)
    const first = createBarrierLink()
    const second = createBarrierLink()
    harness.links.set('alpha', first.link)
    harness.links.set('beta', second.link)
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_POOL_DISPATCH_TOOL)
    const controller = new AbortController()
    const run = tool.execute(
      { prompt: 'long job' },
      { agent: { session: { id: 'chat-1' } }, signal: controller.signal } as never,
    )
    await tick()
    check('both workers in flight before the stop',
      first.promptsStarted() === 1 && second.promptsStarted() === 1)
    controller.abort()
    let thrown: unknown
    try {
      await run
    } catch (error) {
      thrown = error
    }
    check('the dispatch ends as an AbortError',
      thrown instanceof Error && thrown.name === 'AbortError', String(thrown))
    const interrupts = (link: FakeLink): RecordedRequest[] =>
      link.requests.filter(request => request.op === 'agent.interrupt')
    check('every in-flight worker was interrupted', interrupts(first.link).length === 1
      && interrupts(second.link).length === 1,
      `${interrupts(first.link).length}/${interrupts(second.link).length}`)
    check('interrupts target each worker\'s own session',
      interrupts(first.link)[0]?.args.sessionId === peerSessionId('remote', 'alpha', 'chat-1')
      && interrupts(second.link)[0]?.args.sessionId === peerSessionId('remote', 'beta', 'chat-1'))
    check('the already-issued prompt is not retried',
      first.link.requests.filter(request => request.op === 'agent.prompt').length === 1
      && second.link.requests.filter(request => request.op === 'agent.prompt').length === 1)
  }

  // ------------------------------------------------------------------ team hooks alone
  section('createTeamTaskHooks：无 Team / 成员判定 / 失败只 log')
  {
    const logs: string[] = []
    const hookLog = (message: string): void => { logs.push(message) }
    const noTeam = createTeamTaskHooks({ team: () => undefined, log: hookLog })
    const agent = { id: 'lead', session: { id: 'chat-1' } }
    check('no team → begin returns undefined',
      (await noTeam.begin(agent, { subject: 's', description: 'd' })) === undefined)
    await noTeam.finish(agent, undefined, { ok: 0, failed: 0, summary: '' })
    check('no team → finish is a harmless no-op', true)

    const memberOnly = createFakeTeam({ failOn: 'membership' })
    const notMember = createTeamTaskHooks({ team: () => memberOnly.facade, log: hookLog })
    check('non-member caller → begin returns undefined',
      (await notMember.begin(agent, { subject: 's', description: 'd' })) === undefined)
    check('non-member attempt never creates a task', memberOnly.calls.join(',') === 'membership',
      memberOnly.calls.join(','))
    check('non-member reason is logged', logs.some(line => line.includes('不在 Agent Teams')), logs.join(' | '))

    check('no agent → begin returns undefined',
      (await noTeam.begin(undefined, { subject: 's', description: 'd' })) === undefined)
  }

  // ------------------------------------------------------------------ team hooks order/CAS
  section('createTeamTaskHooks：create → claim → edit → complete，CAS 正确')
  {
    const team = createFakeTeam()
    const logs: string[] = []
    const hooks = createTeamTaskHooks({ team: () => team.facade, log: (m) => logs.push(m) })
    const agent = { id: 'lead', session: { id: 'chat-1' } }
    const token = await hooks.begin(agent, {
      subject: 'audit tree',
      description: '参与 peer: alpha, beta\n\nprompt: audit',
    })
    check('begin returns the claimed token', token?.taskId === 'task-1' && token?.revision === 2,
      JSON.stringify(token))
    check('calls start with create then claim', team.calls.join(',') === 'membership,create,claim',
      team.calls.join(','))
    check('subject is prefixed for the board',
      team.creates[0]?.subject === `${TEAM_SUBJECT_PREFIX}audit tree`, String(team.creates[0]?.subject))
    check('description keeps the peer list',
      team.creates[0]?.description.includes('alpha, beta') === true,
      String(team.creates[0]?.description))
    check('claim uses the creation revision', team.updates[0]?.expectedRevision === 1,
      String(team.updates[0]?.expectedRevision))

    await hooks.finish(agent, token, {
      ok: 1,
      failed: 1,
      summary: 'alpha: 成功 — done\nbeta: 失败 — refused',
    })
    check('finish edits then completes', team.calls.join(',') === 'membership,create,claim,edit,complete',
      team.calls.join(','))
    check('edit uses the claim revision', team.updates[1]?.expectedRevision === 2,
      String(team.updates[1]?.expectedRevision))
    check('complete uses the edit revision', team.updates[2]?.expectedRevision === 3,
      String(team.updates[2]?.expectedRevision))
    const editedDescription = team.updates[1]?.description ?? ''
    check('edit keeps the original description and appends the summary',
      editedDescription.includes('参与 peer') && editedDescription.includes('成功 1 个，失败 1 个')
      && editedDescription.includes('beta: 失败'), editedDescription)
    check('finish logs completion', logs.some(line => line.includes('已完成')), logs.join(' | '))
  }

  // ------------------------------------------------------------------ team hooks failures
  section('createTeamTaskHooks：失败只 log，不抛错')
  {
    const createFails = createFakeTeam({ failOn: 'create' })
    const logs: string[] = []
    const hooks = createTeamTaskHooks({ team: () => createFails.facade, log: (m) => logs.push(m) })
    const agent = { id: 'lead', session: { id: 'chat-1' } }
    check('create failure → undefined token',
      (await hooks.begin(agent, { subject: 's', description: 'd' })) === undefined)
    check('create failure is logged', logs.some(line => line.includes('创建看板任务失败')), logs.join(' | '))

    const claimFails = createFakeTeam({ failOn: 'claim' })
    const claimHooks = createTeamTaskHooks({ team: () => claimFails.facade, log: (m) => logs.push(m) })
    check('claim failure → undefined token',
      (await claimHooks.begin(agent, { subject: 's', description: 'd' })) === undefined)
    check('claim failure was logged',
      logs.some(line => line.includes('认领看板任务')), logs.join(' | '))

    const editFails = createFakeTeam({ failOn: 'edit' })
    const editLogs: string[] = []
    const editHooks = createTeamTaskHooks({ team: () => editFails.facade, log: (m) => editLogs.push(m) })
    const token = await editHooks.begin(agent, { subject: 's', description: 'd' })
    let threw = false
    try {
      await editHooks.finish(agent, token, { ok: 1, failed: 0, summary: 'ok' })
    } catch {
      threw = true
    }
    check('edit failure does not throw', !threw)
    check('edit failure never completes the task',
      !editFails.calls.includes('complete'), editFails.calls.join(','))
    check('edit failure is logged', editLogs.some(line => line.includes('写结果摘要失败')),
      editLogs.join(' | '))

    const completeFails = createFakeTeam({ failOn: 'complete' })
    const completeLogs: string[] = []
    const completeHooks = createTeamTaskHooks({
      team: () => completeFails.facade,
      log: (m) => completeLogs.push(m),
    })
    const completeToken = await completeHooks.begin(agent, { subject: 's', description: 'd' })
    let completeThrew = false
    try {
      await completeHooks.finish(agent, completeToken, { ok: 0, failed: 0, summary: '' })
    } catch {
      completeThrew = true
    }
    check('complete failure does not throw', !completeThrew)
    check('complete failure is logged',
      completeLogs.some(line => line.includes('complete 看板任务')), completeLogs.join(' | '))
  }

  // ------------------------------------------------------------------ team truncation
  section('createTeamTaskHooks：标题/描述截断')
  {
    const team = createFakeTeam()
    const hooks = createTeamTaskHooks({ team: () => team.facade, log: () => {} })
    const agent = { id: 'lead', session: { id: 'chat-1' } }
    await hooks.begin(agent, {
      subject: 'x'.repeat(500),
      description: 'y'.repeat(5000),
    })
    check('subject truncated to the Team limit',
      (team.creates[0]?.subject.length ?? 0) === MAX_TEAM_SUBJECT_CHARS,
      String(team.creates[0]?.subject.length))
    check('subject keeps the 远端 prefix',
      team.creates[0]?.subject.startsWith(TEAM_SUBJECT_PREFIX) === true)
    check('description truncated to the module limit',
      (team.creates[0]?.description.length ?? 0) === MAX_TEAM_DESCRIPTION_CHARS,
      String(team.creates[0]?.description.length))

    const small = createFakeTeam()
    const smallHooks = createTeamTaskHooks({
      team: () => small.facade,
      log: () => {},
      maxSummaryChars: 10, // 被夹到最小 80
    })
    const token = await smallHooks.begin(agent, { subject: 's', description: 'd' })
    await smallHooks.finish(agent, token, { ok: 1, failed: 0, summary: 'z'.repeat(400) })
    // updates[0] is the claim from begin; the edit is the first update of finish.
    const smallDescription = small.updates[1]?.description ?? ''
    check('summary length is clamped but bounded by the description limit',
      smallDescription.length > 0 && smallDescription.length <= MAX_TEAM_DESCRIPTION_CHARS,
      String(smallDescription.length))
  }

  // ------------------------------------------------------------------ integration
  section('dispatch × Team：看板记账挂在调用方名下')
  {
    const harness = createHarness(twoPeers, {
      handlerFor: (peer) => peer === 'alpha'
        ? () => Promise.resolve({ reply: 'alpha done', reason: 'completed' })
        : () => Promise.resolve({ reply: 'beta done', reason: 'completed' }),
    })
    const team = createFakeTeam()
    const logs: string[] = []
    const hooks = createTeamTaskHooks({ team: () => team.facade, log: (m) => logs.push(m) })
    harness.deps.teamTask = hooks
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_POOL_DISPATCH_TOOL)
    const exec = { agent: { id: 'lead', session: { id: 'chat-1' } }, signal: new AbortController().signal }
    const { value, error } = await callTool(tool, {
      prompt: 'audit the tree',
      description: 'tree audit',
    }, exec)
    check('dispatch succeeds', error === undefined && value !== undefined, String(error))
    check('one task created per dispatch', team.creates.length === 1, String(team.creates.length))
    check('task subject is prefixed and named after the dispatch',
      team.creates[0]?.subject === `${TEAM_SUBJECT_PREFIX}tree audit`, String(team.creates[0]?.subject))
    check('task description lists participants and the prompt',
      team.creates[0]?.description.includes('参与 peer（2）: alpha, beta') === true
      && team.creates[0]?.description.includes('prompt:') === true,
      String(team.creates[0]?.description))
    check('board lifecycle order',
      team.calls.join(',') === 'membership,create,claim,edit,complete', team.calls.join(','))
    check('result summary written to the board',
      (team.updates[1]?.description ?? '').includes('成功 2 个，失败 0 个'),
      String(team.updates[1]?.description))
  }

  section('dispatch × Team：调用方不是成员 / finish 抛错都不影响结果')
  {
    const harness = createHarness(twoPeers, {
      handlerFor: () => () => Promise.resolve({ reply: 'ok', reason: 'completed' }),
    })
    const outsider = createFakeTeam({ failOn: 'membership' })
    const logs: string[] = []
    harness.deps.teamTask = createTeamTaskHooks({
      team: () => outsider.facade,
      log: (m) => logs.push(m),
    })
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_POOL_DISPATCH_TOOL)
    const exec = { agent: { id: 'someone', session: { id: 'chat-1' } }, signal: new AbortController().signal }
    const outsiderRun = await callTool(tool, { prompt: 'x' }, exec)
    check('non-member dispatch still succeeds',
      outsiderRun.error === undefined && outsiderRun.value?.summary !== undefined,
      String(outsiderRun.error))
    check('non-member creates no task', outsider.creates.length === 0, String(outsider.creates.length))

    const broken = createHarness(twoPeers, {
      handlerFor: () => () => Promise.resolve({ reply: 'ok', reason: 'completed' }),
    })
    broken.deps.teamTask = {
      begin: async () => undefined,
      finish: async () => { throw new Error('board exploded') },
    }
    const brokenTool = toolOf(createPoolTools(broken.deps), REMOTE_POOL_DISPATCH_TOOL)
    const brokenRun = await callTool(brokenTool, { prompt: 'x' }, exec)
    check('a throwing finish does not break the dispatched result',
      brokenRun.error === undefined
      && (brokenRun.value?.summary as { ok?: number } | undefined)?.ok === 2,
      String(brokenRun.error))
    check('the a throwing finish is logged',
      broken.logs.some(line => line.includes('finish 失败')), broken.logs.join(' | '))
  }

  // ------------------------------------------------------------------ team dispatch
  section('remote_team_dispatch：没有 Team 时必须报错，不能静默退化')
  {
    const exec = { agent: { id: 'lead', session: { id: 'chat-1' } }, signal: new AbortController().signal }
    const promptCount = (harness: PoolHarness): number =>
      [...harness.links.values()]
        .reduce((count, link) => count + link.requests.filter(request => request.op === 'agent.prompt').length, 0)

    const noHooks = createHarness(twoPeers)
    const noHooksRun = await callTool(
      toolOf(createPoolTools(noHooks.deps), REMOTE_TEAM_DISPATCH_TOOL),
      { description: 'board audit', prompt: 'audit' },
      exec,
    )
    check('no teamTask at all → readable refusal',
      noHooksRun.error !== undefined
      && noHooksRun.error.message.includes('当前会话不在 Agent Teams 里')
      && noHooksRun.error.message.includes('remote_pool_dispatch / remote_worker_prompt'),
      String(noHooksRun.error))
    check('no teamTask → zero remote prompts spent', promptCount(noHooks) === 0, String(promptCount(noHooks)))

    const emptyTeam = createHarness(twoPeers)
    emptyTeam.deps.teamTask = createTeamTaskHooks({ team: () => undefined, log: () => {} })
    const emptyTeamRun = await callTool(
      toolOf(createPoolTools(emptyTeam.deps), REMOTE_TEAM_DISPATCH_TOOL),
      { description: 'board audit', prompt: 'audit' },
      exec,
    )
    check('hooks present but no agentTeams → readable refusal',
      emptyTeamRun.error !== undefined
      && emptyTeamRun.error.message.includes('当前会话不在 Agent Teams 里'),
      String(emptyTeamRun.error))
    check('hooks present but no agentTeams → zero remote prompts spent',
      promptCount(emptyTeam) === 0)

    const outsider = createHarness(twoPeers)
    const outsiderTeam = createFakeTeam({ failOn: 'membership' })
    outsider.deps.teamTask = createTeamTaskHooks({ team: () => outsiderTeam.facade, log: () => {} })
    const outsiderRun = await callTool(
      toolOf(createPoolTools(outsider.deps), REMOTE_TEAM_DISPATCH_TOOL),
      { description: 'board audit', prompt: 'audit' },
      exec,
    )
    check('caller not a Team member → readable refusal',
      outsiderRun.error !== undefined
      && outsiderRun.error.message.includes('当前会话不在 Agent Teams 里'),
      String(outsiderRun.error))
    check('caller not a Team member → no task and no prompt',
      outsiderTeam.creates.length === 0 && promptCount(outsider) === 0)

    const undefinedToken = createHarness(twoPeers)
    undefinedToken.deps.teamTask = {
      begin: async () => undefined,
      finish: async () => {},
    }
    const undefinedRun = await callTool(
      toolOf(createPoolTools(undefinedToken.deps), REMOTE_TEAM_DISPATCH_TOOL),
      { description: 'board audit', prompt: 'audit' },
      exec,
    )
    check('begin returning undefined is refused, never silently dispatched',
      undefinedRun.error !== undefined
      && undefinedRun.error.message.includes('不在 Agent Teams 里')
      && promptCount(undefinedToken) === 0,
      String(undefinedRun.error))
  }

  section('remote_team_dispatch：有 Team 时登记 → 跑 → 收，并带回 taskId')
  {
    const harness = createHarness(twoPeers, {
      handlerFor: () => () => Promise.resolve({ reply: 'board done', reason: 'completed' }),
    })
    const team = createFakeTeam()
    harness.deps.teamTask = createTeamTaskHooks({ team: () => team.facade, log: () => {} })
    const tool = toolOf(createPoolTools(harness.deps), REMOTE_TEAM_DISPATCH_TOOL)
    const exec = { agent: { id: 'lead', session: { id: 'chat-1' } }, signal: new AbortController().signal }
    const { value, error } = await callTool(tool, {
      description: 'board audit',
      prompt: 'audit the tree',
    }, exec)
    check('call succeeds', error === undefined && value !== undefined, String(error))
    check('taskId is returned for team_task_get', value?.taskId === 'task-1', String(value?.taskId))
    const workers = (value?.workers ?? []) as PoolWorkerResult[]
    check('omitted peer uses the first declared peer',
      workers.length === 1 && workers[0]?.peer === 'alpha', JSON.stringify(workers))
    check('worker ran on the peer\'s deterministic session',
      workers[0]?.sessionId === peerSessionId('remote', 'alpha', 'chat-1'),
      String(workers[0]?.sessionId))
    check('worker reply aggregated', workers[0]?.ok === true && workers[0]?.reply === 'board done',
      JSON.stringify(workers[0]))
    check('board lifecycle order',
      team.calls.join(',') === 'membership,create,claim,edit,complete', team.calls.join(','))
    check('subject is prefixed and named after the description',
      team.creates[0]?.subject === `${TEAM_SUBJECT_PREFIX}board audit`, String(team.creates[0]?.subject))
    check('task description names the single participant and the prompt',
      team.creates[0]?.description.includes('参与 peer（1）: alpha') === true
      && team.creates[0]?.description.includes('prompt:') === true,
      String(team.creates[0]?.description))
    check('edit uses the claim revision', team.updates[1]?.expectedRevision === 2,
      String(team.updates[1]?.expectedRevision))
    check('complete uses the edit revision', team.updates[2]?.expectedRevision === 3,
      String(team.updates[2]?.expectedRevision))
    check('result summary written back to the task',
      (team.updates[1]?.description ?? '').includes('成功 1 个，失败 0 个'),
      String(team.updates[1]?.description))
    const rendered = renderTool(tool, { description: 'board audit', prompt: 'audit the tree' }, value ?? {})
    check('render shows the taskId and one worker line',
      rendered.includes('task-1') && rendered.includes('alpha') && rendered.includes('board done'),
      rendered.slice(0, 240))
    check('render restates the owner boundary',
      rendered.includes('owner 是调用方'), rendered.slice(-160))

    // 显式 peer 走同一套校验；未知 peer 在发出请求前就失败。
    const explicit = await callTool(tool, { description: 'b', prompt: 'x', peer: 'beta' }, exec)
    const explicitWorkers = (explicit.value?.workers ?? []) as PoolWorkerResult[]
    check('explicit peer selects that peer',
      explicit.error === undefined && explicitWorkers[0]?.peer === 'beta',
      `${String(explicit.error)} / ${JSON.stringify(explicitWorkers)}`)
    const unknown = await callTool(tool, { description: 'b', prompt: 'x', peer: 'nope' }, exec)
    check('unknown peer is refused', unknown.error !== undefined
      && unknown.error.message.includes('未知 peer "nope"'), String(unknown.error))
    const blank = await callTool(tool, { description: '   ', prompt: 'x' }, exec)
    check('blank description is refused', blank.error !== undefined
      && blank.error.message.includes('description 不能为空'), String(blank.error))
  }

  console.log(`\n${checks - failures}/${checks} checks passed`)
  if (failures > 0) process.exitCode = 1
}

await main()
