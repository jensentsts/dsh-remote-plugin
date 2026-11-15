/**
 * Self-test for background remote runs — no peer, no cordis.
 *
 * Two layers are covered separately:
 *
 * 1. the registry, which owns the concurrency ceiling, retention, ordering,
 *    cancellation state and settlement bookkeeping (with an injected clock, so
 *    duration and TTL are exact);
 * 2. the four tools, driven through a fake dependency facade, which must resolve
 *    the session exactly like `remote_agent_prompt`, answer immediately, surface
 *    the peer's `agent.note` capability (or its fallback), and render something
 *    the model can act on.
 *
 * The module is deliberately free of cordis and of the transport, so this runs
 * with `node --import tsx/esm` and nothing else.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/remote-runs.test.ts
 */

import {
  MAX_STATUS_WAIT_MS,
  clampStatusWait,
  createRunRegistry,
  createRunTools,
  toRunRow,
} from '../src/remote-runs.ts'
import type {
  RemoteRunRecord,
  RunPromptRequest,
  RunToolDeps,
} from '../src/remote-runs.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

/** The tool-surface facade, recording exactly what the tools ask of the client. */
interface Calls {
  resolved: Array<{ args: { session_id?: string }, exec: unknown }>
  started: RunPromptRequest[]
  sent: Array<{ sessionId: string, text: string }>
  interrupted: string[]
  remembered: Array<{ exec: unknown, sessionId: string }>
  logs: string[]
}

function fakeDeps(options: {
  maxRuns?: number
  send?: RunToolDeps['sendMessage']
  startThrows?: boolean
} = {}): { deps: RunToolDeps, calls: Calls } {
  const calls: Calls = { resolved: [], started: [], sent: [], interrupted: [], remembered: [], logs: [] }
  let counter = 0
  const deps: RunToolDeps = {
    async resolveSession(args, exec) {
      calls.resolved.push({ args, exec })
      const explicit = args.session_id
      return explicit === undefined
        ? { sessionId: 'remote-anchor', origin: 'anchor' }
        : { sessionId: explicit, origin: 'explicit' }
    },
    startPrompt(request) {
      if (options.startThrows === true) throw new Error('link is down')
      calls.started.push(request)
    },
    async sendMessage(request) {
      calls.sent.push({ sessionId: request.sessionId, text: request.text })
      if (options.send !== undefined) return await options.send(request)
      return { accepted: true, method: 'agent.note' }
    },
    async interrupt(sessionId) {
      calls.interrupted.push(sessionId)
    },
    rememberScope(exec, sessionId) {
      calls.remembered.push({ exec, sessionId })
    },
    log(message) { calls.logs.push(message) },
    maxRuns: () => options.maxRuns ?? 8,
    makeRunId: () => { counter += 1; return `run-test-${counter}` },
  }
  return { deps, calls }
}

const exec = { agent: { session: { id: 'local-chat' } }, signal: new AbortController().signal }

/** One tool out of one `createRunTools` result (they share a registry). */
function toolOf(tools: ReturnType<typeof createRunTools>, name: string): ReturnType<typeof createRunTools>[number] {
  const tool = tools.find(candidate => candidate.name === name)
  if (tool === undefined) throw new Error(`missing tool ${name}`)
  return tool
}

/** Execute one tool call and return its JSON value. */
async function run(tool: ReturnType<typeof createRunTools>[number], args: unknown): Promise<Record<string, unknown>> {
  return await tool.execute(args, exec as never) as unknown as Record<string, unknown>
}

// ---------------------------------------------------------------------------
// 1. The registry
// ---------------------------------------------------------------------------

console.log('\n== 1. the registry enforces the concurrent-run ceiling ==')
{
  const clock = { at: 1000 }
  let counter = 0
  const registry = createRunRegistry({
    maxRuns: () => 2,
    now: () => clock.at,
    makeRunId: () => `run-${counter += 1}`,
  })
  const first = registry.start({ sessionId: 'remote-a', description: 'first', text: 'do the first thing' })
  check('start returns a running record', first.status === 'running' && first.id === 'run-1', JSON.stringify(first))
  check('the text is previewed, not stored whole', first.textPreview === 'do the first thing', first.textPreview)
  registry.start({ sessionId: 'remote-a', description: 'second', text: 'do the second thing' })
  check('one slot remains', registry.activeCount() === 2, String(registry.activeCount()))
  let threw: unknown
  try {
    registry.start({ sessionId: 'remote-a', description: 'third', text: 'nope' })
  } catch (error) { threw = error }
  check('the third start is refused with a readable error',
    threw instanceof Error && threw.message.includes('已有 2 个后台远端运行') && threw.message.includes('maxBackgroundRuns'),
    String(threw))
  check('the refused run was not registered', registry.list().length === 2, String(registry.list().length))
}

console.log('\n== 2. settlement records status, duration and reply ==')
{
  const clock = { at: 1000 }
  const registry = createRunRegistry({ maxRuns: () => 4, now: () => clock.at, makeRunId: () => 'run-a' })
  const started = registry.start({ sessionId: 'remote-a', description: 'audit', text: 'audit the tree' })
  check('duration is absent while running', started.durationMs === undefined)
  check('settling a running run is accepted', registry.settle('run-a', { status: 'completed', reply: 'all clean', reason: 'completed' }) !== undefined)
  const settled = registry.get('run-a') as RemoteRunRecord
  check('status completed', settled.status === 'completed', settled.status)
  check('duration measured from the injected clock', settled.durationMs === 0, String(settled.durationMs))
  check('reply kept in full', settled.reply === 'all clean', settled.reply)
  check('reason kept', settled.reason === 'completed', String(settled.reason))
  check('settledAt stamped', settled.settledAt === 1000, String(settled.settledAt))
  check('a second settle is a no-op', registry.settle('run-a', { status: 'error' }) === undefined)
  check('unknown ids settle to undefined', registry.settle('run-nope', { status: 'error' }) === undefined)
  check('the first outcome stays final', registry.get('run-a')?.status === 'completed', String(registry.get('run-a')?.status))
}

console.log('\n== 3. cancellation only applies while running ==')
{
  const registry = createRunRegistry({ maxRuns: () => 4, makeRunId: () => 'run-c' })
  registry.start({ sessionId: 'remote-c', description: 'cancel me', text: 'work' })
  check('cancel of a running run changes state', registry.cancel('run-c') === true)
  check('and marks it cancelling', registry.get('run-c')?.status === 'cancelling', String(registry.get('run-c')?.status))
  check('cancelling is still active', registry.activeCount() === 1, String(registry.activeCount()))
  check('a cancelled run still accepts its terminal outcome', registry.settle('run-c', { status: 'aborted', interrupted: true }) !== undefined)
  const settled = registry.get('run-c')
  check('settled aborted', settled?.status === 'aborted', String(settled?.status))
  check('interrupted flag kept', settled?.interrupted === true)
  check('cancel after settlement does nothing', registry.cancel('run-c') === false)
  check('unknown cancel does nothing', registry.cancel('run-nope') === false)
}

console.log('\n== 4. list ordering and settled retention ==')
{
  const clock = { at: 1000 }
  let counter = 0
  const registry = createRunRegistry({
    maxRuns: () => 8,
    maxSettled: 3,
    settledTtlMs: 24 * 60 * 60 * 1000,
    now: () => clock.at,
    makeRunId: () => `run-${counter += 1}`,
  })
  for (let index = 1; index <= 4; index += 1) {
    registry.start({ sessionId: 'remote-l', description: `settled ${index}`, text: 'x' })
    clock.at += 10
    registry.settle(`run-${index}`, { status: 'completed', reply: `reply ${index}` })
    clock.at += 10
  }
  registry.start({ sessionId: 'remote-l', description: 'still running', text: 'y' })
  const listed = registry.list()
  check('the oldest settled record was dropped at the 3-record limit',
    !listed.some(record => record.id === 'run-1') && listed.length === 4,
    listed.map(record => record.id).join(','))
  check('running comes first', listed[0]?.status === 'running', String(listed[0]?.status))
  check('settled runs are newest first',
    listed.slice(1).map(record => record.id).join(',') === 'run-4,run-3,run-2',
    listed.slice(1).map(record => record.id).join(','))

  // 24 h TTL: old settled records disappear once the clock moves past it.
  clock.at += 25 * 60 * 60 * 1000
  const afterTtl = registry.list()
  check('expired settled runs are pruned', afterTtl.length === 1 && afterTtl[0]?.status === 'running',
    afterTtl.map(record => record.id).join(','))
  check('a pruned id is unknown', registry.get('run-2') === undefined)
}

console.log('\n== 5. waitFor resolves on settlement, and times out as running ==')
{
  const registry = createRunRegistry({ maxRuns: () => 4, makeRunId: () => 'run-w' })
  registry.start({ sessionId: 'remote-w', description: 'wait', text: 'work' })
  const settledWait = registry.waitFor('run-w', 1000)
  registry.settle('run-w', { status: 'completed', reply: 'done waiting' })
  const waited = await settledWait
  check('waitFor resolves with the settled record', waited?.status === 'completed' && waited.reply === 'done waiting', JSON.stringify(waited))

  const registry2 = createRunRegistry({ maxRuns: () => 4, makeRunId: () => 'run-t' })
  registry2.start({ sessionId: 'remote-t', description: 'timeout', text: 'work' })
  const began = Date.now()
  const timedOut = await registry2.waitFor('run-t', 25)
  const elapsed = Date.now() - began
  check('a timed-out wait reports the state instead of throwing',
    timedOut?.status === 'running', JSON.stringify(timedOut))
  check('and actually waited', elapsed >= 15, `${elapsed} ms`)
  check('waitFor of an unknown id is undefined', await registry2.waitFor('run-nope', 100) === undefined)
  check('wait_ms is clamped into range', clampStatusWait(99_999_999) === MAX_STATUS_WAIT_MS
    && clampStatusWait(-5) === 0 && clampStatusWait(undefined) === 0, String(clampStatusWait(99_999_999)))
}

console.log('\n== 6. toRunRow is the compact list shape ==')
{
  const record: RemoteRunRecord = {
    id: 'run-row', sessionId: 'remote-row', description: 'row test', textPreview: 'x',
    status: 'completed', startedAt: 10, settledAt: 20, reply: 'a'.repeat(200), durationMs: 10,
  }
  const row = toRunRow(record, 20)
  check('row names the run and session', row.runId === 'run-row' && row.sessionId === 'remote-row')
  check('settledAt carried', row.settledAt === 20)
  check('reply previewed and clipped', typeof row.replyPreview === 'string' && row.replyPreview.length <= 20 && row.replyPreview.endsWith('…'),
    String(row.replyPreview))
  const running: RemoteRunRecord = { ...record, status: 'running', settledAt: undefined, reply: undefined }
  check('a running row has no preview', toRunRow(running).replyPreview === undefined)
}

// ---------------------------------------------------------------------------
// 2. The tools
// ---------------------------------------------------------------------------

console.log('\n== 7. remote_run_start answers immediately and resolves like the prompt tool ==')
{
  const { deps, calls } = fakeDeps()
  const tools = createRunTools(deps)
  const start = toolOf(tools, 'remote_run_start')
  const value = await run(start, { description: 'audit the tree', text: 'list every file' })
  check('returns a run id', value.runId === 'run-test-1', String(value.runId))
  check('returns the resolved session', value.sessionId === 'remote-anchor', String(value.sessionId))
  check('reports the resolution origin', value.origin === 'anchor', String(value.origin))
  check('reports running', value.status === 'running', String(value.status))
  check('session resolution went through the facade', calls.resolved.length === 1 && calls.resolved[0]?.args.session_id === undefined)
  check('the prompt was started with the same text', calls.started[0]?.text === 'list every file', String(calls.started[0]?.text))
  check('the default peer deadline is 0 (unlimited)', calls.started[0]?.timeoutMs === 0, String(calls.started[0]?.timeoutMs))
  check('the run id is passed to the client wiring', calls.started[0]?.runId === 'run-test-1')
  check('the scope remembers the conversation', calls.remembered[0]?.sessionId === 'remote-anchor')
  check('the calling agent is handed through', calls.remembered[0]?.exec === exec)

  // The key behaviour: no settlement has happened, yet the call already returned.
  const status = toolOf(tools, 'remote_run_status')
  const viewed = await run(status, { run_id: 'run-test-1' })
  check('status is still running right after start', viewed.status === 'running', String(viewed.status))

  // An explicit session id wins, exactly like remote_agent_prompt.
  const explicit = await run(start, { description: 'explicit', text: 'go', session_id: 'remote-explicit' })
  check('explicit session_id is passed through', explicit.sessionId === 'remote-explicit' && explicit.origin === 'explicit',
    `${String(explicit.sessionId)}/${String(explicit.origin)}`)
  check('and the facade saw it', calls.resolved[1]?.args.session_id === 'remote-explicit')
}

console.log('\n== 8. remote_run_start refuses a request that cannot be started ==')
{
  const { deps } = fakeDeps({ maxRuns: 1 })
  const tools = createRunTools(deps)
  const start = toolOf(tools, 'remote_run_start')
  await run(start, { description: 'first', text: 'work' })
  let threw: unknown
  try {
    await run(start, { description: 'second', text: 'work' })
  } catch (error) { threw = error }
  check('the ceiling surfaces as a readable error',
    threw instanceof Error && threw.message.includes('已有 1 个后台远端运行'), String(threw))

  let emptyThrew: unknown
  try {
    await run(start, { description: '   ', text: 'work' })
  } catch (error) { emptyThrew = error }
  check('blank description is rejected', emptyThrew instanceof Error && emptyThrew.message.includes('description'), String(emptyThrew))

  const throwing = fakeDeps({ startThrows: true })
  const throwingTools = createRunTools(throwing.deps)
  let startThrew: unknown
  try {
    await run(toolOf(throwingTools, 'remote_run_start'), { description: 'boom', text: 'work' })
  } catch (error) { startThrew = error }
  check('a client-side start failure propagates', startThrew instanceof Error && startThrew.message.includes('link is down'), String(startThrew))
  const afterFailure = await run(toolOf(throwingTools, 'remote_run_status'), { run_id: 'run-test-1' })
  check('and the run is left settled as error', afterFailure.status === 'error', String(afterFailure.status))
}

console.log('\n== 9. settlement flows into the status tool and its rendering ==')
{
  const { deps, calls } = fakeDeps({ maxRuns: 4 })
  const tools = createRunTools(deps)
  const start = toolOf(tools, 'remote_run_start')
  await run(start, { description: 'audit', text: 'audit the tree' })
  const request = calls.started[0]
  if (request === undefined) throw new Error('start did not reach the facade')
  request.onSettled({ status: 'completed', reply: 'the tree has 12 files', reason: 'completed' })
  const status = toolOf(tools, 'remote_run_status')
  const viewed = await run(status, { run_id: 'run-test-1' })
  check('status completed', viewed.status === 'completed', String(viewed.status))
  check('reply returned in full', viewed.reply === 'the tree has 12 files', String(viewed.reply))
  check('duration recorded', typeof viewed.durationMs === 'number', String(viewed.durationMs))
  const rendered = status.output.render({ run_id: 'run-test-1' }, viewed as never) as Array<{ text?: string }>
  check('the render shows the deliverable', String(rendered[0]?.text).includes('the tree has 12 files'), String(rendered[0]?.text).slice(0, 120))

  // Another run, interrupted by the peer's own user.
  await run(start, { description: 'interrupted', text: 'work' })
  const second = calls.started[1]
  second?.onSettled({ status: 'aborted', interrupted: true, reason: 'user' })
  const stopped = await run(status, { run_id: 'run-test-2' })
  check('interrupted flag surfaced', stopped.interrupted === true)
  const stoppedRender = status.output.render({ run_id: 'run-test-2' }, stopped as never) as Array<{ text?: string }>
  check('the render tells the model not to retry',
    String(stoppedRender[0]?.text).includes('打断') && String(stoppedRender[0]?.text).includes('不要重试'),
    String(stoppedRender[0]?.text).slice(0, 160))
}

console.log('\n== 10. remote_run_status lists runs, waits, and rejects unknown ids ==')
{
  const { deps, calls } = fakeDeps({ maxRuns: 4 })
  const tools = createRunTools(deps)
  const start = toolOf(tools, 'remote_run_start')
  const status = toolOf(tools, 'remote_run_status')

  const empty = await run(status, {})
  const emptyRendered = status.output.render({}, empty as never) as Array<{ text?: string }>
  check('an empty list says so', String(emptyRendered[0]?.text).includes('没有后台远端运行'), String(emptyRendered[0]?.text))

  await run(start, { description: 'long audit', text: 'audit' })
  await run(start, { description: 'short job', text: 'short' })
  calls.started[1]?.onSettled({ status: 'completed', reply: 'short done' })
  const listed = await run(status, {})
  const runs = listed.runs as Array<{ runId: string, status: string, description: string, replyPreview?: string }>
  check('running comes first in the list', runs[0]?.status === 'running', JSON.stringify(runs.map(row => row.status)))
  check('then the settled run with a preview', runs[1]?.status === 'completed' && runs[1]?.replyPreview === 'short done',
    JSON.stringify(runs[1]))
  check('counts are reported', listed.running === 1 && listed.settled === 1, JSON.stringify({ running: listed.running, settled: listed.settled }))
  const listedRender = status.output.render({}, listed as never) as Array<{ text?: string }>
  check('the list render carries the title and status',
    String(listedRender[0]?.text).includes('long audit') && String(listedRender[0]?.text).includes('running'),
    String(listedRender[0]?.text).slice(0, 160))

  // wait_ms on a running run must come back as running, not as an error.
  const began = Date.now()
  const waited = await run(status, { run_id: 'run-test-1', wait_ms: 25 })
  check('a short wait on a running run returns running', waited.status === 'running', String(waited.status))
  check('and the tool really waited', Date.now() - began >= 15, `${Date.now() - began} ms`)

  let threw: unknown
  try {
    await run(status, { run_id: 'run-does-not-exist' })
  } catch (error) { threw = error }
  check('an unknown run id is a readable error',
    threw instanceof Error && threw.message.includes('没有 id 为') && threw.message.includes('run-does-not-exist'), String(threw))
}

console.log('\n== 11. remote_run_cancel marks the run and interrupts its session ==')
{
  const { deps, calls } = fakeDeps({ maxRuns: 4 })
  const tools = createRunTools(deps)
  const start = toolOf(tools, 'remote_run_start')
  const cancel = toolOf(tools, 'remote_run_cancel')
  const status = toolOf(tools, 'remote_run_status')
  await run(start, { description: 'cancel me', text: 'work', session_id: 'remote-cancel' })

  const cancelled = await run(cancel, { run_id: 'run-test-1' })
  check('cancel reports success', cancelled.cancelled === true, String(cancelled.cancelled))
  check('and the cancelling state', cancelled.status === 'cancelling', String(cancelled.status))
  check('the peer session was interrupted', calls.interrupted[0] === 'remote-cancel', JSON.stringify(calls.interrupted))
  const rendered = cancel.output.render({ run_id: 'run-test-1' }, cancelled as never) as Array<{ text?: string }>
  check('the render tells the model to check status, not retry',
    String(rendered[0]?.text).includes('remote_run_status'), String(rendered[0]?.text))

  const viewed = await run(status, { run_id: 'run-test-1' })
  check('the run stays cancelling until the peer settles', viewed.status === 'cancelling', String(viewed.status))

  calls.started[0]?.onSettled({ status: 'aborted', interrupted: true, reason: 'aborted' })
  const second = await run(cancel, { run_id: 'run-test-1' })
  check('cancelling a settled run is a no-op', second.cancelled === false && second.status === 'aborted',
    `${String(second.cancelled)}/${String(second.status)}`)
  check('and no second interrupt was sent', calls.interrupted.length === 1, JSON.stringify(calls.interrupted))

  let threw: unknown
  try {
    await run(cancel, { run_id: 'run-nope' })
  } catch (error) { threw = error }
  check('cancelling an unknown run is an error', threw instanceof Error && threw.message.includes('没有 id 为'), String(threw))
}

console.log('\n== 12. remote_send_message: agent.note path, fallback path, session resolution ==')
{
  const note = fakeDeps({ maxRuns: 4 })
  const noteTools = createRunTools(note.deps)
  const start = toolOf(noteTools, 'remote_run_start')
  const send = toolOf(noteTools, 'remote_send_message')
  await run(start, { description: 'run', text: 'work' })
  const viaRun = await run(send, { message: 'also check the docs', run_id: 'run-test-1' })
  check('run_id resolves the run\'s session', viaRun.sessionId === 'remote-anchor', String(viaRun.sessionId))
  check('agent.note is reported as the method', viaRun.method === 'agent.note', String(viaRun.method))
  check('the message reached the facade', note.calls.sent[0]?.text === 'also check the docs', JSON.stringify(note.calls.sent))
  check('the note remembers this chat\'s remote session', note.calls.remembered.some(row => row.sessionId === 'remote-anchor'))
  check('no session resolution was needed for run_id', note.calls.resolved.length === 1, String(note.calls.resolved.length))
  const rendered = send.output.render({ message: 'x' }, viaRun as never) as Array<{ text?: string }>
  check('the render names the method', String(rendered[0]?.text).includes('agent.note'), String(rendered[0]?.text).slice(0, 120))

  // Explicit session_id, then the calling chat's own conversation.
  const explicit = await run(send, { message: 'hello', session_id: 'remote-explicit' })
  check('explicit session_id used verbatim', explicit.sessionId === 'remote-explicit', String(explicit.sessionId))
  const anchored = await run(send, { message: 'hello again' })
  check('no ids at all falls back to the chat\'s conversation', anchored.sessionId === 'remote-anchor', String(anchored.sessionId))

  let emptyThrew: unknown
  try {
    await run(send, { message: '   ' })
  } catch (error) { emptyThrew = error }
  check('an empty message is rejected', emptyThrew instanceof Error && emptyThrew.message.includes('message'), String(emptyThrew))

  let unknownThrew: unknown
  try {
    await run(send, { message: 'hi', run_id: 'run-nope' })
  } catch (error) { unknownThrew = error }
  check('an unknown run_id is a readable error', unknownThrew instanceof Error && unknownThrew.message.includes('没有 id 为'), String(unknownThrew))

  // Old peer: the client queues an agent.prompt and says so.
  const fallback = fakeDeps({
    maxRuns: 4,
    send: async () => ({
      accepted: true,
      method: 'agent.prompt',
      note: '对端旧版本；消息已排队，但完成时间不可观测',
    }),
  })
  const fallbackSend = toolOf(createRunTools(fallback.deps), 'remote_send_message')
  const fallbackValue = await run(fallbackSend, { message: 'queued', session_id: 'remote-old' })
  check('fallback method reported', fallbackValue.method === 'agent.prompt', String(fallbackValue.method))
  check('fallback caveat reported', String(fallbackValue.note).includes('对端旧版本'), String(fallbackValue.note))
  const fallbackRender = fallbackSend.output.render({ message: 'x' }, fallbackValue as never) as Array<{ text?: string }>
  check('the caveat is visible to the model', String(fallbackRender[0]?.text).includes('对端旧版本'),
    String(fallbackRender[0]?.text))
}

console.log('\n== 13. the tool surface is the documented one ==')
{
  const { deps } = fakeDeps()
  const tools = createRunTools(deps)
  const names = tools.map(tool => tool.name)
  check('exactly the four control-plane tools, no subagent_ prefix',
    names.join(',') === 'remote_run_start,remote_run_status,remote_run_cancel,remote_send_message', names.join(','))
  const start = tools.find(tool => tool.name === 'remote_run_start')
  const required = (start?.parameters as { required?: readonly string[] } | undefined)?.required ?? []
  check('start requires description and text', required.includes('description') && required.includes('text'), JSON.stringify(required))
  const status = tools.find(tool => tool.name === 'remote_run_status')
  const statusRequired = (status?.parameters as { required?: readonly string[] } | undefined)?.required ?? []
  check('status requires nothing', statusRequired.length === 0, JSON.stringify(statusRequired))
  check('the description explains the subagent_remote split',
    String(start?.description).includes('subagent_remote'), String(start?.description).slice(0, 80))
  check('send_message explains it does not block',
    String(tools.find(tool => tool.name === 'remote_send_message')?.description).includes('不阻塞'),
    String(tools.find(tool => tool.name === 'remote_send_message')?.description).slice(0, 80))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
