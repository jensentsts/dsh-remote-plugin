/**
 * Self-test for the `subagent_remote` tool — no peer, no cordis.
 *
 * What matters here is the seam contract around a run: the tool must hand the
 * caller's cancellation through, must always dispose (the seam requires it on
 * every path), and must not dress an aborted run up as a deliverable. The fake
 * registry records exactly those calls, so the assertions are about behaviour
 * rather than about the rendering.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/subagent-tool.test.ts
 */

import { REMOTE_SUBAGENT_TOOL, createRemoteSubagentTool, resultText } from '../src/subagent-tool.ts'
import type { RemoteRunHandle, RemoteSubagentFacade } from '../src/subagent-tool.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

interface Calls {
  starts: Array<{ name: string, request: Record<string, unknown> }>
  disposed: number
}

function harness(result: () => Promise<Record<string, unknown>>): { calls: Calls, facade: RemoteSubagentFacade } {
  const calls: Calls = { starts: [], disposed: 0 }
  const facade: RemoteSubagentFacade = {
    async start(name, request) {
      calls.starts.push({ name, request: request as unknown as Record<string, unknown> })
      const handle: RemoteRunHandle = {
        id: 'remote-abc123',
        result: result() as Promise<never>,
        async dispose() { calls.disposed += 1 },
      }
      return handle
    },
  }
  return { calls, facade }
}

const fakeAgent = { session: { id: 'session-parent' } } as never
const signal = new AbortController().signal
const args = { description: 'audit the tree', prompt: 'list every file and report sizes' }
const exec = { agent: fakeAgent, signal }

console.log('\n== 1. resultText ==')
check('joins text blocks', resultText([
  { type: 'text', text: 'a' }, { type: 'text', text: 'b' },
] as never) === 'a\nb')
check('ignores non-text blocks', resultText([
  { type: 'text', text: 'keep' }, { type: 'image', source: {} },
] as never) === 'keep')
check('empty stays empty', resultText([] as never) === '')

console.log('\n== 2. the tool\'s identity ==')
{
  const { facade } = harness(async () => ({ output: [], stopReason: 'completed' }))
  const tool = createRemoteSubagentTool(facade)
  check('named subagent_remote so the chat groups it as delegation', tool.name === REMOTE_SUBAGENT_TOOL && tool.name.startsWith('subagent_'))
  check('description restates the one-chat-one-conversation rule', tool.description.includes('同一个本机 chat 永远复用同一段远端对话'))
  const required = (tool.parameters as { required?: readonly string[] } | undefined)?.required ?? []
  check('both parameters are required', required.includes('description') && required.includes('prompt'), JSON.stringify(required))
}

console.log('\n== 3. one call, one run, always disposed ==')
{
  const { calls, facade } = harness(async () => ({
    output: [{ type: 'text', text: '  finished the audit  ' }],
    stopReason: 'completed',
  }))
  const tool = createRemoteSubagentTool(facade)
  const value = await tool.execute(args, exec as never) as unknown as {
    sessionId: string, stopReason: string, reply: string, interrupted: boolean, diagnostic: string | null,
  }
  check('starts the configured provider', calls.starts[0]?.name === 'remote', String(calls.starts[0]?.name))
  check('passes the label through', calls.starts[0]?.request?.label === 'audit the tree')
  check('passes the prompt as a text block',
    JSON.stringify(calls.starts[0]?.request?.prompt) === JSON.stringify([{ type: 'text', text: args.prompt }]),
    JSON.stringify(calls.starts[0]?.request?.prompt))
  check('passes the caller\'s signal through', calls.starts[0]?.request?.signal === signal)
  check('passes the calling agent as parent', calls.starts[0]?.request?.parent === fakeAgent)
  check('reports the run id as the remote session', value.sessionId === 'remote-abc123', value.sessionId)
  check('stopReason completed', value.stopReason === 'completed', value.stopReason)
  check('reply is trimmed', value.reply === 'finished the audit', value.reply)
  check('not marked interrupted', value.interrupted === false)
  check('disposed once', calls.disposed === 1, String(calls.disposed))
}

console.log('\n== 4. a failed run is reported, not thrown ==')
{
  const { calls, facade } = harness(async () => ({
    output: [{ type: 'text', text: 'partial' }],
    stopReason: 'error',
    diagnostic: 'remote: the peer\'s turn ended with reason "error"',
  }))
  const value = await createRemoteSubagentTool(facade).execute(args, exec as never) as unknown as {
    stopReason: string, diagnostic: string, reply: string,
  }
  check('stopReason error', value.stopReason === 'error', value.stopReason)
  check('diagnostic surfaced', String(value.diagnostic).includes('reason "error"'), String(value.diagnostic))
  check('partial output kept', value.reply === 'partial', value.reply)
  check('disposed anyway', calls.disposed === 1, String(calls.disposed))
}

console.log('\n== 5. an interrupted run must not look like a deliverable ==')
{
  const { facade } = harness(async () => ({ output: [], stopReason: 'aborted' }))
  const tool = createRemoteSubagentTool(facade)
  const value = await tool.execute(args, exec as never) as unknown as { interrupted: boolean, reply: string }
  check('marked interrupted', value.interrupted === true)
  check('no deliverable', value.reply === '', JSON.stringify(value.reply))
  const rendered = tool.output.render(args, value as never) as Array<{ text?: string }>
  check('the rendered text tells the model to stop and wait',
    String(rendered[0]?.text).includes('立刻停止'), String(rendered[0]?.text).slice(0, 120))
}

console.log('\n== 6. a rejecting run still disposes, and the failure surfaces ==')
{
  const { calls, facade } = harness(async () => { throw new Error('infrastructure fault') })
  let threw: unknown
  try {
    await createRemoteSubagentTool(facade).execute(args, exec as never)
  } catch (error) { threw = error }
  check('the infrastructure failure propagates', threw instanceof Error && threw.message.includes('infrastructure'), String(threw))
  check('the run was still disposed', calls.disposed === 1, String(calls.disposed))
}

console.log('\n== 7. no calling agent is an error, not a silent no-op ==')
{
  const { calls, facade } = harness(async () => ({ output: [], stopReason: 'completed' }))
  let threw: unknown
  try {
    await createRemoteSubagentTool(facade).execute(args, { signal } as never)
  } catch (error) { threw = error }
  check('refuses without a parent', threw instanceof Error && threw.message.includes('no calling agent'), String(threw))
  check('and never started a run', calls.starts.length === 0)
}

console.log('\n== 8. rendering a completed deliverable ==')
{
  const { facade } = harness(async () => ({ output: [], stopReason: 'completed' }))
  const tool = createRemoteSubagentTool(facade)
  const rendered = tool.output.render(args, {
    sessionId: 'remote-abc123', stopReason: 'completed', interrupted: false,
    diagnostic: null, reply: 'the tree has 12 files',
  } as never) as Array<{ text?: string }>
  const text = String(rendered[0]?.text)
  check('shows the session and the stop reason', text.includes('remote-abc123') && text.includes('completed'), text.slice(0, 80))
  check('shows the deliverable', text.includes('the tree has 12 files'), text)
  check('does not claim an interrupt', !text.includes('立刻停止'))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
