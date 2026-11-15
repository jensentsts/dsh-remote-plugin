/**
 * Self-test for the remote-subagent provider — no peer, no socket, no cordis.
 *
 * The kit is the SHIPPED one (`@deepseek-ai/dsh-subagent`), so the settlement and
 * cancellation semantics under test are the real ones; only the peer is faked.
 * That matters: the interesting failures here are "the result rejected after
 * publication" and "a finished run still interrupted the peer", neither of which
 * a hand-rolled stub would catch.
 *
 * Run from the harness checkout so `tsx` resolves, with the plugin's own
 * node_modules junction for `@deepseek-ai/dsh-subagent` in place:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/remote-provider.test.ts
 */

import { NO_START_CAPABILITIES, settleRunResult, subprocessRunHandle } from '@deepseek-ai/dsh-subagent'

import { raceAbort } from '../src/async.ts'
import { createRemoteProvider, promptText } from '../src/remote-provider.ts'
import type { RemotePromptOutcome, RemoteSubagentKit } from '../src/remote-provider.ts'

const kit = { NO_START_CAPABILITIES, settleRunResult, subprocessRunHandle } as unknown as RemoteSubagentKit

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

const blockText = (output: readonly unknown[]): string =>
  output.map(entry => String((entry as { text?: unknown }).text ?? '')).join('')

interface Harness {
  prompts: string[]
  interrupts: string[]
  provider: ReturnType<typeof createRemoteProvider>
}

function harness(outcome: (call: number) => Promise<RemotePromptOutcome> | RemotePromptOutcome): Harness {
  const prompts: string[] = []
  const interrupts: string[] = []
  let call = 0
  const provider = createRemoteProvider({
    kit,
    name: 'remote',
    sessionFor: parent => `remote-${parent.slice(-4)}`,
    prompt: async ({ sessionId, text }) => {
      prompts.push(`${sessionId}|${text}`)
      call += 1
      return await outcome(call)
    },
    interrupt: async (sessionId) => { interrupts.push(sessionId) },
    log: () => {},
  })
  return { prompts, interrupts, provider }
}

const start = async (
  provider: ReturnType<typeof createRemoteProvider>,
  signal: AbortSignal,
  text = 'do the thing',
): Promise<Awaited<ReturnType<typeof provider.start>>> => await provider.start({
  parent: { session: { id: 'session-abcd' } },
  prompt: [{ type: 'text', text }],
  signal,
})

console.log('\n== 1. promptText: a delegation prompt is its text blocks ==')
check('joins text blocks', promptText([
  { type: 'text', text: 'line one' },
  { type: 'text', text: 'line two' },
] as never) === 'line one\nline two')
check('ignores non-text blocks', promptText([
  { type: 'text', text: 'keep' },
  { type: 'image', source: {} },
] as never) === 'keep')
check('empty stays empty', promptText([] as never) === '')

console.log('\n== 2. raceAbort: a local Stop settles without waiting for the peer ==')
{
  const idle = new AbortController()
  check('passes a normal result through', await raceAbort(Promise.resolve('v'), idle.signal) === 'v')

  const mid = new AbortController()
  const pending = raceAbort(new Promise<never>(() => {}), mid.signal)
  mid.abort()
  const error = await pending.then(() => undefined, (failure: unknown) => failure as Error)
  check('aborts while in flight', error?.name === 'AbortError', String(error?.name))

  const pre = new AbortController()
  pre.abort()
  const immediate = await raceAbort(Promise.resolve('late'), pre.signal)
    .then(() => undefined, (failure: unknown) => failure as Error)
  check('an already-aborted signal aborts at once', immediate?.name === 'AbortError', String(immediate?.name))
}

console.log('\n== 3. a completed run ==')
{
  const { prompts, interrupts, provider } = harness(() => ({ reply: 'done', reason: 'completed' }))
  const run = await start(provider, new AbortController().signal)
  check('run id is this chat\'s remote conversation', run.id === 'remote-abcd', String(run.id))
  check('no local child (remote run)', run.localAgent === undefined)
  const result = await run.result
  check('stopReason completed', result.stopReason === 'completed', result.stopReason)
  check('output carries the peer reply', blockText(result.output) === 'done', blockText(result.output))
  check('prompt went to the peer with the session and text', prompts[0] === 'remote-abcd|do the thing', prompts[0])
  await run.dispose()
  check('disposing a finished run does NOT interrupt the peer', interrupts.length === 0, JSON.stringify(interrupts))
}

console.log('\n== 4. the peer reported an interrupt ==')
{
  const { interrupts, provider } = harness(() => ({ reply: '', interrupted: true, reason: 'aborted' }))
  const run = await start(provider, new AbortController().signal)
  const result = await run.result
  check('stopReason aborted', result.stopReason === 'aborted', result.stopReason)
  check('no output', result.output.length === 0)
  await run.dispose()
  check('nothing to stop on the peer', interrupts.length === 0, JSON.stringify(interrupts))
}

console.log('\n== 5. a peer turn that ended in error ==')
{
  const { interrupts, provider } = harness(() => ({ reply: 'partial', reason: 'error' }))
  const run = await start(provider, new AbortController().signal)
  const result = await run.result
  check('stopReason error', result.stopReason === 'error', result.stopReason)
  check('diagnostic mentions the peer reason', (result.diagnostic ?? '').includes('error'), String(result.diagnostic))
  check('partial output preserved', blockText(result.output) === 'partial', blockText(result.output))
  await run.dispose()
  check('a failed run does stop the peer', interrupts.length === 1, JSON.stringify(interrupts))
}

console.log('\n== 6. a transport failure never rejects the run result ==')
{
  const { interrupts, provider } = harness(() => { throw new Error('link is gone') })
  const run = await start(provider, new AbortController().signal)
  const result = await run.result
  check('result resolved (contract: never rejects after publication)', result.stopReason === 'error', result.stopReason)
  check('diagnostic is set', (result.diagnostic ?? '').includes('link is gone'), String(result.diagnostic))
  await run.dispose()
  check('peer stopped once', interrupts.length === 1, JSON.stringify(interrupts))
}

console.log('\n== 7. local Stop: the run aborts and the peer is interrupted exactly once ==')
{
  const controller = new AbortController()
  const { interrupts, provider } = harness(() => new Promise<never>(() => {}))
  const run = await start(provider, controller.signal)
  controller.abort()
  const result = await run.result
  check('stopReason aborted', result.stopReason === 'aborted', result.stopReason)
  await run.dispose()
  await run.dispose()
  check('interrupt called once, not twice', interrupts.length === 1, JSON.stringify(interrupts))
  check('the peer session was the right one', interrupts[0] === 'remote-abcd', String(interrupts[0]))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
