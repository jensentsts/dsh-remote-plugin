/**
 * The client half of "a local Stop must reach the process on the peer".
 *
 * This is the code path a GUI Stop takes: the tool settles its own call first and
 * then asks the peer to kill the process by `execId`. It cannot be exercised from
 * the DSH side of the suite (it needs a real tool call being aborted), so the
 * wiring is extracted and tested here — the ORDER and the "reply wins" rule are
 * the parts that would silently regress.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/exec-client.test.ts
 */

import { runCancellableExec } from '../src/exec-client.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

interface Recorded {
  sent: Array<{ args: Record<string, unknown>, timeout: number }>
  cancels: string[]
}

/** A transport whose reply the test controls. */
function harness(): { calls: Recorded, resolve: (value: Record<string, unknown>) => void, reject: (error: unknown) => void } {
  const calls: Recorded = { sent: [], cancels: [] }
  return {
    calls,
    resolve: () => {},
    reject: () => {},
  }
}

console.log('\n== 1. a command with no signal just runs ==')
{
  const calls: Recorded = { sent: [], cancels: [] }
  const value = await runCancellableExec({
    execId: 'exec-1',
    args: { cmd: 'Write-Output hi', shell: 'powershell' },
    timeoutMs: 5000,
    send: async (args, timeout) => { calls.sent.push({ args, timeout }); return { ok: true, exit: 0 } },
    cancelRemote: (execId) => { calls.cancels.push(execId) },
  })
  check('the reply is returned', value.exit === 0, JSON.stringify(value))
  check('the exec id travels with the command', calls.sent[0]?.args.execId === 'exec-1', JSON.stringify(calls.sent[0]?.args))
  check('the timeout is passed through', calls.sent[0]?.timeout === 5000, String(calls.sent[0]?.timeout))
  check('nothing was cancelled', calls.cancels.length === 0, calls.cancels.join(','))
}

console.log('\n== 2. a local Stop cancels the peer’s process ==')
{
  const calls: Recorded = { sent: [], cancels: [] }
  const controller = new AbortController()
  const pending = runCancellableExec({
    execId: 'exec-2',
    args: { cmd: 'Start-Sleep -Seconds 300' },
    timeoutMs: 5000,
    signal: controller.signal,
    send: (_args, _timeout) => new Promise(() => { /* never settles: the command is still running */ }),
    cancelRemote: (execId) => { calls.cancels.push(execId) },
  })
  controller.abort()
  let threw: unknown
  try {
    await pending
  } catch (error) { threw = error }
  check('the waiting call settles as an abort', (threw as { name?: string } | undefined)?.name === 'AbortError', String(threw))
  check('and the peer is told to stop THAT process', calls.cancels[0] === 'exec-2', JSON.stringify(calls.cancels))
}

console.log('\n== 3. a reply that arrives first is never cancelled afterwards ==')
{
  const calls: Recorded = { sent: [], cancels: [] }
  const controller = new AbortController()
  let release: (value: Record<string, unknown>) => void = () => {}
  const pending = runCancellableExec({
    execId: 'exec-3',
    args: { cmd: 'Write-Output done' },
    timeoutMs: 5000,
    signal: controller.signal,
    send: () => new Promise((resolve) => { release = resolve }),
    cancelRemote: (execId) => { calls.cancels.push(execId) },
  })
  release({ ok: true, exit: 0 })
  const value = await pending
  // A Stop racing a command that already finished must not kill the NEXT thing the
  // peer runs, which is exactly what a late cancel with a reused id would do.
  controller.abort()
  await new Promise(resolve => { setTimeout(resolve, 20) })
  check('the reply is returned', value.exit === 0, JSON.stringify(value))
  check('a late abort sends no cancel', calls.cancels.length === 0, calls.cancels.join(','))
}

console.log('\n== 4. a transport failure is not an abort, and cancels nothing ==')
{
  const calls: Recorded = { sent: [], cancels: [] }
  const controller = new AbortController()
  let threw: unknown
  try {
    await runCancellableExec({
      execId: 'exec-4',
      args: { cmd: 'Write-Output hi' },
      timeoutMs: 5000,
      signal: controller.signal,
      send: async () => { throw new Error('peer closed during handshake') },
      cancelRemote: (execId) => { calls.cancels.push(execId) },
    })
  } catch (error) { threw = error }
  check('the transport error propagates unchanged',
    (threw as Error | undefined)?.message === 'peer closed during handshake', String(threw))
  check('and it is not treated as a local stop', calls.cancels.length === 0, calls.cancels.join(','))
}

console.log('\n== 5. an already-aborted signal cancels instead of sending ==')
{
  const calls: Recorded = { sent: [], cancels: [] }
  const controller = new AbortController()
  controller.abort()
  let threw: unknown
  try {
    await runCancellableExec({
      execId: 'exec-5',
      args: { cmd: 'Write-Output hi' },
      timeoutMs: 5000,
      signal: controller.signal,
      send: (_args, _timeout) => { calls.sent.push({ args: {}, timeout: 0 }); return new Promise(() => {}) },
      cancelRemote: (execId) => { calls.cancels.push(execId) },
    })
  } catch (error) { threw = error }
  check('it aborts immediately', (threw as { name?: string } | undefined)?.name === 'AbortError', String(threw))
  check('and still asks the peer to stop what it sent', calls.cancels[0] === 'exec-5', JSON.stringify(calls.cancels))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
