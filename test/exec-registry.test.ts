/**
 * Self-test for the running-command registry.
 *
 * Small on purpose, but load-bearing: this is what makes "the local user pressed
 * stop" reach a command that is still running on the peer. The cases that matter
 * are the boring ones — a disposer arriving late, an id reused before its
 * predecessor finished, a shell that refuses to die — because those are what a
 * stop racing a natural exit actually looks like.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/exec-registry.test.ts
 */

import { ExecRegistry } from '../src/exec-registry.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

/** A child that records how it was stopped. */
function child(): { cancel: () => void, calls: number } {
  const handle = { calls: 0, cancel: () => { handle.calls += 1 } }
  return handle
}

console.log('\n== 1. track, cancel, release ==')
{
  const registry = new ExecRegistry()
  const first = child()
  const release = registry.add('exec-1', first)
  check('registered', registry.has('exec-1') && registry.size === 1)
  check('cancel reports it stopped something', registry.cancel('exec-1') === true)
  check('the child was asked once', first.calls === 1, String(first.calls))
  check('a second cancel is a miss', registry.cancel('exec-1') === false)
  check('the entry is gone', !registry.has('exec-1') && registry.size === 0)

  const second = child()
  const release2 = registry.add('exec-2', second)
  release2()
  check('release drops the entry', !registry.has('exec-2'))
  check('a released entry cannot be cancelled', registry.cancel('exec-2') === false)
  check('the child was never asked', second.calls === 0, String(second.calls))
  release2()
  check('release is idempotent', registry.size === 0)
  release()
  check('a stale release after cancel is harmless', registry.size === 0)
}

console.log('\n== 2. an id reused before its predecessor finished ==')
{
  const registry = new ExecRegistry()
  const oldChild = child()
  const newChild = child()
  const releaseOld = registry.add('exec-x', oldChild)
  const releaseNew = registry.add('exec-x', newChild)
  check('the newest handle wins', registry.has('exec-x'))
  check('cancel reaches the newest', registry.cancel('exec-x') === true && newChild.calls === 1)
  check('the old child is untouched', oldChild.calls === 0, String(oldChild.calls))
  releaseOld()
  check('the late release of the old entry does not resurrect or clear anything', !registry.has('exec-x'))
  releaseNew()
  check('size settles at zero', registry.size === 0)
}

console.log('\n== 3. a child that refuses to die ==')
{
  const registry = new ExecRegistry()
  registry.add('exec-3', { cancel: () => { throw new Error('access denied') } })
  let threw = false
  try { registry.cancel('exec-3') } catch { threw = true }
  check('cancel does not propagate the refusal', !threw)
  check('and the entry is still dropped (nothing left to retry)', !registry.has('exec-3'))
}

console.log('\n== 4. cancelAll ==')
{
  const registry = new ExecRegistry()
  const a = child()
  const b = child()
  registry.add('a', a)
  registry.add('b', b)
  check('cancels everything and reports the count', registry.cancelAll() === 2 && a.calls === 1 && b.calls === 1)
  check('and empties the registry', registry.size === 0)
  check('a second sweep is a no-op', registry.cancelAll() === 0)
}

console.log('\n== 5. an unusable id is never tracked ==')
{
  const registry = new ExecRegistry()
  const handle = child()
  const release = registry.add('', handle)
  check('empty id is ignored', registry.size === 0 && !registry.has(''))
  check('cancel on it is a miss', registry.cancel('') === false)
  check('release is a no-op', (release(), handle.calls === 0))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
