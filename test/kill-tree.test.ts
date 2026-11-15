/**
 * Regression test for the stop path: killing a command must also kill the
 * programs it started, **including ones it detached**.
 *
 * Honest history, because it changes what this test proves. A live check first
 * reported this failing on a real peer, and `killTree` was rewritten to snapshot
 * the descendants before killing anything. The report turned out to be a bug in
 * the CHECK (`fs.stat` answers a missing path with `ok: true, exists: false`, and
 * the check read `ok`), and a later measurement on that same machine showed plain
 * `taskkill /T /F` also takes the detached grandchild down in this shape. So this
 * test does not show that the old code was broken — it pins the INVARIANT that a
 * stop kills everything the command started, so a regression in the (now
 * snapshot-first) implementation is caught rather than argued about.
 *
 * Windows-only (the sweep is a Windows process-tree problem); elsewhere the test
 * reports a skip rather than pretending to pass.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/kill-tree.test.ts
 */

import { spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const server = await import('../src/server.ts')

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

const sleep = (ms: number): Promise<void> => new Promise(resolve => { setTimeout(resolve, ms) })

if (process.platform !== 'win32') {
  console.log('skip: the process-tree sweep is Windows-specific')
} else {
  const dir = mkdtempSync(join(tmpdir(), 'dshr-kill-'))
  const marker = join(dir, 'grandchild-marker.txt')

  console.log('\n== the grandchild a plain tree kill would leave behind ==')
  // The outer command starts a detached helper (which will write the marker in
  // 8 s) and then sleeps far longer than this test — exactly the shape of a
  // build/daemon a user would expect a stop to take down with it.
  const inner = `Start-Sleep -Seconds 8; Set-Content -Path '${marker}' -Value alive`
  const outer = [
    `Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',`,
    `'"${inner}"'`,
    `; Start-Sleep -Seconds 120`,
  ].join(' ')
  const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', outer], {
    windowsHide: true,
    stdio: 'ignore',
  })

  await sleep(2500)
  check('the command is running before the stop', child.pid !== undefined && !child.killed, String(child.pid))

  server.killTree(child)
  // killTree first takes a CIM snapshot (up to its 20 s budget), then sweeps.
  // A fixed 1.5 s check raced that asynchronous contract on a busy desktop.
  const deadline = Date.now() + 25_000
  while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) await sleep(50)
  check('the command itself is gone after the sweep', child.exitCode !== null || child.signalCode !== null,
    `exitCode=${String(child.exitCode)} signal=${String(child.signalCode)}`)

  // The helper would fire at +8 s; give it well past that.
  console.log('   waiting 12 s to see whether the detached helper survived…')
  await sleep(12_000)
  check('the detached grandchild did NOT survive', !existsSync(marker),
    existsSync(marker) ? `the marker exists: ${marker}` : undefined)

  // A second stop must be harmless (the registry may race with a natural exit).
  let threw = false
  try {
    server.killTree(child)
  } catch {
    threw = true
  }
  check('stopping an already-dead command is not an error', !threw)

  rmSync(dir, { recursive: true, force: true })
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
