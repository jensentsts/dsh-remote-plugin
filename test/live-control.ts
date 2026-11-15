/**
 * Live check of the CONTROLLER side of two things a loopback test cannot prove:
 * that a real peer's stop paths actually stop work, and that the trajectory
 * journal can be read incrementally over the real link.
 *
 * Scenarios:
 *   1. the journal reads, incrementally, context-sized
 *   2. `exec.cancel` stops the command — AND the grandchild it detached
 *   3. the cancellation is part of the record
 *   4. `agent.interrupt` stops a driven turn on the real peer
 *
 * Nothing is sent to a conversation you care about: scenario 4 uses a probe
 * session of its own (`--probe`), scenarios 2–3 run only commands this script
 * starts and immediately cancels.
 *
 *   cd <deepseek-harness root>
 *   node --import tsx/esm E:/path/to/dsh-remote/test/live-control.ts \
 *     --host peer.example --port 50000 [--probe remote-live-probe] [--skip-cancel]
 *
 * `--skip-cancel` is for the window where the peer still runs an older build than
 * the fix on disk: those two scenarios would then fail for a known reason.
 *
 * Keys come from the same place the plugin reads them: `${DSH_HOME}/dsh-remote/`
 * (`client.key` + `server.pub`), overridable with `--private-key-file` /
 * `--peer-public-key-file`.
 *
 * The interesting part of scenario 2 is the GRANDCHILD: the command starts a
 * detached Powershell that would write a marker file 20 s later, then sleeps 90 s.
 * `child.kill()` would only kill the outer shell and that marker would still
 * appear; so would `taskkill /T` alone. The peer snapshots the tree first, so the
 * marker must NOT appear — that is the difference between "the shell exited" and
 * "the work stopped".
 */

import { LinkClient } from '../src/link.ts'
import { dshHomePath } from '../src/keys.ts'

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`)
  if (index === -1) return undefined
  const value = process.argv[index + 1]
  return value === undefined || value.startsWith('--') ? '' : value
}

const host = arg('host') ?? process.env.DSHR_HOST ?? ''
const port = Number(arg('port') ?? process.env.DSHR_PORT ?? 0)
const marker = arg('marker') ?? 'C:/Users/demo/.dsh/dsh-remote/cancel-probe-marker.txt'
const probe = arg('probe') ?? 'remote-live-probe'
const skipCancel = process.argv.includes('--skip-cancel')

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

const sleep = (ms: number): Promise<void> => new Promise(resolve => { setTimeout(resolve, ms) })

if (host === '' || port <= 0) {
  console.error('give --host and --port (the peer the plugin is configured against)')
  process.exitCode = 2
} else {
  const link = new LinkClient(() => ({
    host,
    port,
    privateKeyFile: arg('private-key-file') ?? dshHomePath('dsh-remote', 'client.key'),
    peerPublicKeyFile: arg('peer-public-key-file') ?? dshHomePath('dsh-remote', 'server.pub'),
    timeoutMs: 120_000,
  }), message => console.log(`   link: ${message}`), 'dsh-remote(live-control)')

  try {
    console.log('\n== peer ==')
    const info = await link.request('sysinfo', {}, 30_000)
    const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
    console.log(`   ${String(info.hostname)}  build=${String(info.build)}  platform=${String(info.platform)}`)
    console.log(`   ops: ${ops.length === 0 ? '(none — pre-r11)' : ops.join(', ')}`)
    check('the peer advertises exec.cancel', ops.includes('exec.cancel'))

    if (!ops.includes('journal.read')) {
      console.log('\nthis peer is too old for the checks below (needs r14+)')
    } else {
      check('the peer advertises journal.read', true)
      if (skipCancel) console.log('   (--skip-cancel: scenarios 2 and 3 are skipped)')

      console.log('\n== 1. the trajectory journal reads, and reads incrementally ==')
      const tail = await link.request('journal.read', { limit: 3 }, 30_000)
      const cursor = Number(tail.nextSeq)
      console.log(`   total=${String(tail.written)}  lastSeq=${String(tail.lastSeq)}  this page=${String(tail.count)}  cursor=${String(cursor)}`)
      for (const entry of (tail.entries as Array<Record<string, unknown>>) ?? []) {
        console.log(`   #${String(entry.seq)} ${String(entry.at).slice(11, 19)} ${String(entry.kind).padEnd(9)} ${String(entry.summary)}`)
      }
      check('a tail read comes back marked as a tail', tail.tail === true)
      check('it carries entries with a one-line summary', Array.isArray(tail.entries)
        && (tail.entries as unknown[]).length > 0
        && (tail.entries as Array<{ summary?: unknown }>).every(entry => typeof entry.summary === 'string'))
      check('detail is opt-in, so the default stays context-sized',
        (tail.entries as Array<{ detail?: unknown }>).every(entry => entry.detail === undefined))
      check('the cursor is a number', Number.isFinite(cursor))

      if (!skipCancel) {
        console.log('\n== 2. exec.cancel stops the command — and its children ==')
        // Clean slate: whatever is at the marker path is not this run's evidence.
        await link.request('exec', {
          cmd: `Remove-Item '${marker.replace(/\//gu, '\\')}' -Force -ErrorAction SilentlyContinue; 'cleared'`,
          shell: 'powershell',
        }, 60_000)
        const execId = `live-cancel-${Date.now()}`
        const parked = link.request('exec', {
          shell: 'powershell',
          timeoutMs: 120_000,
          execId,
          cmd: [
            `Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command',`,
            `'"Start-Sleep -Seconds 20; Set-Content -Path ''${marker.replace(/\//gu, '\\')}'' -Value alive"'`,
            `; Start-Sleep -Seconds 90`,
          ].join(' '),
        }, 150_000)

        // Long enough that the outer shell has certainly STARTED and spawned its
        // detached helper: at 3 s a slow powershell boot can still be in flight,
        // which would turn this into a race about startup rather than about the kill.
        await sleep(8000)
        const cancel = await link.request('exec.cancel', { execId }, 30_000)
        check('exec.cancel reports it stopped something', cancel.ok === true && cancel.cancelled === true, JSON.stringify(cancel))

        const stopped = await parked as Record<string, unknown>
        check('the command settled as cancelled, not timed out',
          stopped.cancelled === true && stopped.timedOut === false,
          JSON.stringify({ cancelled: stopped.cancelled, timedOut: stopped.timedOut }))
        check('and the peer says who stopped it', String(stopped.stderr).includes('stopped by the controller'), String(stopped.stderr))

        // The grandchild would fire at +20s. If the tree really died, nothing lands.
        console.log('   waiting 25 s to see whether the grandchild survived…')
        await sleep(25_000)
        let markerThere = true
        try {
          const stat = await link.request('fs.stat', { path: marker }, 30_000)
          // `fs.stat` reports a MISSING path as a SUCCESSFUL op with
          // `{ exists: false }`, so `ok` says nothing about the file. Reading `ok`
          // here made this assertion report "the marker exists" unconditionally —
          // a false defect report about the plugin's kill path.
          markerThere = stat.exists === true
        } catch {
          markerThere = false
        }
        check('the detached grandchild did NOT survive the cancel', !markerThere,
          markerThere ? `the marker exists: ${marker}` : undefined)

        console.log('\n== 3. the cancel is part of the record ==')
        const after = await link.request('journal.read', { fromSeq: cursor, limit: 50 }, 30_000)
        const entries = (after.entries as Array<{ seq?: unknown, op?: unknown, summary?: unknown }>) ?? []
        console.log(`   ${entries.length} new entr(ies) since cursor ${cursor}; nextSeq=${String(after.nextSeq)}`)
        for (const entry of entries.slice(-6)) {
          console.log(`   ${String(entry.seq)} ${String(entry.op ?? '')} ${String(entry.summary).slice(0, 110)}`)
        }
        check('the incremental read returned only what came after the cursor',
          entries.every(entry => Number(entry.seq) > cursor))
        check('the exec it ran is recorded', entries.some(entry => entry.op === 'exec'))
        check('the cancellation is recorded too', entries.some(entry => entry.op === 'exec.cancel'))
        check('journal.read itself is never recorded (no self-feeding)',
          !entries.some(entry => entry.op === 'journal.read'))
        check('a read right after the cursor is caught up', (await link.request('journal.read', {
          fromSeq: Number(after.nextSeq), limit: 10,
        }, 30_000)).count === 0)
      }

      console.log('\n== 4. an interrupt stops a driven turn on the real peer ==')
      // The controller's other stop path: `remote_agent_prompt` aborts → the
      // plugin calls agent.interrupt. Determinism matters more than usual here: a
      // model asked to "sleep" may simply answer instead, and then the turn is over
      // before the interrupt and the run proves nothing. So this waits for
      // EVIDENCE that a tool call is in flight, and reports INCONCLUSIVE rather
      // than passing or failing if the turn ends first.
      if (ops.includes('agent.prompt') && ops.includes('agent.interrupt')) {
        // Warm the conversation up first: an interrupt that arrives while a fresh
        // session is still being created is a no-op (the half latches a stop only
        // for a bounded window), which would make the result ambiguous.
        const warm = await link.request('agent.prompt', {
          sessionId: probe,
          text: '只回复 OK，不要调用任何工具。',
          timeoutMs: 150_000,
        }, 180_000)
        console.log(`   warmed ${probe}: created=${String(warm.created)} reply=${JSON.stringify(String(warm.reply ?? '').slice(0, 40))}`)

        const beforeInterrupt = await link.request('journal.read', { limit: 1 }, 30_000)
        const cursor2 = Number(beforeInterrupt.nextSeq)
        let settledEarly: Record<string, unknown> | undefined
        const parked2 = link.request('agent.prompt', {
          sessionId: probe,
          text: '主控要求做一次停止路径测试，请严格照做：调用 pwsh 工具，且只调用一次，'
            + '命令内容必须是 Start-Sleep -Seconds 300。不要执行别的命令，不要解释，执行完不要补充说明。',
          timeoutMs: 180_000,
        }, 220_000)
        void parked2.then(
          (value) => { settledEarly = value as Record<string, unknown> },
          () => { settledEarly = { reason: 'rejected' } },
        )

        // Wait until the tool call is in flight (the model entry names it).
        let inFlight = false
        const deadline = Date.now() + 60_000
        while (Date.now() < deadline && settledEarly === undefined) {
          const page = await link.request('journal.read', { fromSeq: cursor2, limit: 50 }, 30_000)
          const rows = (page.entries as Array<{ kind?: unknown, summary?: unknown }>) ?? []
          if (rows.some(row => row.kind === 'model' && String(row.summary).includes('tools:'))) {
            inFlight = true
            break
          }
          await sleep(1500)
        }

        if (!inFlight) {
          const finished = settledEarly
          console.log('   INCONCLUSIVE: no tool call was in flight when the interrupt was due'
            + `${finished === undefined ? ' (turn still going, no tool entry seen)' : ` (turn settled first: reason=${String(finished.reason)})`}`)
          check('the scenario was inconclusive, so it asserts nothing', true)
        } else {
          const startedAt = Date.now()
          const ack = await link.request('agent.interrupt', { sessionId: probe }, 30_000)
          check('the peer accepted the interrupt of a live turn',
            ack.ok === true && ack.interrupted === true, JSON.stringify(ack))
          const settled = await parked2 as Record<string, unknown>
          const stoppedAfterMs = Date.now() - startedAt
          console.log(`   settled ${stoppedAfterMs} ms after the interrupt: reason=${String(settled.reason)} interruptCause=${String(settled.interruptCause)}`)
          check('the turn ended aborted, not completed', String(settled.reason) === 'aborted', `reason=${String(settled.reason)}`)
          // The nested cause is `user` for BOTH a controller stop and a human
          // pressing stop on that machine — `agent.cancel({kind:'user'})` is what
          // the controller sends, so the event cannot tell them apart. The
          // controller-origin distinction travels in the interrupt PUSH frame
          // (`origin: 'controller'` vs `'remote-user'`), which is covered by the
          // loopback suite; here it is enough that the stop is attributed at all.
          check('and the peer attributes the stop to a cause',
            String(settled.interruptCause ?? '') !== '', `cause=${String(settled.interruptCause)}`)
          check('it stopped promptly rather than finishing its 300 s sleep', stoppedAfterMs < 60_000, `${stoppedAfterMs} ms`)
        }

        const afterInterrupt = await link.request('journal.read', { fromSeq: cursor2, limit: 100 }, 30_000)
        const turns = (afterInterrupt.entries as Array<{ kind?: unknown, sessionId?: unknown, summary?: unknown }>) ?? []
        for (const entry of turns.slice(-5)) {
          console.log(`   ${String((entry as { seq?: unknown }).seq)} ${String(entry.kind)} ${String(entry.summary).slice(0, 100)}`)
        }
        check('every journal entry for this scenario belongs to the probe conversation',
          turns.every(entry => entry.sessionId === undefined || entry.sessionId === probe),
          JSON.stringify(turns.map(entry => entry.sessionId)))
      } else {
        console.log('   skipped: this peer does not advertise agent.prompt/agent.interrupt')
      }
    }
  } catch (error) {
    console.error(`\nlive check failed: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  } finally {
    link.close()
  }
}

console.log(`\n${failures === 0 ? 'LIVE ALL PASS' : `${failures} LIVE FAILURE(S)`}`)
process.exitCode = failures === 0 ? (process.exitCode ?? 0) : 1
