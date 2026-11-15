/**
 * Loopback integration test for the SERVER half, over the real wire protocol.
 *
 * Everything else about this half is unit-tested in pieces; this brings up the
 * actual `apply()` (its listener, op table, handshake pinning, permission fence)
 * and drives it with the actual client handshake, on 127.0.0.1, in a temp
 * `DSH_HOME`. No peer machine and no DSH are involved 闂?which is the point: the
 * code the controlled machine will run is exercised before it runs there.
 *
 * Only the cordis context is faked (the half talks to it through `logger`,
 * `effect`, `on`, `get`), and every service it would inject is absent on purpose,
 * so the ops that need one are seen failing cleanly instead of silently.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/server-loopback.test.ts
 */

import { connect, createServer } from 'node:net'
import type { AddressInfo, Socket } from 'node:net'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { createHash, createPublicKey } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'
import { traceFixture } from './trace-fixture.ts'

const home = mkdtempSync(join(tmpdir(), 'dshr-server-'))
process.env.DSH_HOME = home

const server = await import('../src/server.ts')
const { clientHandshake, generateKeyPair, parsePrivateKey, publicToPem } = await import('../src/protocol.ts')
const { requiredLevel } = await import('../src/peers.ts')

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

/** The controller's identity; the server under test pins its public half. */
const controller = generateKeyPair()

/** Ask the OS for a port nothing is using, then release it. */
async function freePort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>(resolve => probe.listen(0, '127.0.0.1', resolve))
  const port = (probe.address() as AddressInfo).port
  await new Promise<void>(resolve => probe.close(() => resolve()))
  return port
}

interface Running {
  port: number
  stop: () => void
  /** Fire a cordis event the half subscribed to (session/event, 闂?. */
  fire: (event: string, ...args: unknown[]) => void
  /** The heartbeat this instance writes 闂?what a deploy script would read. */
  heartbeat: () => Record<string, unknown>
}

/** The server's own public key, read from the temp home it just generated. */
function serverPublicKey(): KeyObject {
  return createPublicKey(parsePrivateKey(readFileSync(join(home, 'dsh-remote', 'server.key'), 'utf8')))
}

/**
 * Just enough of the harness for the server half to believe it drives a session.
 *
 * The point is the PUSH channel: to observe `session/event` the half must first
 * own a session, which it only does after `agent.prompt` succeeds 闂?so the fakes
 * cover `agents`/`agentPresets`/`sessions` and an agent whose session has no
 * events. Setup errors are swallowed on purpose: model selection is production
 * behaviour, not what this test is about.
 */
function fakeHarness() {
  const sent: Array<{ id?: unknown, content?: unknown }> = []
  /** Whether the fake agent looks mid-turn (see the interrupt op's busy probe). */
  let busy = false
  const session = {
    id: 'remote-push',
    seq: 0,
    header: { cwd: home },
    snapshotEvents: () => [] as unknown[],
  }
  const agent = {
    session,
    /** `busy` keeps whenIdle pending, which is how an idle agent is told apart. */
    async whenIdle() { if (busy) await new Promise(() => {}) },
    followup(message: { id?: unknown }) { sent.push(message as never) },
    cancel() {},
  }
  const agentCtx = {
    effect: (fn: () => unknown) => { const stop = fn(); return typeof stop === 'function' ? stop : () => {} },
    systemPrompt: { section: () => () => {} },
  }
  const services: Record<string, unknown> = {
    storageDomain: traceFixture(),
    agents: {
      async resume(request: { resumeSessionId: string }) { throw Object.assign(new Error('no such session'), { name: 'SessionPersistenceNotFoundError', sessionId: request.resumeSessionId }) },
      async create(request: { setup?: (ctx: unknown) => Promise<void> }) {
        try { await request.setup?.(agentCtx) } catch { /* model selection is not under test */ }
        return { agent }
      },
      list: () => [],
      get: () => undefined,
    },
    agentPresets: { async resolve() { return { id: 'standard' } }, async mount() {}, defaultId: 'standard', async list() { return [] } },
    workspaceRegistry: {
      async create(path: string) { return { path, async attachSession() {} } },
      list: () => [],
    },
    sessions: { get: () => undefined, async flush() {}, list: () => [] },
    agentDefaultModel: { currentSelection: () => ({ provider: 'test', model: 'test' }) },
    sessionTitle: { rename() {} },
  }
  return { services, agent, sent, session, setBusy: (value: boolean) => { busy = value } }
}

/** Bring up the server half against a fake cordis context. */
async function startServer(
  config: Record<string, unknown> = {},
  fake?: ReturnType<typeof fakeHarness>,
): Promise<Running> {
  const port = await freePort()
  const disposers: Array<() => void> = []
  const handlers = new Map<string, Array<(...args: unknown[]) => void>>()
  const ctx: Record<string, unknown> = {
    logger: { info() {}, warn() {}, debug() {}, error() {} },
    effect(fn: () => unknown) {
      const stop = fn()
      if (typeof stop === 'function') disposers.push(stop as () => void)
      return () => {}
    },
    on(event: string, handler: (...args: unknown[]) => void) {
      const list = handlers.get(event) ?? []
      list.push(handler)
      handlers.set(event, list)
      return () => {}
    },
    // Services absent unless the test supplies a harness: ops that need one must
    // then be seen failing cleanly instead of silently.
    get(name: string) { return fake?.services[name] },
  }
  server.apply(ctx as never, server.Config({
    host: '127.0.0.1',
    port,
    audit: false,
    allowLegacyHandshake: true, // This regression suite deliberately exercises direct DSHR2 clients.
    // One server half per machine owns one journal (and one port). This test
    // brings several instances up on different ports, so each gets its own file 闂?    // otherwise their per-process seq counters would interleave in one file.
    journalFile: join(home, `journal-${port}.jsonl`),
    heartbeatFile: join(home, `heartbeat-${port}.json`),
    ...config,
  }) as never)
  const stop = (): void => { for (const dispose of disposers) { try { dispose() } catch { /* already gone */ } } }
  const deadline = Date.now() + 5000
  for (;;) {
    const reachable = await new Promise<boolean>((resolve) => {
      const probe = connect(port, '127.0.0.1')
      probe.once('connect', () => { probe.destroy(); resolve(true) })
      probe.once('error', () => { probe.destroy(); resolve(false) })
    })
    if (reachable || Date.now() > deadline) break
    await new Promise(resolve => { setTimeout(resolve, 50) })
  }
  return {
    port,
    stop,
    fire: (event, ...args) => { for (const handler of handlers.get(event) ?? []) handler(...args) },
    heartbeat: () => {
      try {
        return JSON.parse(readFileSync(join(home, `heartbeat-${port}.json`), 'utf8')) as Record<string, unknown>
      } catch {
        return {}
      }
    },
  }
}

/** One authenticated controller session with replies routed by frame id. */
async function dial(port: number, key: { privateKey: KeyObject } = controller) {
  const socket: Socket = connect(port, '127.0.0.1')
  await new Promise<void>((resolve, reject) => {
    socket.once('connect', resolve)
    socket.once('error', reject)
  })
  const session = await clientHandshake(socket, key.privateKey, serverPublicKey())
  let counter = 0
  const waiting = new Map<number, (reply: Record<string, unknown>) => void>()
  /** Frames the peer initiated (no request id): the push channel. */
  const pushed: Array<Record<string, unknown>> = []
  void (async () => {
    for (;;) {
      const frame = await session.recv()
      if (frame === null) break
      const id = typeof frame.id === 'number' ? frame.id : undefined
      if (id !== undefined) waiting.get(id)?.(frame)
      else pushed.push(frame)
    }
  })().catch(() => { socket.destroy() }) // Closing an encrypted session rejects a parked receive.
  const request = (op: string, args: Record<string, unknown> = {}, timeoutMs = 15_000) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      counter += 1
      const id = counter
      const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`${op} timed out`)) }, timeoutMs)
      waiting.set(id, (reply) => { clearTimeout(timer); waiting.delete(id); resolve(reply) })
      void session.send({ id, op, ...args }).catch((error) => { clearTimeout(timer); waiting.delete(id); reject(error) })
    })
  /** Await the next pushed frame, or undefined when none arrives in time. */
  const next = async (timeoutMs = 3000): Promise<Record<string, unknown> | undefined> => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      const frame = pushed.shift()
      if (frame !== undefined) return frame
      await new Promise(resolve => { setTimeout(resolve, 25) })
    }
    return undefined
  }
  return { session, request, socket, next, pushed, close: () => { socket.destroy() } }
}

console.log('\n== 1. the handshake pins the controller key ==')
{
  const unpinned = await startServer()
  const stranger = generateKeyPair()
  let refused = false
  try {
    const stray = await dial(unpinned.port, stranger)
    stray.close()
  } catch {
    refused = true
  }
  check('an unpinned client is refused', refused)
  unpinned.stop()

  const pinned = await startServer({ peerPublicKey: publicToPem(controller.publicKey) })
  let accepted = true
  try {
    const ok = await dial(pinned.port)
    ok.close()
  } catch { accepted = false }
  check('the pinned client is accepted', accepted)
  pinned.stop()
}

console.log('\n== 2. sysinfo advertises the ops a controller can rely on ==')
const running = await startServer({ peerPublicKey: publicToPem(controller.publicKey) })
const client = await dial(running.port)
{
  const ping = await client.request('ping')
  check('ping answers', ping.ok === true && ping.pong === true, JSON.stringify(ping))

  const info = await client.request('sysinfo')
  check('sysinfo reports the build', info.build === server.BUILD, String(info.build))
  const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
  check('sysinfo advertises exec.cancel', ops.includes('exec.cancel'), ops.length === 0 ? '(no ops)' : '')
  check('sysinfo advertises usage.read', ops.includes('usage.read'))
  check('sysinfo advertises agent.sessions', ops.includes('agent.sessions'))
  check('sysinfo advertises agent.interrupt', ops.includes('agent.interrupt'))
  // The fast path is capability-negotiated from exactly this list, so a peer
  // that predates it must not be asked for these ops.
  check('sysinfo advertises the chunked-transfer ops',
    ['fs.put.begin', 'fs.put.chunk', 'fs.put.commit', 'fs.put.abort', 'fs.get'].every(op => ops.includes(op)),
    ops.filter(op => op.startsWith('fs.')).join(','))
  check('sysinfo still lists sessions for older controllers', Array.isArray(info.sessions))

  const unknown = await client.request('nope.nope')
  check('an unknown op is refused, not fatal', unknown.ok === false && String(unknown.error).includes('unknown op'), JSON.stringify(unknown))
}

console.log('\n== 3. exec runs, and exec.cancel really stops it ==')
{
  const echo = await client.request('exec', { cmd: 'Write-Output hello-from-peer', shell: 'powershell' })
  check('exec returns stdout', echo.ok === true && String(echo.stdout).includes('hello-from-peer'), JSON.stringify(echo).slice(0, 140))
  check('exec reports a clean exit', echo.exit === 0 && echo.timedOut === false, JSON.stringify({ exit: echo.exit, timedOut: echo.timedOut }))

  const startedAt = Date.now()
  const parked = client.request('exec', {
    cmd: 'Start-Sleep -Seconds 30', shell: 'powershell', timeoutMs: 60_000, execId: 'loop-1',
  }, 70_000)
  await new Promise(resolve => { setTimeout(resolve, 1200) })
  const cancel = await client.request('exec.cancel', { execId: 'loop-1' })
  check('exec.cancel reports it stopped something', cancel.ok === true && cancel.cancelled === true, JSON.stringify(cancel))

  const stopped = await parked
  const elapsed = Date.now() - startedAt
  check('the command settled long before its own 30s sleep', elapsed < 20_000, `${elapsed} ms`)
  check('and says it was cancelled, not timed out', stopped.cancelled === true && stopped.timedOut === false,
    JSON.stringify({ cancelled: stopped.cancelled, timedOut: stopped.timedOut }))
  check('the stderr names the controller as the cause', String(stopped.stderr).includes('stopped by the controller'), String(stopped.stderr))

  const again = await client.request('exec.cancel', { execId: 'loop-1' })
  check('cancelling a finished command is a clean miss', again.ok === true && again.cancelled === false, JSON.stringify(again))
  const noId = await client.request('exec.cancel', {})
  check('exec.cancel without an id is refused', noId.ok === false && String(noId.error).includes('execId'), JSON.stringify(noId))
}

console.log('\n== 4. file ops round-trip inside the temp home ==')
{
  const dir = join(home, 'workspace')
  const target = join(dir, 'note.txt').replace(/\\/gu, '/')
  const write = await client.request('fs.write', { path: target, dataB64: Buffer.from('hello file', 'utf8').toString('base64') })
  check('fs.write creates the file', write.ok === true && write.written === 10, JSON.stringify(write).slice(0, 120))
  const read = await client.request('fs.read', { path: target })
  check('fs.read returns the bytes', Buffer.from(String(read.dataB64), 'base64').toString('utf8') === 'hello file')
  const list = await client.request('fs.list', { path: dir.replace(/\\/gu, '/') })
  check('fs.list sees it', Array.isArray(list.entries) && list.entries.some(entry => entry.name === 'note.txt'))
  const hash = await client.request('fs.hash', { path: target })
  check('fs.hash answers sha256', hash.algo === 'sha256' && String(hash.hash).length === 64, String(hash.hash))
}

console.log('\n== 5. ops that need a service fail honestly, not silently ==')
{
  const prompt = await client.request('agent.prompt', { sessionId: 'remote-none', text: 'hi' })
  check('agent.prompt reports the missing service', prompt.ok === false && String(prompt.error).includes('agents'), JSON.stringify(prompt))
  const sessions = await client.request('agent.sessions', { prefix: 'remote' })
  check('agent.sessions answers with an empty list instead of throwing',
    sessions.ok === true && sessions.count === 0 && Array.isArray(sessions.sessions), JSON.stringify(sessions))
  const interrupt = await client.request('agent.interrupt', { sessionId: 'remote-none' })
  check('agent.interrupt on an unknown session is a clean no-op',
    interrupt.ok === true && interrupt.interrupted === false, JSON.stringify(interrupt))
  // The controller's cost meter calls this; a session with no live handle is a
  // normal "nothing to report", not a failed op.
  const usage = await client.request('usage.read', { sessionId: 'remote-none' })
  check('usage.read answers available:false for a session with no live handle',
    usage.ok === true && usage.available === false && Array.isArray(usage.records), JSON.stringify(usage))
  const usageNoId = await client.request('usage.read', {})
  check('usage.read requires a session id', usageNoId.ok === false && String(usageNoId.error).includes('sessionId'), JSON.stringify(usageNoId))
}

console.log('\n== 6. the permission fence, end to end ==')
{
  const locked = await startServer({ maxPermission: 1, peerPublicKey: publicToPem(controller.publicKey) })
  const limited = await dial(locked.port)
  const ping = await limited.request('ping')
  check('level 1 still permits a look', ping.ok === true, JSON.stringify(ping))
  const exec = await limited.request('exec', { cmd: 'Write-Output nope' })
  check('level 1 refuses exec', exec.ok === false && exec.code === 'FS_PERMISSION_DENIED', JSON.stringify(exec))
  const cancel = await limited.request('exec.cancel', { execId: 'anything' })
  check('level 1 refuses exec.cancel too (it cannot kill a human\'s command)', cancel.ok === false && cancel.code === 'FS_PERMISSION_DENIED', JSON.stringify(cancel))
  limited.close()
  locked.stop()

  check('and the shared rule agrees', requiredLevel('exec') === 3 && requiredLevel('exec.cancel') === 3 && requiredLevel('sysinfo') === 1)
}

console.log('\n== 7. the peer\'s own user: interrupts and words reach the controller ==')
{
  const fake = fakeHarness()
  const runs = await startServer({ peerPublicKey: publicToPem(controller.publicKey) }, fake)
  const peer = await dial(runs.port)

  // The half only reports on sessions IT drives, so drive one first.
  const prompt = await peer.request('agent.prompt', { sessionId: 'remote-push', text: 'do the thing' })
  check('the session is now driven by this controller', prompt.ok === true, JSON.stringify(prompt).slice(0, 120))
  const injectedId = String((fake.sent[0] as { id?: unknown } | undefined)?.id ?? '')
  check('the injected prompt carried an id', injectedId !== '')

  // A turn that ended normally is not news.
  runs.fire('session/event', { id: 'remote-push' }, {
    seq: 3, type: 'turn/end', data: { turn: 1, reason: { kind: 'completed' } },
  })
  check('a completed turn pushes nothing', await peer.next(400) === undefined)

  // The machine's user pressed stop.
  runs.fire('session/event', { id: 'remote-push' }, {
    seq: 4, type: 'turn/end', data: { turn: 1, reason: { kind: 'aborted', reason: { kind: 'user' } } },
  })
  const interrupted = await peer.next()
  check('the controller hears the interrupt', interrupted?.kind === 'interrupt', JSON.stringify(interrupted))
  check('and is told it came from the peer\'s user', interrupted?.origin === 'remote-user' && interrupted?.cause === 'user',
    JSON.stringify(interrupted))
  check('with the session it belongs to', interrupted?.sessionId === 'remote-push', String(interrupted?.sessionId))

  // The machine's user typed into the conversation.
  runs.fire('session/event', { id: 'remote-push' }, {
    seq: 5,
    type: 'user/message',
    data: { id: 'message-from-human', content: [{ type: 'text', text: 'stop and do this instead' }], source: { kind: 'user', rpcId: 'req-42' } },
  })
  const note = await peer.next()
  check('the controller hears what the human said', note?.kind === 'note' && note?.human === true, JSON.stringify(note))
  check('the words travel', String(note?.text).includes('stop and do this instead'), String(note?.text))

  // Our OWN injected message must stay invisible: same shape, but the id is one
  // this half recorded when it injected it.
  runs.fire('session/event', { id: 'remote-push' }, {
    seq: 6,
    type: 'user/message',
    data: { id: injectedId, content: [{ type: 'text', text: 'do the thing' }], source: { kind: 'user' } },
  })
  check('our own prompt is not reported as a human', await peer.next(500) === undefined)

  // A stop the CONTROLLER asked for is echoed back marked as such, so the client
  // can tell its own cancellation from the peer user's.
  // The op has to tell the truth about whether anything was running:
  // `cancel()` is a documented no-op on an idle agent, so a blind
  // `interrupted: true` claims a stop that never happened 閳?which is exactly what
  // a real peer did after its turn had already completed.
  fake.setBusy(false)
  const idleStop = await peer.request('agent.interrupt', { sessionId: 'remote-push' })
  check('interrupting an idle session says so instead of claiming a stop',
    idleStop.interrupted === false && String(idleStop.reason).includes('no turn running'), JSON.stringify(idleStop))

  fake.setBusy(true)
  const ack = await peer.request('agent.interrupt', { sessionId: 'remote-push' })
  check('a live turn is reported as interrupted', ack.ok === true && ack.interrupted === true, JSON.stringify(ack))
  fake.setBusy(false)
  runs.fire('session/event', { id: 'remote-push' }, {
    seq: 7, type: 'turn/end', data: { turn: 1, reason: { kind: 'aborted', reason: { kind: 'user' } } },
  })
  const echo = await peer.next()
  check('the controller\'s own stop comes back marked as its own', echo?.kind === 'interrupt' && echo?.origin === 'controller',
    JSON.stringify(echo))

  // Events for sessions this half does not drive are ignored entirely.
  runs.fire('session/event', { id: 'somebody-elses-session' }, {
    seq: 8, type: 'turn/end', data: { turn: 1, reason: { kind: 'aborted', reason: { kind: 'user' } } },
  })
  check('a session it does not own pushes nothing', await peer.next(400) === undefined)

  peer.close()
  runs.stop()
}

console.log('\n== 8. the trajectory journal records the work, cheaply ==')
{
  const page = await client.request('journal.read', { fromSeq: 0, limit: 200 })
  check('the journal answers', page.ok === true && Array.isArray(page.entries), JSON.stringify(page).slice(0, 120))
  const entries = (page.entries ?? []) as Array<{ seq: number, at: string, kind: string, summary: string, op?: string, detail?: unknown, sessionId?: string }>
  check('it recorded the work this test did', entries.length > 5, String(entries.length))
  check('seq is monotonic', entries.every((entry, index) => index === 0 || entry.seq > (entries[index - 1]?.seq ?? 0)),
    entries.map(entry => entry.seq).join(','))
  check('every entry is stamped', entries.every(entry => typeof entry.at === 'string' && entry.at.includes('T')))
  check('it opens with a lifecycle note', entries[0]?.kind === 'note' && String(entries[0]?.summary).includes(server.BUILD), JSON.stringify(entries[0]))
  check('the exec it ran is in there', entries.some(entry => entry.op === 'exec' && entry.summary.includes('hello-from-peer')),
    entries.filter(entry => entry.op === 'exec').map(entry => entry.summary).join(' | ').slice(0, 160))
  check('the file ops are in there', entries.some(entry => entry.op === 'fs.write') && entries.some(entry => entry.op === 'agent.sessions'))
  check('summaries are one line', entries.every(entry => !String(entry.summary).includes('\n')))

  const withDetail = await client.request('journal.read', { fromSeq: 0, limit: 200, full: true })
  const detailed = (withDetail.entries ?? []) as Array<{ op?: string, detail?: unknown }>
  check('compact reads carry no detail', entries.every(entry => entry.detail === undefined))
  check('full reads do', detailed.some(entry => entry.detail !== undefined))

  // Reading must not grow what is being read.
  const before = Number(page.lastSeq ?? 0)
  await client.request('journal.read', { fromSeq: 0, limit: 5 })
  const after = await client.request('journal.read', { fromSeq: 0, limit: 200 })
  const afterEntries = (after.entries ?? []) as Array<{ op?: string }>
  check('journal.read is never journalled', !afterEntries.some(entry => entry.op === 'journal.read'), String(after.lastSeq))
  check('and a read does not add entries', Number(after.lastSeq ?? 0) === before || afterEntries.filter(e => e.op === 'journal.read').length === 0)

  // Incremental reads are the point: only what is new.
  const first = await client.request('journal.read', { fromSeq: 0, limit: 3 })
  const firstEntries = (first.entries ?? []) as Array<{ seq: number }>
  const second = await client.request('journal.read', { fromSeq: Number(first.nextSeq ?? 0), limit: 200 })
  const secondEntries = (second.entries ?? []) as Array<{ seq: number }>
  check('nextSeq advances past what was returned', secondEntries.every(entry => entry.seq > (firstEntries.at(-1)?.seq ?? 0)),
    `${firstEntries.map(e => e.seq).join(',')} then ${secondEntries.slice(0, 3).map(e => e.seq).join(',')}`)
  const caughtUp = await client.request('journal.read', { fromSeq: Number(second.nextSeq ?? 0) })
  check('and a caught-up read is empty', caughtUp.count === 0,
    `nextSeq=${String(second.nextSeq)} count=${String(caughtUp.count)} entries=${JSON.stringify(caughtUp.entries).slice(0, 200)}`)

  // A reader that has never looked wants the NEWEST entries, not the oldest.
  const tail = await client.request('journal.read', { limit: 3 })
  const tailEntries = (tail.entries ?? []) as Array<{ seq: number }>
  check('omitting fromSeq reads the tail and says so', tail.tail === true, JSON.stringify(tail.tail))
  check('the tail is the newest entries', tailEntries.length === 3
    && tailEntries.at(-1)?.seq === Number(tail.lastSeq), `${tailEntries.map(e => e.seq).join(',')} of ${String(tail.lastSeq)}`)
  check('and it starts after them, not at them', Number(tail.nextSeq) === Number(tail.lastSeq))

  const single = await client.request('journal.read', { limit: 1 })
  const singleEntries = (single.entries ?? []) as Array<{ seq: number }>
  check('a one-entry tail is the very last entry', singleEntries.length === 1
    && singleEntries[0]?.seq === Number(single.lastSeq), JSON.stringify(singleEntries))
  check('an explicit fromSeq is not a tail', (await client.request('journal.read', { fromSeq: 0, limit: 2 })).tail === undefined)
  check('the total is reported for a fresh reader', Number(tail.written) >= Number(tail.lastSeq), `${String(tail.written)}/${String(tail.lastSeq)}`)
}

console.log('\n== 9. the heartbeat a deploy script reads ==')
{
  // This is the check that was missing when a remote upgrade could not be
  // verified: "port open" says nothing about WHICH build is serving.
  const beat = running.heartbeat()
  check('a heartbeat exists once the listener is bound', Object.keys(beat).length > 0, JSON.stringify(beat))
  check('it names the build', beat.build === server.BUILD, String(beat.build))
  check('and the port it bound', Number(beat.port) === running.port, `${String(beat.port)} vs ${running.port}`)
  check('with a parseable instant and a pid',
    !Number.isNaN(Date.parse(String(beat.at))) && Number(beat.pid) > 0, `${String(beat.at)} / ${String(beat.pid)}`)
  check('and it is fresh', Date.now() - Date.parse(String(beat.at)) < 60_000, String(beat.at))

  // The controller in this test is connected, so the count proves the handshake
  // path ran 闂?not merely that a socket was accepted.
  check('a connected controller is visible in it', Number(beat.controllers) >= 1, String(beat.controllers))
  check('and the journal position travels with it', Number(beat.journalSeq) >= 0, String(beat.journalSeq))

  // An instance that never bound (section 1's unpinned one is gone, but the
  // locked one from section 6 wrote its own) must not masquerade as this one.
  check('each instance has its own heartbeat file', running.heartbeat().port !== undefined)
}

// ------------------------------------------------- chunked-transfer helpers
/** Block size these tests use: comfortably inside the 64 KiB..8 MiB clamp. */
const TRANSFER_BLOCK = 512 * 1024

/** The temp directory the transfer sections write into, native path. */
const transferDir = join(home, 'transfer')
/** A three-megabyte, highly compressible payload: text, not random bytes. */
const BIG_PATTERN = 'the quick brown fox jumps over the lazy dog\n'
const BIG_BYTES = 3 * 1024 * 1024
const BIG_DATA = Buffer.from(BIG_PATTERN.repeat(Math.ceil(BIG_BYTES / BIG_PATTERN.length)), 'utf8')
  .subarray(0, BIG_BYTES)
/** Wire paths are normalised exactly like the existing fs tests do. */
const BIG_PATH = join(transferDir, 'big.txt').replace(/\\/gu, '/')

function sha256Of(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

/** One wire block: exactly what a controller would put on the wire. */
function blockOf(data: Buffer, offset: number, length: number, encoding: 'gzip' | 'raw'): Record<string, unknown> {
  const slice = data.subarray(offset, offset + length)
  return encoding === 'gzip'
    ? { dataB64: gzipSync(slice).toString('base64'), encoding: 'gzip' }
    : { dataB64: slice.toString('base64'), encoding: 'raw' }
}

type LoopClient = Awaited<ReturnType<typeof dial>>

/**
 * Upload a whole buffer through the new ops: begin, every block (optionally out
 * of order and concurrently), commit. Returns the interesting replies so a test
 * can assert on whichever stage it is about.
 */
async function putFile(
  client: LoopClient,
  path: string,
  data: Buffer,
  options: Record<string, unknown> = {},
  plan: { order?: 'forward' | 'reverse', encodings?: Array<'gzip' | 'raw'> } = {},
): Promise<{
  begin: Record<string, unknown>
  commit: Record<string, unknown>
  replies: Array<Record<string, unknown>>
}> {
  const begin = await client.request('fs.put.begin', {
    path,
    size: data.length,
    sha256: sha256Of(data),
    chunkSize: TRANSFER_BLOCK,
    ...options,
  })
  if (begin.ok !== true) return { begin, commit: begin, replies: [] }
  const chunkSize = Number(begin.chunkSize)
  const count = Math.ceil(data.length / chunkSize)
  const order = Array.from({ length: count }, (_unused, index) => index)
  if (plan.order === 'reverse') order.reverse()
  const replies = await Promise.all(order.map((index) => {
    const offset = index * chunkSize
    const length = Math.min(chunkSize, data.length - offset)
    return client.request('fs.put.chunk', {
      uploadId: String(begin.uploadId),
      index,
      ...blockOf(data, offset, length, plan.encodings?.[index] ?? 'gzip'),
    })
  }))
  const commit = await client.request('fs.put.commit', { uploadId: String(begin.uploadId) })
  return { begin, commit, replies }
}

/** Names of staging files currently left in a directory. */
function stagingFiles(dir: string): string[] {
  return readdirSync(dir).filter(name => name.endsWith('.dshremote-upload'))
}

console.log('\n== 10. large files take the chunked, compressed fast path ==')
{
  // Six 512 KiB blocks, sent concurrently and out of order, with two of them
  // deliberately uncompressed: the wire encoding is per block, the file is not.
  const encodings: Array<'gzip' | 'raw'> = ['gzip', 'raw', 'gzip', 'gzip', 'raw', 'gzip']
  const { begin, commit, replies } = await putFile(client, BIG_PATH, BIG_DATA, { encoding: 'gzip' },
    { order: 'reverse', encodings })

  check('begin answers a usable upload',
    begin.ok === true && typeof begin.uploadId === 'string' && Number(begin.size) === BIG_DATA.length,
    JSON.stringify(begin).slice(0, 160))
  check('every block is accepted, whatever its order',
    replies.length === 6 && replies.every(reply => reply.ok === true),
    replies.filter(reply => reply.ok !== true).map(reply => String(reply.error)).join(' | ').slice(0, 200))
  check('block replies report their decoded byte count',
    replies.every(reply => Number(reply.received) === TRANSFER_BLOCK), replies.map(reply => String(reply.received)).join(','))
  check('commit succeeds', commit.ok === true, JSON.stringify(commit).slice(0, 200))
  check('commit reports the sha256 it verified', commit.sha256 === sha256Of(BIG_DATA),
    `${String(commit.sha256)} vs ${sha256Of(BIG_DATA)}`)
  check('the commit is a creation with nothing to diff',
    commit.created === true && commit.before === null && Number(commit.beforeBytes) === 0)
  check('the path travels back', commit.path === BIG_PATH, String(commit.path))
  const landed = readFileSync(join(transferDir, 'big.txt'))
  check('the bytes on disk are byte-for-byte the input',
    landed.length === BIG_DATA.length && landed.equals(BIG_DATA), `${landed.length} vs ${BIG_DATA.length}`)
  const stat = await client.request('fs.stat', { path: BIG_PATH })
  check('the returned version chains into the existing guard', stat.version === commit.version,
    `${String(stat.version)} vs ${String(commit.version)}`)

  // The journal is context, not a transfer log: thousands of block lines would
  // drown it, so only the begin/commit pair is recorded.
  const page = await client.request('journal.read', { fromSeq: 0, limit: 500 })
  const entries = (page.entries ?? []) as Array<{ op?: string }>
  check('transfer blocks are not journalled', !entries.some(entry => entry.op === 'fs.put.chunk'))
  check('fs.get reads are not journalled either', !entries.some(entry => entry.op === 'fs.get'))
  check('but the begin and the commit are each recorded once',
    entries.filter(entry => entry.op === 'fs.put.begin').length === 1
    && entries.filter(entry => entry.op === 'fs.put.commit').length === 1,
    `begin=${entries.filter(entry => entry.op === 'fs.put.begin').length} commit=${entries.filter(entry => entry.op === 'fs.put.commit').length}`)
}

console.log('\n== 11. an upload honors createOnly and reports what it replaced ==')
{
  const target = join(transferDir, 'note.txt').replace(/\\/gu, '/')
  const first = Buffer.from('first version\n', 'utf8')
  const second = Buffer.from('second version\n', 'utf8')

  const created = await putFile(client, target, first)
  check('a text file lands through the fast path', created.commit.ok === true && created.commit.created === true,
    JSON.stringify(created.commit).slice(0, 200))

  const refused = await putFile(client, target, second, { createOnly: true })
  check('createOnly refuses to overwrite the existing file',
    refused.commit.ok === false && refused.commit.code === 'FS_NOT_OBSERVED', JSON.stringify(refused.commit).slice(0, 200))
  check('the refused upload left the old bytes untouched', readFileSync(join(transferDir, 'note.txt')).equals(first))

  const overwrite = await putFile(client, target, second)
  check('without createOnly the upload overwrites',
    overwrite.commit.ok === true && overwrite.commit.created === false, JSON.stringify(overwrite.commit).slice(0, 200))
  check('the commit reports the replaced text, for the controller diff',
    overwrite.commit.before === 'first version\n', JSON.stringify(overwrite.commit.before))
  check('and the size of what was replaced', Number(overwrite.commit.beforeBytes) === first.length,
    `${String(overwrite.commit.beforeBytes)} vs ${first.length}`)
  check('the new bytes are on disk', readFileSync(join(transferDir, 'note.txt')).equals(second))

  // size=0 is a legal upload: begin then commit, with no block in between.
  const emptyTarget = join(transferDir, 'empty.txt').replace(/\\/gu, '/')
  const empty = await putFile(client, emptyTarget, Buffer.alloc(0))
  check('an empty file is a legal transfer',
    empty.commit.ok === true && empty.commit.created === true
    && readFileSync(join(transferDir, 'empty.txt')).length === 0,
    JSON.stringify(empty.commit).slice(0, 200))
}

console.log('\n== 12. expectedVersion guards a commit against a stale read ==')
{
  const target = join(transferDir, 'guarded.txt').replace(/\\/gu, '/')
  const first = Buffer.from('version one\n', 'utf8')
  const second = Buffer.from('version two\n', 'utf8')
  const third = Buffer.from('must never land\n', 'utf8')

  await putFile(client, target, first)
  const staleVersion = String((await client.request('fs.stat', { path: target })).version)

  const fresh = await putFile(client, target, second, { expectedVersion: staleVersion })
  check('an up-to-date expectedVersion passes', fresh.commit.ok === true, JSON.stringify(fresh.commit).slice(0, 200))

  // The same token is now the OLD version: exactly the stale read a guard exists
  // to catch. The file must keep the newer bytes and the staging file must go.
  const stale = await putFile(client, target, third, { expectedVersion: staleVersion })
  check('a stale expectedVersion is refused with FS_STALE_VERSION',
    stale.commit.ok === false && stale.commit.code === 'FS_STALE_VERSION', JSON.stringify(stale.commit).slice(0, 200))
  check('and the target file was not changed', readFileSync(join(transferDir, 'guarded.txt')).equals(second))
  check('the refused upload left no staging file', stagingFiles(transferDir).length === 0,
    stagingFiles(transferDir).join(','))
}

console.log('\n== 13. fs.get serves bounded, compressed blocks ==')
{
  const expected = readFileSync(join(transferDir, 'big.txt'))
  const wire = await client.request('fs.get', { path: BIG_PATH, offset: 0, length: 700 * 1024, encoding: 'gzip' })
  check('fs.get answers a block', wire.ok === true, JSON.stringify(wire).slice(0, 160))
  check('it reports the offset, the block size and the total size',
    Number(wire.offset) === 0 && Number(wire.bytes) === 700 * 1024 && Number(wire.size) === expected.length
    && wire.eof === false, JSON.stringify(wire).slice(0, 160))

  const replies: Array<Record<string, unknown>> = []
  let offset = 0
  let eof = false
  while (!eof && replies.length < 10) {
    const reply = await client.request('fs.get', { path: BIG_PATH, offset, length: 700 * 1024, encoding: 'gzip' })
    if (reply.ok !== true) break
    replies.push(reply)
    offset += Number(reply.bytes)
    eof = reply.eof === true
  }
  const decoded = replies.map((reply) => {
    const packed = Buffer.from(String(reply.dataB64 ?? ''), 'base64')
    return reply.encoding === 'gzip' ? gunzipSync(packed) : packed
  })
  const joined = Buffer.concat(decoded)
  check('every block decodes with the encoding it came back with',
    replies.every(reply => reply.encoding === 'gzip' || reply.encoding === 'raw'),
    replies.map(reply => String(reply.encoding)).join(','))
  check('a compressible file really travels compressed', replies.some(reply => reply.encoding === 'gzip'))
  check('the blocks reassemble to the whole file', joined.equals(expected) && joined.length === expected.length,
    `${joined.length} vs ${expected.length}`)
  check('the last block reports eof', eof === true, String(replies.at(-1)?.eof))

  const pastEnd = await client.request('fs.get', { path: BIG_PATH, offset: expected.length, length: 1024 })
  check('an offset at EOF is an empty block with eof set',
    pastEnd.ok === true && Number(pastEnd.bytes) === 0 && pastEnd.eof === true && pastEnd.dataB64 === '',
    JSON.stringify(pastEnd).slice(0, 160))
  const lastByte = await client.request('fs.get', { path: BIG_PATH, offset: expected.length - 1, length: 1024, encoding: 'raw' })
  check('a read past the end stops at the last byte and still says eof',
    lastByte.ok === true && Number(lastByte.bytes) === 1 && lastByte.eof === true, JSON.stringify(lastByte).slice(0, 160))

  const missing = await client.request('fs.get', { path: join(transferDir, 'nope.bin').replace(/\\/gu, '/'), offset: 0, length: 10 })
  check('a missing path is FS_NOT_FOUND', missing.ok === false && missing.code === 'FS_NOT_FOUND',
    JSON.stringify(missing).slice(0, 160))
  const directory = await client.request('fs.get', { path: transferDir.replace(/\\/gu, '/'), offset: 0, length: 10 })
  check('a directory is FS_NOT_REGULAR_FILE', directory.ok === false && directory.code === 'FS_NOT_REGULAR_FILE',
    JSON.stringify(directory).slice(0, 160))
}

console.log('\n== 14. abort removes the staging file ==')
{
  const target = join(transferDir, 'aborted.bin').replace(/\\/gu, '/')
  const data = Buffer.from('will never be committed', 'utf8')
  const begin = await client.request('fs.put.begin', {
    path: target, size: data.length, sha256: sha256Of(data),
  })
  check('begin creates exactly one staging file next to the target',
    begin.ok === true && stagingFiles(transferDir).length === 1, stagingFiles(transferDir).join(','))

  const abort = await client.request('fs.put.abort', { uploadId: String(begin.uploadId) })
  check('abort reports it removed the upload', abort.ok === true && abort.aborted === true, JSON.stringify(abort))
  check('the staging file is gone', stagingFiles(transferDir).length === 0, stagingFiles(transferDir).join(','))
  check('the target itself was never created', !existsSync(join(transferDir, 'aborted.bin')))

  const again = await client.request('fs.put.abort', { uploadId: String(begin.uploadId) })
  check('a second abort is a clean miss, not an error', again.ok === true && again.aborted === false, JSON.stringify(again))
  const late = await client.request('fs.put.chunk', { uploadId: String(begin.uploadId), index: 0, dataB64: '' })
  check('a block for an aborted upload is refused',
    late.ok === false && String(late.error).includes('unknown uploadId'), JSON.stringify(late).slice(0, 160))
}

console.log('\n== 15. a corrupt block is refused without breaking anything ==')
{
  const target = join(transferDir, 'good.bin').replace(/\\/gu, '/')
  const data = Buffer.from('payload that must still land\n', 'utf8')
  const begin = await client.request('fs.put.begin', {
    path: target, size: data.length, sha256: sha256Of(data), chunkSize: 64 * 1024,
  })
  const uploadId = String(begin.uploadId)

  const notGzip = await client.request('fs.put.chunk', {
    uploadId, index: 0, dataB64: Buffer.from('this is not gzip').toString('base64'), encoding: 'gzip',
  })
  check('a block that is not gzip is refused',
    notGzip.ok === false && String(notGzip.error).includes('not valid gzip'), JSON.stringify(notGzip).slice(0, 160))
  const wrongLength = await client.request('fs.put.chunk', {
    uploadId, index: 0, dataB64: gzipSync(Buffer.from('short')).toString('base64'), encoding: 'gzip',
  })
  check('a block that inflates to the wrong size is refused',
    wrongLength.ok === false && String(wrongLength.error).includes('expected'), JSON.stringify(wrongLength).slice(0, 160))
  const wrongRaw = await client.request('fs.put.chunk', {
    uploadId, index: 0, dataB64: Buffer.from('too long for the block').toString('base64'), encoding: 'raw',
  })
  check('a raw block of the wrong size is refused',
    wrongRaw.ok === false && String(wrongRaw.error).includes('expected'), JSON.stringify(wrongRaw).slice(0, 160))
  const badIndex = await client.request('fs.put.chunk', { uploadId, index: 99, dataB64: '' })
  check('an out-of-range block index is refused',
    badIndex.ok === false && String(badIndex.error).includes('index'), JSON.stringify(badIndex).slice(0, 160))

  const good = await client.request('fs.put.chunk', {
    uploadId, index: 0, dataB64: gzipSync(data).toString('base64'), encoding: 'gzip',
  })
  check('the correct block is still accepted after the junk', good.ok === true, JSON.stringify(good).slice(0, 160))
  const commit = await client.request('fs.put.commit', { uploadId })
  check('the upload still commits, unaffected',
    commit.ok === true && readFileSync(join(transferDir, 'good.bin')).equals(data), JSON.stringify(commit).slice(0, 200))

  // A commit must refuse bytes that do not match the declared hash, and must not
  // leave the target (or a staging file) behind when it does.
  const mismatchTarget = join(transferDir, 'mismatch.bin').replace(/\\/gu, '/')
  const badBegin = await client.request('fs.put.begin', {
    path: mismatchTarget, size: data.length, sha256: '0'.repeat(64), chunkSize: 64 * 1024,
  })
  await client.request('fs.put.chunk', {
    uploadId: String(badBegin.uploadId), index: 0,
    dataB64: gzipSync(data).toString('base64'), encoding: 'gzip',
  })
  const mismatch = await client.request('fs.put.commit', { uploadId: String(badBegin.uploadId) })
  check('a sha256 mismatch refuses the commit',
    mismatch.ok === false && String(mismatch.error).includes('sha256'), JSON.stringify(mismatch).slice(0, 160))
  check('and never materialises the target', !existsSync(join(transferDir, 'mismatch.bin')))
  check('no staging files survive any of these failures', stagingFiles(transferDir).length === 0,
    stagingFiles(transferDir).join(','))
}

console.log('\n== 16. the new ops honor the permission ceiling ==')
{
  const restricted = await startServer({ maxPermission: 1, readRoots: [transferDir], peerPublicKey: publicToPem(controller.publicKey) })
  const limited = await dial(restricted.port)

  const read = await limited.request('fs.get', { path: BIG_PATH, offset: 0, length: 1024, encoding: 'raw' })
  const firstKilobyte = Buffer.from(String(read.dataB64 ?? ''), 'base64')
  check('level 1 may read through fs.get', read.ok === true && Number(read.bytes) === 1024,
    JSON.stringify(read).slice(0, 160))
  check('and gets the real bytes back', firstKilobyte.equals(readFileSync(join(transferDir, 'big.txt')).subarray(0, 1024)))

  const denied = await limited.request('fs.put.begin', {
    path: join(transferDir, 'denied.bin').replace(/\\/gu, '/'), size: 3, sha256: 'a'.repeat(64),
  })
  check('level 1 may not begin an upload',
    denied.ok === false && denied.code === 'FS_PERMISSION_DENIED', JSON.stringify(denied).slice(0, 200))
  const blocksDenied = await limited.request('fs.put.chunk', { uploadId: 'whatever', index: 0, dataB64: '' })
  check('level 1 may not send blocks either',
    blocksDenied.ok === false && blocksDenied.code === 'FS_PERMISSION_DENIED', JSON.stringify(blocksDenied).slice(0, 200))

  limited.close()
  restricted.stop()
  check('the shared rule agrees about the new ops',
    requiredLevel('fs.put.begin') === 2 && requiredLevel('fs.put.chunk') === 2
    && requiredLevel('fs.put.commit') === 2 && requiredLevel('fs.put.abort') === 2
    && requiredLevel('fs.get') === 1,
    `${requiredLevel('fs.put.begin')}/${requiredLevel('fs.put.chunk')}/${requiredLevel('fs.put.commit')}/${requiredLevel('fs.put.abort')}/${requiredLevel('fs.get')}`)
}

console.log('\n== 17. tearing the half down aborts in-flight uploads ==')
{
  // An upload stages a real file next to its target. Releasing the plugin
  // context (hot reload, process shutdown) must delete it, or the peer's disk
  // slowly fills with `*.dshremote-upload` orphans.
  const shortLived = await startServer({ peerPublicKey: publicToPem(controller.publicKey) })
  const ephemeral = await dial(shortLived.port)
  const target = join(transferDir, 'orphan.bin').replace(/\\/gu, '/')
  const data = Buffer.from('left behind?', 'utf8')
  const begin = await ephemeral.request('fs.put.begin', {
    path: target, size: data.length, sha256: sha256Of(data),
  })
  check('the upload is staged before teardown',
    begin.ok === true && stagingFiles(transferDir).length === 1, stagingFiles(transferDir).join(','))

  ephemeral.close()
  shortLived.stop()
  check('disposal deleted the staged file', stagingFiles(transferDir).length === 0, stagingFiles(transferDir).join(','))
  check('and never created the target', !existsSync(join(transferDir, 'orphan.bin')))
}

client.close()
running.stop()
rmSync(home, { recursive: true, force: true })
console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
