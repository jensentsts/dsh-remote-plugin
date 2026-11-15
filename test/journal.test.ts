/**
 * Self-test for the trajectory journal.
 *
 * The journal is the thing the objective calls "save model calls but keep every
 * trace", so the cases that matter are: seq survives a restart, a read returns
 * only what is new, the default read is context-sized (no detail), a bulk
 * payload never lands in the file, and nothing here can throw into the work it
 * records.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/journal.test.ts
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { Journal, clip, formatJournal, safeDetail, summarizeEvent, summarizeOp } from '../src/journal.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

const dir = mkdtempSync(join(tmpdir(), 'dshr-journal-'))
const file = join(dir, 'journal.jsonl')

console.log('\n== 1. append assigns seq and instant ==')
{
  let clock = Date.parse('2026-10-08T10:00:00.000Z')
  const journal = new Journal({ file, now: () => new Date(clock) })
  const first = journal.append({ kind: 'note', summary: 'journal started' })
  clock += 1000
  const second = journal.append({ kind: 'op', summary: 'ping → ok', op: 'ping', ok: true, ms: 3 })
  check('seq starts at 1 and increments', first.seq === 1 && second.seq === 2, `${first.seq},${second.seq}`)
  check('the instant comes from the clock', first.at === '2026-10-08T10:00:00.000Z' && second.at === '2026-10-08T10:00:01.000Z', second.at)
  check('lastSeq tracks the highest', journal.lastSeq === 2)
  check('writtenCount counts entries', journal.writtenCount === 2)
  check('the file has one line per entry', readFileSync(file, 'utf8').trim().split('\n').length === 2)
}

console.log('\n== 2. read is incremental and context-sized ==')
{
  const journal = new Journal({ file: join(dir, 'read.jsonl') })
  for (let i = 0; i < 5; i += 1) {
    journal.append({ kind: 'op', summary: `step ${i}`, detail: { big: 'x'.repeat(50) } })
  }
  const all = journal.read(0, 10, false)
  check('reads everything', all.count === 5 && all.total === 5, JSON.stringify({ count: all.count, total: all.total }))
  check('nextSeq points at the last entry returned', all.nextSeq === 5)
  check('detail is stripped by default', all.entries.every(entry => entry.detail === undefined))
  check('summaries survive the strip', all.entries.every(entry => typeof entry.summary === 'string'))

  const tail = journal.read(3, 10, false)
  check('fromSeq is exclusive', tail.count === 2 && tail.entries[0]?.seq === 4, JSON.stringify(tail.entries.map(e => e.seq)))
  check('a caught-up read returns nothing', journal.read(tail.nextSeq, 10, false).count === 0)

  const limited = journal.read(0, 2, false)
  check('limit is honoured and nextSeq follows it', limited.count === 2 && limited.nextSeq === 2, JSON.stringify({ c: limited.count, n: limited.nextSeq }))
  const withDetail = journal.read(0, 1, true)
  check('full returns the detail', withDetail.entries[0]?.detail !== undefined, JSON.stringify(withDetail.entries[0]))
}

console.log('\n== 3. seq survives a restart ==')
{
  const path = join(dir, 'restart.jsonl')
  const first = new Journal({ file: path })
  first.append({ kind: 'note', summary: 'a' })
  first.append({ kind: 'note', summary: 'b' })

  const restarted = new Journal({ file: path })
  restarted.load()
  check('resumes from the file', restarted.lastSeq === 2, String(restarted.lastSeq))
  const next = restarted.append({ kind: 'note', summary: 'c' })
  check('the next append continues the sequence', next.seq === 3, String(next.seq))
  const history = restarted.read(0, 10, false)
  check('and history written by the previous process is readable', history.count === 3, String(history.count))
}

console.log('\n== 4. a torn last line does not poison the journal ==')
{
  const path = join(dir, 'torn.jsonl')
  const journal = new Journal({ file: path })
  journal.append({ kind: 'note', summary: 'good' })
  writeFileSync(path, `${readFileSync(path, 'utf8')}{"seq":2,"at":"x","kind":"op"`, 'utf8')
  const reopened = new Journal({ file: path })
  reopened.load()
  check('the good entry is read and the torn one ignored', reopened.lastSeq === 1, String(reopened.lastSeq))
  reopened.append({ kind: 'note', summary: 'after' })
  check('appending still works', reopened.lastSeq === 2)
}

console.log('\n== 5. rotation keeps one generation and the sequence ==')
{
  const path = join(dir, 'rotate.jsonl')
  const journal = new Journal({ file: path, maxBytes: 400 })
  for (let i = 0; i < 12; i += 1) journal.append({ kind: 'op', summary: `entry ${i} ${'y'.repeat(60)}` })
  check('the live file was rotated', readFileSync(`${path}.1`, 'utf8').trim() !== '')
  const seqs = journal.read(0, 100, false).entries.map(entry => entry.seq)
  check('seq stays monotonic across rotation', journal.lastSeq === 12, String(journal.lastSeq))
  check('the recent window is still readable', seqs.length > 0 && seqs.at(-1) === 12, JSON.stringify(seqs.slice(-3)))

  // A brand new process reading the same file must still find recent history.
  const fresh = new Journal({ file: path })
  fresh.load()
  check('a fresh process resumes the sequence after rotation', fresh.lastSeq === 12, String(fresh.lastSeq))
  check('and can answer a read for history it did not write', fresh.read(10, 100, false).count >= 1,
    JSON.stringify(fresh.read(10, 100, false).entries.map(e => e.seq)))
}

console.log('\n== 6. nothing sensitive or bulky is stored verbatim ==')
{
  const payload = safeDetail({ dataB64: 'A'.repeat(5000), content: 'B'.repeat(3000), path: 'C:/x', nested: { stdout: 'D'.repeat(500) } }) as Record<string, unknown>
  check('bulk payloads become sizes, not bodies', String(payload.dataB64).includes('chars') && String(payload.dataB64).length < 40, String(payload.dataB64))
  check('file content too', String(payload.content).includes('chars'), String(payload.content))
  check('plain values survive', payload.path === 'C:/x')
  check('nested bulk is summarized as well', String((payload.nested as Record<string, unknown>).stdout).includes('chars'))
  check('long strings are clipped', clip('z'.repeat(50), 10).startsWith('zzzzzzzzzz…'))
  let deep: unknown = 'leaf'
  for (let i = 0; i < 8; i += 1) deep = { down: deep }
  check('depth is capped', JSON.stringify(safeDetail(deep)).includes('deep'), JSON.stringify(safeDetail(deep)).slice(0, 80))
}

console.log('\n== 7. op summaries say what happened ==')
{
  const exec = summarizeOp('exec', { cmd: 'Get-ChildItem C:\\a\nsecond line' }, { ok: true, ms: 12, result: { exit: 0, stdout: 'many', stderr: '' } })
  check('names the op and the command', exec.summary.startsWith('exec Get-ChildItem C:\\a'), exec.summary)
  check('reports the exit code', exec.summary.includes('exit 0'), exec.summary)
  check('does not paste the command body twice', !exec.summary.includes('second line'), exec.summary)
  const failed = summarizeOp('fs.write', { path: 'C:/x/y.txt' }, { ok: false, ms: 2, error: 'FS_PERMISSION_DENIED: nope' })
  check('a failure is explicit and includes the path', failed.summary.includes('FAILED') && failed.summary.includes('C:/x/y.txt'), failed.summary)
  const cancelled = summarizeOp('exec', { cmd: 'sleep' }, { ok: true, ms: 900, result: { exit: null, cancelled: true } })
  check('a cancelled command says so', cancelled.summary.includes('cancelled'), cancelled.summary)
  const prompt = summarizeOp('agent.prompt', { sessionId: 'remote-x' }, { ok: true, ms: 5, result: { reply: 'hello there', sessionId: 'remote-x' } })
  check('a prompt reports the reply size and the session', prompt.summary.includes('chars reply') && prompt.summary.includes('remote-x'), prompt.summary)
}

console.log('\n== 8. observed session events become journal entries ==')
{
  const ended = summarizeEvent('turn/end', { turn: 3, reason: { kind: 'completed' } })
  check('a normal turn end is a turn', ended?.kind === 'turn' && ended.summary.includes('completed'), JSON.stringify(ended))
  const aborted = summarizeEvent('turn/end', { turn: 4, reason: { kind: 'aborted', reason: { kind: 'user' } } })
  check('a cancelled turn is an interrupt, with the cause', aborted?.kind === 'interrupt' && aborted.summary.includes('user'), JSON.stringify(aborted))
  const model = summarizeEvent('assistant/message', {
    message: { content: [{ type: 'text', text: 'hi there' }, { type: 'tool-call', name: 'exec' }, { type: 'tool-call', name: 'read' }] },
  })
  check('a model reply is a model entry naming its tools',
    model?.kind === 'model' && model.summary.includes('chars') && model.summary.includes('exec') && model.summary.includes('read'),
    JSON.stringify(model))
  const human = summarizeEvent('user/message', { content: [{ type: 'text', text: 'please stop' }], source: { kind: 'user', rpcId: 'r1' } })
  check('a human message is noted as the machine\'s user', human?.kind === 'note' && human.summary.includes("machine's user"), JSON.stringify(human))
  const injected = summarizeEvent('user/message', { content: [{ type: 'text', text: 'injected prompt' }], source: { kind: 'user' } })
  check('an injected message is marked injected', injected?.summary.startsWith('injected message') === true, JSON.stringify(injected))
  check('unrelated events are not journalled', summarizeEvent('tool/call', {}) === undefined)
}

console.log('\n== 9. recording can never break the work it records ==')
{
  const unwritable = new Journal({ file: join(dir, 'a-file.txt', 'nested', 'journal.jsonl') })
  writeFileSync(join(dir, 'a-file.txt'), 'not a directory', 'utf8')
  let threw = false
  try { unwritable.append({ kind: 'op', summary: 'still recorded' }) } catch { threw = true }
  check('an unwritable path does not throw', !threw)
  check('and the entry is still readable in-process', unwritable.read(0, 10, false).count === 1)
}

console.log('\n== 10. what the model actually reads ==')
{
  const page = formatJournal({
    written: 42,
    count: 2,
    nextSeq: 9,
    tail: true,
    entries: [
      { seq: 8, at: '2026-10-08T10:31:07.123Z', kind: 'op', summary: 'exec Get-ChildItem → exit 0' },
      { seq: 9, at: '2026-10-08T10:31:09.000Z', kind: 'interrupt', summary: 'turn 1 ended: aborted (user)' },
    ],
  })
  check('the header carries the totals and the cursor', page[0]?.includes('共记录 42 条') === true
    && page[0]?.includes('本次 2 条') === true && page[0]?.includes('nextSeq=9') === true, String(page[0]))
  check('a tail read says so', page[0]?.includes('（尾部）') === true, String(page[0]))
  check('one line per entry, with seq and time',
    page[1] === '#8 10:31:07 op        exec Get-ChildItem → exit 0', String(page[1]))
  check('kinds are aligned so the column reads down', page[1]?.includes('op        ') === true, String(page[1]))
  check('and it teaches the next call', String(page.at(-1)).includes('省略 from_seq'), String(page.at(-1)))

  const empty = formatJournal({ written: 42, count: 0, nextSeq: 42, entries: [] })
  check('an empty read says there is nothing new', empty.some(line => line.includes('没有新条目')), empty.join(' | '))

  const unsupported = formatJournal({ unsupported: true })
  check('an old peer is explained, not thrown', unsupported[0]?.includes('r14+') === true, String(unsupported[0]))
  check('and a working alternative is offered', unsupported.some(line => line.includes('remote_agent_events')), unsupported.join(' | '))

  // A malformed payload must not throw inside a tool render.
  const junk = formatJournal({ entries: [{}, { seq: 3 }] } as never)
  check('a missing field degrades to placeholders', junk.some(line => line.startsWith('#3 --:--:-- ?')), junk.join(' | '))
  check('and a null payload is still a report', formatJournal({} as never)[0]?.includes('remote journal') === true)
}

rmSync(dir, { recursive: true, force: true })
console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
