/**
 * Self-test for the session-reuse policy — no peer, no socket, no cordis.
 *
 * The point of these cases is the *decision*: which remote conversation an
 * omitted `session_id` continues, and that "remembering" degrades to nothing
 * rather than to an error. Run from the harness checkout so `tsx` resolves:
 *
 *   node --import tsx/esm E:/path/to/dsh-remote/test/session-reuse.test.ts
 */

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  SessionMemory,
  anchorSessionId,
  familyMatches,
  freshSessionId,
  normalizePath,
  orderReusableSessions,
  pickReusableSession,
  scopeKey,
} from '../src/reuse.ts'

let failures = 0

function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

console.log('\n== 1. familyMatches: which ids are "ours" ==')
check('exact prefix matches', familyMatches('remote', 'remote'))
check('prefixed id matches', familyMatches('remote', 'remote-muomaz7k'))
check('another family does not', !familyMatches('remote', 'ieee-probe-001'))
check('"remotex" is not the family', !familyMatches('remote', 'remotex-1'))
check('empty prefix accepts anything', familyMatches('', 'whatever-1'))
check('blank prefix is empty', familyMatches('   ', 'whatever-1'))

console.log('\n== 2. anchorSessionId: one chat, one remote conversation ==')
{
  const bare = anchorSessionId('remote')
  check('no calling chat falls back to the family', bare === 'remote', bare)
  const a = anchorSessionId('remote', 'session-711c8b2c-7a8c-489b')
  const b = anchorSessionId('remote', 'session-eeee1111-2222-3333')
  check('derived from the chat', a.startsWith('remote-') && a !== bare, a)
  check('stable across calls', anchorSessionId('remote', 'session-711c8b2c-7a8c-489b') === a, a)
  check('a different chat gets a different id', a !== b, `${a} ${b}`)
  check('safe charset', /^[A-Za-z0-9._-]+$/u.test(a), a)
  check('blank prefix falls back to remote', anchorSessionId('  ', 'session-x').startsWith('remote-'))
  check('blank chat id is treated as absent', anchorSessionId('remote', '   ') === 'remote')
  check('fresh ids are not anchors', freshSessionId('remote', 1_700_000_000_000) !== bare)
  // The whole point of the stricter rule: identity cannot be split by anything
  // the caller passes per call. Nothing but the chat feeds the id.
  const sameChat = new Set([
    anchorSessionId('remote', 'session-chat-1'),
    anchorSessionId('remote', 'session-chat-1'),
  ])
  check('one id per chat, regardless of repeated calls', sameChat.size === 1, [...sameChat].join(','))
}

console.log('\n== 3. scopeKey: the chat and nothing else ==')
{
  const base = scopeKey({ prefix: 'remote', localSession: 'session-1' })
  check('stable', base === scopeKey({ prefix: 'remote', localSession: 'session-1' }))
  check('different chat differs', base !== scopeKey({ prefix: 'remote', localSession: 'session-2' }))
  check('different family differs', base !== scopeKey({ prefix: 'other', localSession: 'session-1' }))
  check('no chat is its own scope', scopeKey({ prefix: 'remote' }) !== base)
}

console.log('\n== 4. pickReusableSession: newest first, inside the family ==')
{
  const candidates = [
    { sessionId: 'remote-new', cwd: 'E:\\proj', live: true, seq: 40 },
    { sessionId: 'remote-old', cwd: 'E:\\proj' },
    { sessionId: 'ieee-probe-001' },
  ]
  check('takes the newest match', pickReusableSession(candidates, { prefix: 'remote' })?.sessionId === 'remote-new')
  check(
    'skips ids already in flight',
    pickReusableSession(candidates, { prefix: 'remote', skip: new Set(['remote-new']) })?.sessionId === 'remote-old',
  )
  check('never adopts another family', pickReusableSession(
    [{ sessionId: 'ieee-probe-001' }, { sessionId: 'remote-x' }],
    { prefix: 'remote' },
  )?.sessionId === 'remote-x')
  check(
    'workspace mismatch is skipped',
    pickReusableSession(candidates, { prefix: 'remote', workspace: 'E:\\other' }) === undefined,
  )
  check(
    'workspace match is taken',
    pickReusableSession(candidates, { prefix: 'remote', workspace: 'e:/proj/' })?.sessionId === 'remote-new',
  )
  check(
    'an unknown cwd is still adoptable',
    pickReusableSession([{ sessionId: 'remote-live' }], { prefix: 'remote', workspace: 'E:\\any' })?.sessionId === 'remote-live',
  )
  check('nothing to reuse yields undefined', pickReusableSession([], { prefix: 'remote' }) === undefined)
  check('junk entries are ignored', pickReusableSession(
    [null as never, { sessionId: '' }, { sessionId: 'remote-ok' }],
    { prefix: 'remote' },
  )?.sessionId === 'remote-ok')
  check('normalizePath folds case and separators', normalizePath('E:\\A\\b\\') === 'e:/a/b')
}

console.log('\n== 5. orderReusableSessions: what a peer offers ==')
{
  const accounts = [
    { path: 'E:\\proj-a', sessionIds: ['remote-a2', 'remote-a1', 'ieee-probe-001'] },
    { path: 'E:\\proj-b', sessionIds: ['remote-b1', 'remote-a2'] },
  ]
  const all = orderReusableSessions(accounts, { prefix: 'remote' })
  check('keeps workspace order, newest first', all.map(s => s.sessionId).join(',') === 'remote-a2,remote-a1,remote-b1',
    all.map(s => s.sessionId).join(','))
  check('carries the account cwd', all[0]?.cwd === 'E:\\proj-a', String(all[0]?.cwd))
  check('drops other families', !all.some(s => s.sessionId === 'ieee-probe-001'))
  check('dedupes across workspaces', all.filter(s => s.sessionId === 'remote-a2').length === 1)
  const narrowed = orderReusableSessions(accounts, { prefix: 'remote', workspace: 'e:/proj-b/' })
  check('narrows to one workspace, in its own order',
    narrowed.map(s => s.sessionId).join(',') === 'remote-b1,remote-a2' && narrowed.every(s => s.cwd === 'E:\\proj-b'),
    narrowed.map(s => s.sessionId).join(','))
  check('unknown workspace yields nothing', orderReusableSessions(accounts, { prefix: 'remote', workspace: 'E:\\nope' }).length === 0)
  check('no accounts yields nothing', orderReusableSessions([], { prefix: 'remote' }).length === 0)
}

console.log('\n== 6. SessionMemory: a cache that never breaks a prompt ==')
{
  const dir = mkdtempSync(join(tmpdir(), 'dshr-reuse-'))
  const file = join(dir, 'nested', 'client-sessions.json')
  try {
    const first = new SessionMemory(file)
    first.load()
    check('missing file loads empty', first.size === 0)
    check('missing key reads undefined', first.get('k') === undefined)
    first.set('k', 'remote-1')
    check('set/get round-trips', first.get('k') === 'remote-1')
    check('inUse reports the id', first.inUse().has('remote-1'))
    first.set(scopeKey({ prefix: 'remote', localSession: 'local-a' }), 'remote-shared')
    first.set(scopeKey({ prefix: 'remote', localSession: 'local-b' }), 'remote-shared')
    first.set(scopeKey({ prefix: 'remote', localSession: 'local-c' }), 'remote-other')
    check('reverse lookup finds the latest local session', first.latestLocalSessionFor('remote-shared') === 'local-b')
    first.set(scopeKey({ prefix: 'remote-other', localSession: 'local-peer-b' }), 'remote-shared')
    check('reverse lookup with no family takes the latest mapping', first.latestLocalSessionFor('remote-shared') === 'local-peer-b')
    check('a peer-specific family is preferred', first.latestLocalSessionFor('remote-shared', 'remote') === 'local-b')
    check('the other family resolves its own mapping', first.latestLocalSessionFor('remote-shared', 'remote-other') === 'local-peer-b')
    check('an unknown peer family never adopts another peer mapping', first.latestLocalSessionFor('remote-shared', 'remote-unmatched') === undefined)
    check('reverse lookup ignores unknown remote sessions', first.latestLocalSessionFor('remote-missing') === undefined)
    check('reverse lookup ignores a blank id', first.latestLocalSessionFor('') === undefined)
    check('file was written', readFileSync(file, 'utf8').includes('remote-1'))

    const second = new SessionMemory(file)
    second.load()
    check('survives a restart', second.get('k') === 'remote-1')
    check('reverse lookup survives a restart', second.latestLocalSessionFor('remote-shared', 'remote') === 'local-b')
    check('the family preference survives a restart', second.latestLocalSessionFor('remote-shared', 'remote-other') === 'local-peer-b')

    const corrupt = new SessionMemory(join(dir, 'corrupt.json'))
    writeFileSync(join(dir, 'corrupt.json'), '{ not json', 'utf8')
    corrupt.load()
    check('a corrupt file loads empty', corrupt.size === 0)
    corrupt.set('k', 'remote-2')
    check('and heals on the next write', corrupt.get('k') === 'remote-2')

    const bounded = new SessionMemory(join(dir, 'bounded.json'), 3)
    for (let i = 0; i < 6; i += 1) bounded.set(`k${i}`, `remote-${i}`)
    check('prunes to the limit', bounded.size === 3, String(bounded.size))
    check('keeps the newest', bounded.get('k5') === 'remote-5')
    check('drops the oldest', bounded.get('k0') === undefined)

    const unwritable = new SessionMemory(join(dir, 'corrupt.json', 'nope.json'))
    unwritable.set('k', 'remote-3')
    check('an unwritable path does not throw', unwritable.get('k') === 'remote-3')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
