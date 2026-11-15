/** Offline exact-error and placement tests; no runtime services or network. */
import assert from 'node:assert/strict'
import { deliverInput, inputMode, isDefiniteSessionNotFound } from '../src/agent-delivery.ts'
import type { RemoteInputSource } from '../src/agent-delivery.ts'
import { admitTracked, traceKey } from '../src/message-traces.ts'
import type { MessageTrace, TraceStore } from '../src/message-traces.ts'

class SessionPersistenceNotFoundError extends Error {
  sessionId: string
  constructor(id: string) { super(`session "${id}" not found`); this.name = 'SessionPersistenceNotFoundError'; this.sessionId = id }
}
assert.equal(isDefiniteSessionNotFound(new SessionPersistenceNotFoundError('scope-session'), 'scope-session'), true)
assert.equal(isDefiniteSessionNotFound(new SessionPersistenceNotFoundError('other'), 'scope-session'), false)
for (const error of [new Error('no such session'), Object.assign(new Error('ENOENT'), { code: 'ENOENT' }),
  Object.assign(new Error('corrupt'), { name: 'SessionPersistenceCorruptionError' }),
  Object.assign(new Error('held'), { name: 'SessionAlreadyOwnedError' }),
  Object.assign(new Error('unsupported'), { name: 'SessionFormatUnsupportedError' }),
  Object.assign(new Error('not found'), { code: 'session/not-found', details: { sessionId: 'other' } }),
  new Error('persistence is not configured')]) assert.equal(isDefiniteSessionNotFound(error, 'scope-session'), false)
assert.equal(isDefiniteSessionNotFound(Object.assign(new Error('absent'), { code: 'session/not-found', details: { sessionId: 'scope-session' } }), 'scope-session'), true)
assert.equal(inputMode(undefined), 'auto')
assert.throws(() => inputMode('invented'), /mode must/)
const source: RemoteInputSource = { kind: 'dsh-remote', version: 1, principal: 'principal', remoteSessionId: 'wire-id', operation: 'agent.note', traceId: 'trace' }
const message = { id: 'msg' as never, role: 'user' as const, source, content: [{ type: 'text' as const, text: 'note' }] }
const calls: string[] = []
const agent = { followup: () => { calls.push('queue') }, steer: () => { calls.push('steer') } }
assert.deepEqual(deliverInput(agent, message, 'auto', true), { mode: 'steer', processing: 'next-step' })
assert.deepEqual(deliverInput(agent, message, 'auto', false), { mode: 'queue', processing: 'starting' })
assert.deepEqual(deliverInput(agent, message, 'queue', true), { mode: 'queue', processing: 'next-turn' })
assert.deepEqual(deliverInput(agent, message, 'steer', false), { mode: 'steer', processing: 'starting' })
assert.deepEqual(calls, ['steer', 'queue', 'queue', 'steer'])
assert.throws(() => deliverInput({ followup: agent.followup }, message, 'auto', true), /no steering capability/)
const rows = new Map<string, MessageTrace>()
const order: string[] = []
const store: TraceStore = { get: key => rows.get(key), async put(key, value) { order.push(value.state); rows.set(key, structuredClone(value)) } }
const trace: MessageTrace = { version: 1, traceId: 'trace', principal: 'principal', sessionId: 'scoped-session', remoteSessionId: 'wire-session', messageId: 'message', seq: null, time: 1, operation: 'agent.note', requestedMode: 'auto', mode: 'steer', state: 'admitting' }
await admitTracked(store, trace, () => { assert.equal(rows.get(traceKey(trace))?.state, 'admitting'); order.push('wake') })
assert.deepEqual(order, ['admitting', 'wake', 'accepted'])
await assert.rejects(admitTracked(store, trace, () => { throw new Error('must not replay') }), /not replaying/)
assert.notEqual(traceKey(trace), traceKey({ ...trace, principal: 'other' }))
assert.notEqual(traceKey(trace), traceKey({ ...trace, sessionId: 'other' }))
let woke = false
await assert.rejects(admitTracked({ get: () => undefined, put: async () => { throw new Error('disk failed') } }, trace, () => { woke = true }), /disk failed/)
assert.equal(woke, false)
const ambiguous = { ...trace, messageId: 'ambiguous' }
await assert.rejects(admitTracked(store, ambiguous, () => { throw new Error('inbox uncertain') }), /inbox uncertain/)
assert.equal(rows.get(traceKey(ambiguous))?.state, 'unknown')
console.log('ALL PASS: exact absence only, real producer source, queue/steer/auto and persist-before-wake with no ambiguous replay')
