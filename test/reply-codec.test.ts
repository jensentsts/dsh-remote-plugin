/** Offline message export and presenter snapshot: no DSH runtime, sockets, model or external peer. */
import assert from 'node:assert/strict'
import { extractPublicEvents, mergeReplyFrames, publicContent, renderRemoteReplies, replyFields, replyFrame, summarizeReplies } from '../src/reply-codec.ts'
import type { ReplyEvent } from '../src/reply-codec.ts'

const message = (id: string, content: unknown[], patch: Record<string, unknown> = {}) => ({
  turn: 1, step: 1, message: { id, role: 'assistant', source: { kind: 'model', provider: 'fixture-provider', model: 'fixture-model', replayState: { secret: 'never export' } }, content }, ...patch,
})
const events: ReplyEvent[] = [
  { seq: 0, time: 100, type: 'assistant/message', data: message('before', [{ type: 'text', text: 'before' }]) },
  { seq: 1, time: 101, type: 'turn/start', data: { turn: 1 } },
  { seq: 2, time: 102, type: 'step/start', data: { turn: 1, step: 1 } },
  { seq: 3, time: 103, type: 'user/message', data: { id: 'input', role: 'user', source: { kind: 'dsh-remote', version: 1, traceId: 'trace', replayState: { secret: 'no' } }, content: [{ type: 'text', text: 'request' }] } },
  { seq: 4, time: 104, type: 'assistant/attempt', data: message('attempt', [{ type: 'text', text: 'attempt not reply' }]) },
  { seq: 5, time: 105, type: 'assistant/message', data: message('reasoning', [{ type: 'reasoning', text: 'private thinking' }]) },
  { seq: 6, time: 106, type: 'assistant/message', data: message('first', [{ type: 'reasoning', text: 'secret' }, { type: 'text', text: 'first ' }, { type: 'text', text: 'reply' }, { type: 'tool-call', name: 'tool', arguments: 'secret' }]) },
  { seq: 7, time: 107, type: 'tool/result', data: { message: { content: [{ type: 'text', text: 'tool output' }], isError: true } } },
  { seq: 8, time: 108, type: 'assistant/message', data: message('partial', [{ type: 'text', text: 'interrupted partial' }], { interrupted: true }) },
  { seq: 9, time: 109, type: 'assistant/message', data: message('second', [{ type: 'text', text: 'second reply' }], { step: 2, usage: { inputTokens: 100, outputTokens: 20, replayState: 'no' } }) },
  { seq: 10, time: 110, type: 'assistant/message', data: message('media-only', [
    { type: 'image', attachment: { attachmentId: 'remote-image', mediaType: 'image/png', bytes: 120, width: 16, height: 12, name: 'image.png', data: 'should not copy' } },
    { type: 'file', attachment: { attachmentId: 'remote-file', name: 'report.pdf', bytes: 456, localPath: 'no-path-leak' } },
  ], { step: 3 }) },
  { seq: 11, time: 111, type: 'turn/end', data: { turn: 1, reason: { kind: 'completed' } } },
]
const outcome = summarizeReplies(events, 1, 'remote-fixture')
assert.equal(outcome.text, 'first reply\n\nsecond reply')
assert.deepEqual(outcome.replies.map(reply => reply.messageId), ['first', 'second', 'media-only'])
assert.deepEqual(outcome.replies.map(reply => [reply.seq, reply.time, reply.turn, reply.step]), [[6, 106, 1, 1], [9, 109, 1, 2], [10, 110, 1, 3]])
assert.equal(outcome.replies[2]?.content.length, 2)
assert.equal(outcome.replies[2]?.attachmentScope, 'remote-session')
assert.deepEqual(outcome.replies[1]?.usage, { inputTokens: 100, outputTokens: 20 })
for (const secret of ['private thinking', 'replayState', 'interrupted partial', 'no-path-leak', 'should not copy']) assert.equal(JSON.stringify(outcome).includes(secret), false)
assert.deepEqual(replyFields(outcome).replies, outcome.replies)
assert.equal(replyFields({ reply: 'last text from old peer' }).replyFormat, 'legacy-text')
assert.equal(replyFields({ reply: 'legacy', replies: [{ messageId: 'invented' }] }).replyFormat, 'invalid-replies')
assert.equal(replyFields({ ...outcome, replies: [...outcome.replies].reverse() }).replyFormat, 'invalid-replies')
assert.equal(replyFields({ ...outcome, sessionId: 'different-session' }).replyFormat, 'invalid-replies')
assert.equal(replyFields({ ...outcome, replies: [outcome.replies[0], outcome.replies[0]] }).replyFormat, 'invalid-replies')
assert.equal(replyFields({ ...outcome, replies: [{ ...outcome.replies[0], source: { kind: 'user' } }] }).replyFormat, 'invalid-replies')
// Per-message IO frames use the same validation; they may only fill gaps in a
// final committed array, never create boundaries for a legacy string.
const frame = replyFrame(outcome.replies[0], 'remote-fixture')
assert.equal(frame?.messageId, 'first')
assert.equal(replyFrame({ ...outcome.replies[0], sessionId: 'other' }, 'remote-fixture'), undefined)
const partial = { ...outcome, replies: [outcome.replies[0]], reply: 'first reply' }
const merged = mergeReplyFrames(partial, [outcome.replies[1], outcome.replies[2]]) as { replies: Array<{ messageId: string }>, reply: string }
assert.deepEqual(merged.replies.map(reply => reply.messageId), ['first', 'second', 'media-only'])
assert.equal(merged.reply, 'first reply\n\nsecond reply')
const legacyFrames = mergeReplyFrames({ reply: 'legacy' }, [outcome.replies[0]])
assert.deepEqual(legacyFrames, { reply: 'legacy' })
assert.equal(mergeReplyFrames(partial, [outcome.replies[0]]), partial)
assert.deepEqual(publicContent([{ type: 'image', data: 'base64' }, { type: 'file', attachment: { name: 'x', bytes: 1 } }, { type: 'reasoning', text: 'hidden' }]), [])
const history = extractPublicEvents(events, 3, 100, 'remote-fixture')
assert.equal(history.some(event => event.type === 'assistant/attempt'), false)
assert.equal(history.some(event => event.messageId === 'partial' || event.messageId === 'reasoning'), false)
assert.equal(history.find(event => event.messageId === 'input')?.time, 103)
assert.equal((history.find(event => event.messageId === 'input')?.source as Record<string, unknown>).kind, 'dsh-remote')
assert.equal(history.find(event => event.messageId === 'media-only')?.step, 3)
assert.equal(extractPublicEvents(events, 3, 1, 'remote-fixture').length, 1)
assert.equal(JSON.stringify(history).includes('replayState'), false)
const rendered = renderRemoteReplies(outcome)
assert.ok(rendered.includes('remote reply 1/3 [assistant · fixture-provider/fixture-model]'))
assert.ok(rendered.includes('remote reply 2/3') && rendered.includes('remote reply 3/3'))
assert.ok(rendered.includes('remote image') && rendered.includes('remote file'))
assert.equal(renderRemoteReplies({ reply: 'legacy one' }), '--- legacy reply (message boundaries unavailable) ---\nlegacy one')
assert.equal(renderRemoteReplies({ replies: [], replyFormat: 'committed-assistant-v1' }), '--- committed remote replies: 0 ---')
const aborted = summarizeReplies([...events, { seq: 12, time: 112, type: 'turn/end', data: { turn: 1, reason: { kind: 'aborted', reason: { kind: 'user' } } } }], 1, 'remote-fixture')
assert.equal(aborted.interruptCause, 'user')
assert.deepEqual(aborted.replies.map(reply => reply.messageId), ['first', 'second', 'media-only'])
assert.deepEqual(summarizeReplies(events, 100, 'remote-fixture').replies, [])
console.log('ALL PASS: genuine ordered messages, metadata, durable media, filtered attempts/reasoning/interrupted, explicit legacy view')
