/** Inbound-only IO adapter contract: fake service, no DSH runtime, socket, model or peer. */
import assert from 'node:assert/strict'
import {
  INBOUND_TRANSPORT_ID,
  createInboundIoAdapter,
  inboundBindingId,
  inboundExternalId,
  inboundReplySource,
  inboundSenderId,
  inboundText,
} from '../src/remote-inbound.ts'
import type { InboundService } from '../src/remote-inbound.ts'
import type { RemoteReply } from '../src/reply-codec.ts'

const reply = {
  version: 1,
  sessionId: 'remote-session',
  seq: 7,
  time: 1_700_000_000_000,
  turn: 2,
  step: 3,
  messageId: 'remote-message-7',
  source: { kind: 'model', provider: 'fixture-provider', model: 'fixture-model' },
  provider: 'fixture-provider',
  model: 'fixture-model',
  content: [
    { type: 'text', text: 'one real remote reply' },
    { type: 'image', attachment: { attachmentId: 'remote-image', mediaType: 'image/png', bytes: 12, width: 2, height: 2 } },
  ],
  text: 'one real remote reply',
  attachmentScope: 'remote-session',
} as unknown as RemoteReply

assert.equal(inboundBindingId('peer-a', 'local-a'), inboundBindingId('peer-a', 'local-a'))
assert.notEqual(inboundBindingId('peer-a', 'local-a'), inboundBindingId('peer-b', 'local-a'))
const external = inboundExternalId('peer-a', 'remote-session', 'remote-message-7')
assert.equal(external, inboundExternalId('peer-a', 'remote-session', 'remote-message-7'))
assert.notEqual(external, inboundExternalId('peer-b', 'remote-session', 'remote-message-7'))
assert.notEqual(external, inboundExternalId('peer-a', 'remote-session', 'remote-message-8'))
assert.notEqual(inboundExternalId('peer-a', 's:x', 'm'), inboundExternalId('peer-a', 's', 'x:m'))
assert.ok(external.includes('peer-a') && external.includes('remote-session') && external.includes('remote-message-7'))
const longExternal = inboundExternalId('p'.repeat(200), 's'.repeat(200), 'm'.repeat(200))
assert.ok(longExternal.length <= 512 && longExternal.startsWith('dsh-remote:'))
const sender = inboundSenderId('peer-a', reply)
assert.ok(sender.includes('peer-a') && sender.includes('fixture-provider/fixture-model'))
const replySource = inboundReplySource('peer-a', reply)
assert.deepEqual(replySource, { actor: 'peer-a', provider: reply.provider, model: reply.model, sessionId: reply.sessionId, messageId: reply.messageId, seq: reply.seq, turn: reply.turn, step: reply.step })
const text = inboundText(reply)
for (const expected of ['one real remote reply', 'remote-image']) {
  assert.ok(text.includes(expected), expected)
}
assert.equal(text.includes('"type":"image"'), false)
assert.equal(text.includes('remote-message-7'), false)

const placed: Array<Record<string, unknown>> = []
const received: Array<Record<string, unknown>> = []
let enabled = true
const service: InboundService = {
  contractVersion: 1,
  async putBinding(binding) { placed.push(binding); return binding },
  async receive(input) {
    received.push(input)
    return {
      traceId: 'io-trace',
      bindingId: String(input.bindingId),
      sessionId: 'local-a',
      messageId: 'local-message',
      state: 'accepted',
      mode: 'queue',
      requestedMode: 'queue',
    }
  },
}
const ctx = { get: () => service }
const adapter = createInboundIoAdapter(ctx as never, { enabled: () => enabled, log: () => {} })
const binding = await adapter.ensureBinding('peer-a', 'local-a', 'remote-session')
assert.ok(binding !== undefined)
assert.equal(binding!.bindingId, inboundBindingId('peer-a', 'local-a'))
assert.equal(placed.length, 1)
assert.equal(placed[0]?.transport, INBOUND_TRANSPORT_ID)
assert.equal(placed[0]?.sessionId, 'local-a')
assert.equal(placed[0]?.enabled, true)
assert.equal(placed[0]?.sendEnabled, false)
assert.equal(placed[0]?.receiveOnly, true)
assert.equal(String(placed[0]?.endpoint).startsWith('dsh-remote-inbound:'), true)
assert.equal(String(placed[0]?.label).includes('peer-a'), true)
await adapter.ensureBinding('peer-a', 'local-a', 'remote-session')
assert.equal(placed.length, 1)
const outcome = await adapter.receive(binding!, {
  externalMessageId: external,
  senderId: sender,
  text,
  replySource,
})
assert.equal(outcome.kind, 'accepted')
assert.equal(received.length, 1)
assert.equal(received[0]?.mode, 'queue')
assert.equal(received[0]?.externalMessageId, external)
assert.equal(received[0]?.senderId, sender)
assert.deepEqual(received[0]?.replySource, replySource)
assert.deepEqual(received[0]?.content, [{ type: 'text', text }])
enabled = false
assert.equal(await adapter.ensureBinding('peer-a', 'local-a', 'remote-session'), undefined)
assert.equal((await adapter.receive(binding!, { externalMessageId: external, senderId: sender, text, replySource })).kind, 'unavailable')
adapter.dispose()
console.log('ALL PASS: inbound-only IO binding (sendEnabled=false), real producer/message metadata, media stays a remote reference, no transport registered')
