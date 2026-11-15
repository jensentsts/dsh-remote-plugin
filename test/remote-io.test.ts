/** Optional IO adapter contract only: fake service, no DSH runtime, socket, model or peer. */
import assert from 'node:assert/strict'
import { createRemoteIoBridge, ioBindingId, remoteReplyOf } from '../src/remote-io.ts'
import type { IoDelivery, IoReply, IoTransport, SuperAgentIoService } from '../src/remote-io.ts'

const ioReply: IoReply = {
  version: 1,
  sessionId: 'remote-session',
  seq: 7,
  messageId: 'assistant-message-7',
  turn: 2,
  step: 3,
  time: 1_700_000_000_000,
  source: { kind: 'model', provider: 'fixture-provider', model: 'fixture-model', replayState: { hidden: true } },
  content: [{ type: 'text', text: 'one real committed reply' }],
  usage: { inputTokens: 3, outputTokens: 5 },
}
const converted = remoteReplyOf(ioReply)
assert.ok(converted !== undefined)
assert.equal(converted.messageId, 'assistant-message-7')
assert.equal(converted.seq, 7)
assert.equal(converted.source.provider, 'fixture-provider')
assert.equal(converted.source.model, 'fixture-model')
assert.equal(converted.text, 'one real committed reply')
assert.equal(converted.attachmentScope, 'remote-session')
assert.deepEqual(converted.usage, { inputTokens: 3, outputTokens: 5 })
assert.equal(JSON.stringify(converted).includes('replayState'), false)
assert.equal(remoteReplyOf({ ...ioReply, source: { kind: 'user', provider: 'p', model: 'm' } }), undefined)
assert.equal(remoteReplyOf({ ...ioReply, time: Number.NaN }), undefined)
assert.equal(remoteReplyOf({ ...ioReply, content: [{ type: 'reasoning', text: 'private' }] }), undefined)

const registered: IoTransport[] = []
const bindings: Array<Record<string, unknown>> = []
const received: Array<Record<string, unknown>> = []
let removed = false
const service: SuperAgentIoService = {
  contractVersion: 1,
  registerTransport(transport) {
    registered.push(transport)
    return () => { removed = true }
  },
  async putBinding(binding) { bindings.push(binding); return binding },
  async receive(input) {
    received.push(input)
    return {
      traceId: 'io-trace', bindingId: String(input.bindingId), sessionId: 'local-session',
      messageId: 'io-message', state: 'accepted', mode: 'queue', requestedMode: 'queue',
    }
  },
}
const ctx = { get: () => service, on: () => () => {} }
const delivered: Array<{ bindingId: string, deliveryId: string, text: string }> = []
let enabled = true
const bridge = createRemoteIoBridge(ctx as never, {
  enabled: () => enabled,
  log: () => {},
  async deliver(binding, delivery, reply) {
    delivered.push({ bindingId: binding.bindingId, deliveryId: delivery.deliveryId, text: reply.text })
    return 'delivered'
  },
})
assert.equal(registered.length, 1)
assert.equal(registered[0]?.id, 'dsh-remote')
const binding = await bridge.ensureBinding('principal', 'local-session', 'wire-session', 'label')
assert.ok(binding !== undefined)
assert.equal(binding!.bindingId, ioBindingId('principal', 'local-session'))
assert.equal(bindings.length, 1)
assert.equal(bindings[0]?.sessionId, 'local-session')
assert.equal(bindings[0]?.transport, 'dsh-remote')
assert.equal(String(bindings[0]?.endpoint).startsWith('dsh-remote:'), true)
// A second ensure reuses the process cache instead of appending another binding.
await bridge.ensureBinding('principal', 'local-session', 'wire-session', 'label')
assert.equal(bindings.length, 1)
const admitted = await bridge.receive(binding!, { text: 'hello', mode: 'auto', externalMessageId: 'external-1' })
assert.equal(admitted.kind, 'accepted')
assert.equal(received[0]?.externalMessageId, 'external-1')
assert.deepEqual(received[0]?.content, [{ type: 'text', text: 'hello' }])
assert.equal(received[0]?.senderId, 'principal')
const delivery: IoDelivery = {
  deliveryId: 'delivery-1', bindingId: binding!.bindingId, endpoint: String(bindings[0]?.endpoint),
  reply: ioReply, traceIds: ['io-trace'], replyTo: 'external-1',
}
const transport = registered[0] as IoTransport
const result = await transport.deliver(delivery, { signal: new AbortController().signal, idempotencyKey: 'delivery-1' })
assert.deepEqual(result, { state: 'delivered', externalMessageId: 'dsh-remote:delivery-1' })
assert.equal(delivered[0]?.bindingId, binding!.bindingId)
assert.equal(delivered[0]?.text, 'one real committed reply')
// Disabling the live switch removes the transport; the caller then sees IO as unavailable.
enabled = false
bridge.sync()
assert.equal(removed, true)
const unavailable = await bridge.receive(binding, { text: 'later', mode: 'queue', externalMessageId: 'external-2' })
assert.equal(unavailable.kind, 'unavailable')
assert.equal(received.length, 1)
bridge.dispose()
console.log('ALL PASS: optional IO transport, stable binding, real source/reply conversion, no replay on unavailable')
