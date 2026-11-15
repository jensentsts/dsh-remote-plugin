/**
 * Optional client-side ingress for replies that arrive outside a foreground
 * RPC.
 *
 * The server half can route every committed assistant message one-by-one over
 * `super-agent-io`. A foreground `agent.prompt` consumes those frames into its
 * own `replies` result, so they must NOT also be injected. An asynchronous turn
 * (typically the output of `agent.note`) has no RPC to return to; this adapter
 * puts its real, explicitly-labelled message into the local Session that memory
 * already maps to that remote conversation, using IO's public `receive`.
 *
 * The injected row is a `super-agent-io` user-role external input, not a fake
 * assistant/message/turn-end. `sendEnabled` is deliberately false: the local
 * agent may react, but its output is never routed back into the remote peer, so
 * no automatic ping-pong loop is created. The IO package remains optional and
 * is resolved structurally through `ctx.superAgentIo`.
 *
 * @module dsh-remote/remote-inbound
 */
import type { Context } from '@deepseek-ai/cordis'
import { createHash } from 'node:crypto'
import type { RemoteReply } from './reply-codec.ts'

/** The transport id recorded on inbound-only bindings. No transport is registered. */
export const INBOUND_TRANSPORT_ID = 'dsh-remote-inbound'

export interface InboundReceipt {
  traceId: string
  bindingId: string
  sessionId: string
  messageId: string
  state: 'pending' | 'admitting' | 'accepted' | 'failed' | 'unknown' | 'cancelled'
  mode: 'queue' | 'steer'
  requestedMode: 'queue' | 'steer' | 'auto'
  duplicate?: boolean
  acceptedSeq?: number
  messageCommitted?: boolean
  durable?: boolean
  reason?: string
}

/** The subset of the frozen IO v1 service used for inbound admission. */
export interface InboundService {
  readonly contractVersion: 1
  putBinding(binding: Record<string, unknown>): Promise<unknown>
  receive(input: Record<string, unknown>): Promise<InboundReceipt>
}

export interface InboundBinding {
  bindingId: string
  peer: string
  localSession: string
  remoteSession: string
}

export type InboundOutcome =
  | { kind: 'accepted'; receipt: InboundReceipt }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'unknown'; reason: string }

export interface InboundRequest {
  externalMessageId: string
  senderId: string
  text: string
  replySource: InboundReplySource
}

type InboundReplySource = Pick<RemoteReply, 'provider' | 'model' | 'sessionId' | 'messageId' | 'seq' | 'turn' | 'step'> & { actor: string }

export interface InboundHooks {
  enabled(): boolean
  log(message: string, level?: 'info' | 'warn' | 'debug'): void
}

export interface InboundIoAdapter {
  ensureBinding(peer: string, localSession: string, remoteSession: string): Promise<InboundBinding | undefined>
  receive(binding: InboundBinding, request: InboundRequest): Promise<InboundOutcome>
  dispose(): void
}

const errorCode = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code
  return typeof code === 'string' ? code : ''
}
const errorMessage = (error: unknown): string => error instanceof Error ? error.message : String(error)
const bounded = (raw: string): string => raw.length <= 512
  ? raw
  : `dsh-remote:${createHash('sha256').update(raw).digest('hex').slice(0, 64)}`

/** Stable per peer+local-Session binding; changing either gets a new id. */
export function inboundBindingId(peer: string, localSession: string): string {
  return `dsh-remote-inbound-${createHash('sha256').update(JSON.stringify([peer, localSession])).digest('hex').slice(0, 40)}`
}

/** Stable external identity for IO dedupe; real peer/session/message ids when bounded. */
export function inboundExternalId(peer: string, remoteSession: string, messageId: string): string {
  return bounded(`dsh-remote:${JSON.stringify([peer, remoteSession, messageId])}`)
}

/** Preserve the real peer/model producer in IO's `senderId`, bounded for the wire. */
export function inboundSenderId(peer: string, reply: RemoteReply): string {
  return bounded(`dsh-remote:${peer}:${reply.provider}/${reply.model}`)
}

/**
 * One honest text projection of a remote committed reply.
 *
 * Media is never submitted as an attachment: its durable reference belongs to
 * the remote Session, so it stays visible as a labelled remote reference.
 * Producer identity travels in the structured source, outside the text.
 */
export function inboundText(reply: RemoteReply): string {
  return reply.content.map(block => block.type === 'text' ? block.text
    : `\n[remote ${block.type}: ${block.attachment.name ?? block.type} · ${block.attachment.attachmentId}]\n`).join('')
}

/** The real reply's producer and coordinates, carried separately from text. */
export function inboundReplySource(actor: string, reply: RemoteReply): InboundReplySource {
  const { provider, model, sessionId, messageId, seq, turn, step } = reply
  return { actor, provider, model, sessionId, messageId, seq, turn, step }
}

/** Codes that prove IO refused before admission; a duplicate frame may safely retry. */
const RETRYABLE_INBOUND_CODES = new Set(['DISABLED', 'BINDING_NOT_FOUND', 'INVALID_CONTENT', 'CONTENT_TOO_LARGE', 'INVALID_INPUT'])

/**
 * Create the inbound-only adapter.
 *
 * It never registers a transport: with `sendEnabled:false` there is nothing to
 * deliver back to the remote, and the ordinary dsh-remote tools keep their own
 * transport. All state is dropped on `dispose`.
 */
export function createInboundIoAdapter(ctx: Context, hooks: InboundHooks): InboundIoAdapter {
  let closed = false
  let service: InboundService | undefined
  const bindings = new Map<string, InboundBinding>()
  const initialized = new Set<string>()

  const resolve = (): InboundService | undefined => {
    if (closed || !hooks.enabled()) return undefined
    let candidate: Partial<InboundService> | undefined
    try {
      candidate = (ctx as unknown as { get(key: string): unknown }).get('superAgentIo') as Partial<InboundService> | undefined
    } catch {
      return undefined
    }
    if (candidate == null || candidate.contractVersion !== 1
      || typeof candidate.putBinding !== 'function'
      || typeof candidate.receive !== 'function') return undefined
    return candidate as InboundService
  }

  const sync = (): InboundService | undefined => {
    const current = resolve()
    if (current !== service) initialized.clear()
    service = current
    return current
  }

  const keyOf = (peer: string, localSession: string): string => `${peer}\0${localSession}`

  const ensureBinding = async (
    peer: string,
    localSession: string,
    remoteSession: string,
  ): Promise<InboundBinding | undefined> => {
    const io = sync()
    if (io === undefined) return undefined
    const bindingId = inboundBindingId(peer, localSession)
    const key = keyOf(peer, localSession)
    let binding = bindings.get(key)
    if (binding === undefined || binding.bindingId !== bindingId) {
      binding = { bindingId, peer, localSession, remoteSession }
      bindings.set(key, binding)
    }
    if (initialized.has(bindingId)) return binding
    try {
      await io.putBinding({
        id: bindingId,
        transport: INBOUND_TRANSPORT_ID,
        endpoint: `dsh-remote-inbound:${peer}`,
        sessionId: localSession,
        label: `dsh-remote inbound ${peer} ${remoteSession}`.slice(0, 160),
        enabled: true,
        // This is an INBOUND-only binding: local assistant output must never be
        // routed back to the remote peer automatically.
        sendEnabled: false,
        receiveOnly: true,
        preload: false,
        mode: 'queue',
        routing: 'exclusive-turn',
      })
      if (closed) {
        if (bindings.get(key) === binding) bindings.delete(key)
        return undefined
      }
      initialized.add(bindingId)
      return binding
    } catch (error) {
      if (bindings.get(key) === binding) bindings.delete(key)
      hooks.log(`dsh-remote-client: inbound IO binding unavailable (${errorMessage(error)})`, 'warn')
      return undefined
    }
  }

  const receive = async (binding: InboundBinding, request: InboundRequest): Promise<InboundOutcome> => {
    const io = sync()
    if (io === undefined) return { kind: 'unavailable', reason: 'super-agent-io service is unavailable' }
    if (request.text.trim() === '') return { kind: 'unavailable', reason: 'empty inbound text' }
    const input = {
      bindingId: binding.bindingId,
      externalMessageId: request.externalMessageId,
      content: [{ type: 'text', text: request.text }],
      mode: 'queue',
      senderId: request.senderId,
      replySource: request.replySource,
    }
    try {
      const receipt = await io.receive(input)
      if (receipt.state === 'accepted') return { kind: 'accepted', receipt }
      if (receipt.state === 'failed') return { kind: 'unavailable', reason: receipt.reason ?? 'inbound admission failed before send' }
      return { kind: 'unknown', reason: receipt.reason ?? `inbound admission ended as ${receipt.state}` }
    } catch (error) {
      const code = errorCode(error)
      if (code === 'BINDING_NOT_FOUND') {
        initialized.delete(binding.bindingId)
        const refreshed = await ensureBinding(binding.peer, binding.localSession, binding.remoteSession)
        const retryIo = refreshed === undefined ? undefined : sync()
        if (retryIo !== undefined) {
          try {
            const receipt = await retryIo.receive(input)
            if (receipt.state === 'accepted') return { kind: 'accepted', receipt }
            if (receipt.state === 'failed') return { kind: 'unavailable', reason: receipt.reason ?? 'inbound admission failed before send' }
            return { kind: 'unknown', reason: receipt.reason ?? `inbound admission ended as ${receipt.state}` }
          } catch (retryError) {
            return RETRYABLE_INBOUND_CODES.has(errorCode(retryError))
              ? { kind: 'unavailable', reason: errorMessage(retryError) }
              : { kind: 'unknown', reason: errorMessage(retryError) }
          }
        }
      }
      return RETRYABLE_INBOUND_CODES.has(code)
        ? { kind: 'unavailable', reason: errorMessage(error) }
        : { kind: 'unknown', reason: errorMessage(error) }
    }
  }

  return {
    ensureBinding,
    receive,
    dispose: () => {
      closed = true
      service = undefined
      bindings.clear()
      initialized.clear()
    },
  }
}
