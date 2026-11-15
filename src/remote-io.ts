/**
 * Optional bridge between a controller-driven remote Session and
 * `super-agent-io` v1.
 *
 * The IO package is intentionally NOT a dependency: this module talks to the
 * public `ctx.superAgentIo` service structurally, and every failure degrades to
 * "no IO" so the ordinary dsh-remote input/output path keeps working. When the
 * service is present and enabled:
 *
 *  - controller input is admitted with `io.receive`, so the Session row carries
 *    IO's real external producer source instead of pretending to be a local
 *    human or a private replay entry;
 *  - every committed `assistant/message` IO routes is delivered through one
 *    `transport.deliver` call, i.e. one real message at a time, never a joined
 *    or sentence-split string.
 *
 * The bridge never creates or owns an Agent. It only binds to the scoped
 * Session dsh-remote has already created/resumed, which is why unload can drop
 * the transport without touching the Session.
 *
 * @module dsh-remote/remote-io
 */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/cordis-plugin-loader'
import { createHash } from 'node:crypto'
import { replyOf } from './reply-codec.ts'
import type { RemoteReply } from './reply-codec.ts'

/** The one transport id this plugin registers with the IO service. */
export const IO_TRANSPORT_ID = 'dsh-remote'
/** The public IO contract this adapter understands. */
export const IO_CONTRACT_VERSION = 1

export interface IoContentBlock {
  type: string
  text?: string
  attachment?: Record<string, unknown>
}

/** Public committed reply shape from super-agent-io's `index.d.ts`. */
export interface IoReply {
  version: 1
  sessionId: string
  seq: number
  messageId: string
  turn: number
  step: number
  time: number
  source: { kind: 'model'; provider: string; model: string; [key: string]: unknown }
  content: readonly IoContentBlock[]
  usage?: Record<string, number>
}

export interface IoDelivery {
  deliveryId: string
  bindingId: string
  endpoint: string
  reply: IoReply
  traceIds: string[]
  replyTo?: string
}

export interface IoReceipt {
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

export type IoTransportResult =
  | { state: 'delivered'; externalMessageId: string }
  | { state: 'failed'; reason: string }
  | { state: 'unknown'; reason: string }

export interface IoTransport {
  id: string
  deliver(
    delivery: Readonly<IoDelivery>,
    context: { signal: AbortSignal; idempotencyKey: string },
  ): Promise<IoTransportResult>
}

/** The subset of the frozen v1 service this adapter uses. */
export interface SuperAgentIoService {
  readonly contractVersion: 1
  registerTransport(transport: IoTransport): () => void
  putBinding(binding: Record<string, unknown>): Promise<unknown>
  receive(input: Record<string, unknown>): Promise<IoReceipt>
}

/** One scoped Session bound to the IO service for this process. */
export interface IoBinding {
  bindingId: string
  principal: string
  localId: string
  wireId: string
}

export type ReplyDelivery = 'delivered' | 'failed' | 'unknown'

export interface RemoteIoHooks {
  /** Read live, so turning the integration off takes effect on the next call. */
  enabled(): boolean
  log(message: string, level?: 'info' | 'warn' | 'debug'): void
  /** Hand one converted real assistant message to the waiting controller(s). */
  deliver(binding: IoBinding, delivery: Readonly<IoDelivery>, reply: RemoteReply): Promise<ReplyDelivery>
}

export type IoReceiveOutcome =
  | { kind: 'accepted'; receipt: IoReceipt }
  | { kind: 'unavailable'; reason: string }
  | { kind: 'unknown'; reason: string }

export interface IoReceiveRequest {
  text: string
  mode: 'queue' | 'steer' | 'auto'
  externalMessageId: string
}

export interface RemoteIoBridge {
  /** Register the transport now when the service is available. */
  sync(): SuperAgentIoService | undefined
  /** Resolve the service, register the transport and (re)write one stable binding. */
  ensureBinding(principal: string, localId: string, wireId: string, label: string): Promise<IoBinding | undefined>
  /** Admit one text input. `unavailable` means IO definitely did not admit it. */
  receive(binding: IoBinding, request: IoReceiveRequest): Promise<IoReceiveOutcome>
  /** Whether the service resolved on the last sync. */
  available(): boolean
  dispose(): void
}

/** Stable binding identity: a reused id always names the same principal + Session. */
export function ioBindingId(principal: string, localId: string): string {
  return `dsh-remote-${createHash('sha256').update(JSON.stringify([principal, localId])).digest('hex').slice(0, 40)}`
}

/** Convert one IO reply to the same public shape dsh-remote already transports. */
export function remoteReplyOf(value: unknown): RemoteReply | undefined {
  const reply = value as Partial<IoReply> | null
  if (reply === null || typeof reply !== 'object' || reply.version !== 1
    || typeof reply.sessionId !== 'string' || reply.sessionId === '') return undefined
  return replyOf({
    type: 'assistant/message',
    seq: Number(reply.seq),
    time: Number(reply.time),
    data: {
      turn: reply.turn,
      step: reply.step,
      message: {
        id: reply.messageId,
        role: 'assistant',
        source: reply.source,
        content: reply.content,
      },
      ...(reply.usage === undefined ? {} : { usage: reply.usage }),
    },
  }, reply.sessionId)
}

const errorCode = (error: unknown): string => {
  const code = (error as { code?: unknown } | null)?.code
  return typeof code === 'string' ? code : ''
}
const errorMessage = (error: unknown): string => error instanceof Error ? error.message : String(error)

/** Codes that prove `receive` refused BEFORE any native send; only these may fall back. */
const FALLBACK_RECEIVE_CODES = new Set(['DISABLED', 'BINDING_NOT_FOUND', 'INVALID_CONTENT', 'CONTENT_TOO_LARGE', 'INVALID_INPUT'])

/**
 * Create the optional adapter. Construction is side-effect free apart from a
 * best-effort transport registration when both the switch and the service are
 * already available; every entry point calls `sync()` again so a service that
 * appears later is picked up without remounting this plugin.
 */
export function createRemoteIoBridge(ctx: Context, hooks: RemoteIoHooks): RemoteIoBridge {
  let closed = false
  let service: SuperAgentIoService | undefined
  let dropTransport: (() => void) | undefined
  let offVolatile: (() => void) | undefined
  const bindings = new Map<string, IoBinding>()
  const byBinding = new Map<string, IoBinding>()
  const initialized = new Set<string>()

  const resolve = (): SuperAgentIoService | undefined => {
    if (closed || !hooks.enabled()) return undefined
    let candidate: Partial<SuperAgentIoService> | undefined
    try {
      candidate = (ctx as unknown as { get(key: string): unknown }).get('superAgentIo') as Partial<SuperAgentIoService> | undefined
    } catch {
      return undefined
    }
    if (candidate == null || candidate.contractVersion !== IO_CONTRACT_VERSION
      || typeof candidate.registerTransport !== 'function'
      || typeof candidate.putBinding !== 'function'
      || typeof candidate.receive !== 'function') return undefined
    return candidate as SuperAgentIoService
  }

  const sync = (): SuperAgentIoService | undefined => {
    if (closed || !hooks.enabled()) {
      try { dropTransport?.() } catch { /* already gone */ }
      dropTransport = undefined
      service = undefined
      return undefined
    }
    const current = resolve()
    if (current === undefined) {
      try { dropTransport?.() } catch { /* already gone */ }
      dropTransport = undefined
      service = undefined
      return undefined
    }
    if (service === current && dropTransport !== undefined) return current
    // A replaced service must not leave the old transport registered under the
    // same id: unregister first, then register against the new owner.
    try { dropTransport?.() } catch { /* already gone */ }
    dropTransport = undefined
    service = current
    initialized.clear()
    try {
      dropTransport = current.registerTransport({
        id: IO_TRANSPORT_ID,
        deliver: async (delivery, { signal }) => {
          if (closed || !hooks.enabled()) return { state: 'unknown', reason: 'DSH_REMOTE_DISABLED' }
          if (signal.aborted) return { state: 'unknown', reason: 'DSH_REMOTE_ABORTED' }
          const binding = byBinding.get(delivery.bindingId)
          if (binding === undefined) return { state: 'unknown', reason: 'DSH_REMOTE_UNKNOWN_BINDING' }
          const reply = remoteReplyOf(delivery.reply)
          if (reply === undefined) return { state: 'failed', reason: 'DSH_REMOTE_INVALID_REPLY' }
          let result: ReplyDelivery
          try {
            result = await hooks.deliver(binding, delivery, reply)
          } catch (error) {
            hooks.log(`dsh-remote-server: super-agent-io reply delivery failed (${errorMessage(error)})`, 'warn')
            result = 'unknown'
          }
          if (result === 'delivered') {
            return { state: 'delivered', externalMessageId: `dsh-remote:${delivery.deliveryId}` }
          }
          return {
            state: result,
            reason: result === 'failed' ? 'DSH_REMOTE_NO_CONTROLLER' : 'DSH_REMOTE_SEND_OUTCOME_UNKNOWN',
          }
        },
      })
      hooks.log('dsh-remote-server: super-agent-io transport registered')
    } catch (error) {
      // Duplicate/invalid registration is an unavailable output channel, not a
      // reason to make the ordinary remote tools disappear.
      dropTransport = undefined
      hooks.log(`dsh-remote-server: super-agent-io transport unavailable (${errorMessage(error)})`, 'warn')
    }
    return current
  }

  const ensureBinding = async (
    principal: string,
    localId: string,
    wireId: string,
    label: string,
  ): Promise<IoBinding | undefined> => {
    const io = sync()
    if (io === undefined) return undefined
    const bindingId = ioBindingId(principal, localId)
    let binding = bindings.get(localId)
    if (binding === undefined || binding.bindingId !== bindingId) {
      binding = { bindingId, principal, localId, wireId }
      bindings.set(localId, binding)
      byBinding.set(bindingId, binding)
    }
    if (initialized.has(bindingId)) return binding
    try {
      await io.putBinding({
        id: bindingId,
        transport: IO_TRANSPORT_ID,
        // Stable, principal-scoped and non-secret: the adapter's own identity.
        endpoint: `dsh-remote:${principal}`,
        sessionId: localId,
        label: label.slice(0, 160),
        enabled: true,
        // Output is still gated by IO's global send switch and this binding's
        // sendEnabled flag; asking for it does not bypass either gate.
        sendEnabled: true,
        preload: false,
        mode: 'auto',
        routing: 'exclusive-turn',
      })
      if (closed) {
        // The plugin unloaded while the sidecar write was in flight; never hand
        // this binding to a caller that could still admit input.
        if (byBinding.get(bindingId) === binding) byBinding.delete(bindingId)
        if (bindings.get(localId) === binding) bindings.delete(localId)
        return undefined
      }
      initialized.add(bindingId)
      return binding
    } catch (error) {
      // No binding, so no IO admission and no routed output for this Session.
      // The caller falls back to the original dsh-remote path.
      if (byBinding.get(bindingId) === binding) byBinding.delete(bindingId)
      if (bindings.get(localId) === binding) bindings.delete(localId)
      hooks.log(`dsh-remote-server: super-agent-io binding unavailable (${errorMessage(error)})`, 'warn')
      return undefined
    }
  }

  const receive = async (binding: IoBinding, request: IoReceiveRequest): Promise<IoReceiveOutcome> => {
    const io = sync()
    if (io === undefined) return { kind: 'unavailable', reason: 'super-agent-io service is unavailable' }
    if (request.text.trim() === '') return { kind: 'unavailable', reason: 'empty input cannot be admitted through IO' }
    const input = {
      bindingId: binding.bindingId,
      externalMessageId: request.externalMessageId,
      content: [{ type: 'text', text: request.text }],
      mode: request.mode,
      senderId: binding.principal,
    }
    try {
      const receipt = await io.receive(input)
      if (receipt.state === 'accepted') return { kind: 'accepted', receipt }
      if (receipt.state === 'failed') {
        // IO's `failed` is set only before a native send attempt, so the caller
        // may still use the ordinary admission path.
        return { kind: 'unavailable', reason: receipt.reason ?? 'IO admission failed before send' }
      }
      // `unknown`, `cancelled`, `pending`/`admitting` (which receive should not
      // return) all mean a retry/direct injection could duplicate input.
      return { kind: 'unknown', reason: receipt.reason ?? `IO admission ended as ${receipt.state}` }
    } catch (error) {
      const code = errorCode(error)
      if (code === 'BINDING_NOT_FOUND') {
        // The sidecar was recreated under us; re-put the stable binding once.
        initialized.delete(binding.bindingId)
        const refreshed = await ensureBinding(binding.principal, binding.localId, binding.wireId, `dsh-remote ${binding.wireId}`)
        if (refreshed !== undefined) {
          try {
            const receipt = await io.receive(input)
            if (receipt.state === 'accepted') return { kind: 'accepted', receipt }
            if (receipt.state === 'failed') return { kind: 'unavailable', reason: receipt.reason ?? 'IO admission failed before send' }
            return { kind: 'unknown', reason: receipt.reason ?? `IO admission ended as ${receipt.state}` }
          } catch (retryError) {
            return FALLBACK_RECEIVE_CODES.has(errorCode(retryError))
              ? { kind: 'unavailable', reason: errorMessage(retryError) }
              : { kind: 'unknown', reason: errorMessage(retryError) }
          }
        }
      }
      if (FALLBACK_RECEIVE_CODES.has(code)) return { kind: 'unavailable', reason: errorMessage(error) }
      return { kind: 'unknown', reason: errorMessage(error) }
    }
  }

  try {
    offVolatile = ctx.on('loader/volatile-update', () => { sync() }) as unknown as () => void
  } catch {
    // A hot-reload context may be inactive; sync() still runs on every call.
  }
  sync()

  return {
    sync,
    ensureBinding,
    receive,
    available: () => sync() !== undefined,
    dispose: () => {
      closed = true
      try { offVolatile?.() } catch { /* already disposed */ }
      offVolatile = undefined
      try { dropTransport?.() } catch { /* already disposed */ }
      dropTransport = undefined
      service = undefined
      bindings.clear()
      byBinding.clear()
      initialized.clear()
    },
  }
}
