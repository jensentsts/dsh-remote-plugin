/** Versioned transport facts. Session messages remain the only model-history authority. */
import { createHash } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-storage-domain'
import type { Domain, DomainSpec, KvTable } from '@deepseek-ai/dsh-storage-domain'
import type { RemoteInputMode } from './agent-delivery.ts'

export interface MessageTrace {
  version: 1
  traceId: string
  principal: string
  sessionId: string
  remoteSessionId: string
  messageId: string
  seq: number | null
  time: number
  operation: 'agent.prompt' | 'agent.note'
  requestedMode: RemoteInputMode
  mode: 'queue' | 'steer'
  state: 'admitting' | 'accepted' | 'committed' | 'unknown'
}

export interface TraceStore {
  get(key: string): MessageTrace | undefined
  put(key: string, trace: MessageTrace): Promise<void>
}

/** Keys carry full identity; the digest prevents path-valued record names in per-record backends. */
export function traceKey(trace: Pick<MessageTrace, 'principal' | 'sessionId' | 'messageId'>): string {
  return createHash('sha256').update(JSON.stringify([trace.principal, trace.sessionId, trace.messageId])).digest('hex')
}

/** Persist admission intent before waking an Agent. An ambiguous wake is never replayed automatically. */
export async function admitTracked(store: TraceStore, trace: MessageTrace, admit: () => void): Promise<MessageTrace> {
  const key = traceKey(trace)
  const previous = store.get(key)
  if (previous !== undefined) throw new Error(`dsh-remote: message ${trace.messageId} already has an admission record (${previous.state}); not replaying`)
  await store.put(key, { ...trace, state: 'admitting' })
  try { admit() } catch (error) {
    // An inbox method may throw after publication; do not assert that nothing happened.
    await store.put(key, { ...trace, state: 'unknown' })
    throw error
  }
  const accepted = { ...trace, state: 'accepted' as const }
  try { await store.put(key, accepted) } catch (error) {
    throw new Error(`dsh-remote: input may have been admitted but its receipt could not be stored; do not resend (${String(error)})`)
  }
  return accepted
}

/** One server plugin owns its domain and close operation. Missing storage fails before input admission. */
export function createMessageTraces(ctx: Context): {
  store(): Promise<TraceStore>
  anchor(principal: string, sessionId: string, messageId: string, seq: number, time: number): Promise<boolean>
  close(): Promise<void>
} {
  let opening: Promise<Domain<DomainSpec>> | undefined
  let closed = false
  let writes: Promise<void> = Promise.resolve()
  const persist = (records: KvTable<string, MessageTrace>, key: string, value: MessageTrace): Promise<void> => {
    const writing = writes.then(async () => {
      const current = records.get(key)
      // A synchronous inbox publication can race the accepted receipt. Never
      // replace an observed committed anchor with a later unanchored receipt.
      await records.put(key, current?.state === 'committed' && value.state !== 'committed'
        ? { ...value, seq: current.seq, time: current.time, state: 'committed' } : value)
    })
    writes = writing.catch(() => { /* caller receives the write failure; later records may still drain */ })
    return writing
  }
  const table = async (): Promise<KvTable<string, MessageTrace>> => {
    if (closed) throw new Error('dsh-remote: message trace domain is closed')
    opening ??= (async () => {
      const facility = ctx.get('storageDomain')
      if (facility === undefined) throw new Error('dsh-remote: storageDomain is required before admitting remote input')
      const { z } = await import('zod')
      const id = z.string().min(1)
      const schema = z.object({
        version: z.literal(1), traceId: id, principal: id, sessionId: id, remoteSessionId: id, messageId: id,
        seq: z.number().int().nonnegative().nullable(), time: z.number().nonnegative(),
        operation: z.enum(['agent.prompt', 'agent.note']), requestedMode: z.enum(['queue', 'steer', 'auto']),
        mode: z.enum(['queue', 'steer']), state: z.enum(['admitting', 'accepted', 'committed', 'unknown']),
      }).strict()
      return facility.open({ name: 'dsh_remote_message_traces', version: 1, layout: 'per-record', tables: { traces: { valueSchema: schema } } })
    })()
    const attempt = opening
    try { return (await attempt).table('traces') as KvTable<string, MessageTrace> } catch (error) {
      // A later explicit input may retry opening storage; this never replays a wake.
      if (opening === attempt) opening = undefined
      throw error
    }
  }
  return {
    store: async () => {
      const records = await table()
      return { get: key => records.get(key), put: (key, value) => persist(records, key, value) }
    },
    anchor: async (principal, sessionId, messageId, seq, time) => {
      const records = await table()
      const key = traceKey({ principal, sessionId, messageId })
      const previous = records.get(key)
      if (previous === undefined) return false
      await persist(records, key, { ...previous, seq, time, state: 'committed' })
      return true
    },
    close: async () => { closed = true; await writes; if (opening !== undefined) await (await opening).close() },
  }
}
