/** Public remote replies copied from committed Session messages, never from streams or attempts. */
import type { FileBlock, ImageBlock, TextBlock } from '@deepseek-ai/dsh-llm'

export type RemotePublicContent = TextBlock | ImageBlock | FileBlock
export type ReplyFormat = 'committed-assistant-v1' | 'legacy-text' | 'invalid-replies'

/** Attachment ids belong to the remote Session's store, not the receiver's local store. */
export interface RemoteReply {
  version: 1
  sessionId: string
  seq: number
  time: number
  turn: number
  step: number
  messageId: string
  source: { kind: 'model', provider: string, model: string }
  provider: string
  model: string
  content: RemotePublicContent[]
  text: string
  attachmentScope: 'remote-session'
  usage?: Record<string, number>
}

/** Minimal untrusted event fields accepted at tests and wire boundaries. */
export interface ReplyEvent {
  type: string
  seq: number
  time?: number
  data: unknown
}

export interface ReplySummary {
  text: string
  replies: RemoteReply[]
  replyFormat: 'committed-assistant-v1'
  reason: string | null
  error: string | null
  interruptCause: string | null
}

const record = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined
const natural = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
const nonempty = (value: unknown): value is string => typeof value === 'string' && value !== ''

/** Copy only text and durable image/file references; never leak encoded bytes or adapter state. */
export function publicContent(value: unknown): RemotePublicContent[] {
  if (!Array.isArray(value)) return []
  const out: RemotePublicContent[] = []
  for (const raw of value) {
    const block = record(raw)
    if (block?.type === 'text' && typeof block.text === 'string') {
      if (block.text !== '') out.push({ type: 'text', text: block.text })
      continue
    }
    const ref = record(block?.attachment)
    if (ref === undefined || !nonempty(ref.attachmentId) || !natural(ref.bytes)) continue
    if (block?.type === 'file' && typeof ref.name === 'string') {
      out.push({ type: 'file', attachment: { attachmentId: ref.attachmentId as FileBlock['attachment']['attachmentId'], name: ref.name, bytes: ref.bytes } })
    } else if (block?.type === 'image' && ['image/png', 'image/jpeg', 'image/webp', 'image/gif'].includes(String(ref.mediaType))
      && natural(ref.width) && ref.width > 0 && natural(ref.height) && ref.height > 0) {
      const original = record(ref.originalDimensions)
      out.push({ type: 'image', attachment: {
        attachmentId: ref.attachmentId as ImageBlock['attachment']['attachmentId'], mediaType: ref.mediaType as ImageBlock['attachment']['mediaType'],
        bytes: ref.bytes, width: ref.width, height: ref.height,
        ...(typeof ref.name === 'string' ? { name: ref.name } : {}),
        ...(original !== undefined && natural(original.width) && original.width > 0 && natural(original.height) && original.height > 0
          ? { originalDimensions: { width: original.width, height: original.height } } : {}),
      } })
    }
  }
  return out
}

/** Concatenate text blocks of one message without inventing additional messages. */
export function contentText(content: readonly RemotePublicContent[]): string {
  return content.filter((block): block is TextBlock => block.type === 'text').map(block => block.text).join('')
}

/** Narrow one committed assistant event; partial/interrupted and non-model messages are not replies. */
export function replyOf(event: ReplyEvent, sessionId: string): RemoteReply | undefined {
  if (event.type !== 'assistant/message' || !natural(event.seq) || !natural(event.time)) return undefined
  const data = record(event.data)
  const message = record(data?.message)
  const source = record(message?.source)
  if (data?.interrupted === true || message?.role !== 'assistant' || !nonempty(message.id)
    || source?.kind !== 'model' || !nonempty(source.provider) || !nonempty(source.model)
    || !natural(data?.turn) || !natural(data?.step)) return undefined
  const content = publicContent(message.content)
  if (content.length === 0) return undefined
  const usage = record(data.usage)
  const tokens = usage === undefined ? undefined : Object.fromEntries(Object.entries(usage)
    .filter(([key, value]) => ['inputTokens', 'outputTokens', 'totalTokens', 'cacheReadTokens', 'cacheWriteTokens', 'reasoningTokens'].includes(key) && natural(value))) as Record<string, number>
  return {
    version: 1, sessionId, seq: event.seq, time: event.time, turn: data.turn, step: data.step, messageId: message.id,
    source: { kind: 'model', provider: source.provider, model: source.model }, provider: source.provider, model: source.model,
    content, text: contentText(content), attachmentScope: 'remote-session',
    ...(tokens === undefined || Object.keys(tokens).length === 0 ? {} : { usage: tokens }),
  }
}

/** Preserve every genuine public message in Session order; legacy text is their complete join. */
export function summarizeReplies(events: readonly ReplyEvent[], firstSeq: number, sessionId: string): ReplySummary {
  let started = false
  const replies: RemoteReply[] = []
  let reason: string | null = null
  let error: string | null = null
  let interruptCause: string | null = null
  for (const event of events) {
    if (event.seq < firstSeq) continue
    if (event.type === 'turn/start') { started = true; continue }
    if (!started) continue
    const reply = replyOf(event, sessionId)
    if (reply !== undefined) replies.push(reply)
    if (event.type !== 'turn/end') continue
    const why = record(record(event.data)?.reason)
    reason = typeof why?.kind === 'string' ? why.kind : null
    interruptCause = why?.kind === 'aborted' ? String(record(why.reason)?.kind ?? 'legacy') : null
    const failure = record(why?.error)
    if (failure !== undefined) error = `${String(failure.code ?? '')}: ${String(failure.message ?? '')}`.replace(/^: /, '')
  }
  return { text: replies.map(reply => reply.text).filter(Boolean).join('\n\n'), replies, replyFormat: 'committed-assistant-v1', reason, error, interruptCause }
}

/** Parse optional upgraded wire replies. Missing arrays remain legacy text, never synthesized identities. */
export function replyFields(value: unknown): { replies?: RemoteReply[], replyFormat: ReplyFormat } {
  const envelope = record(value)
  if (!Array.isArray(envelope?.replies)) return { replyFormat: 'legacy-text' }
  if (envelope.replyFormat !== 'committed-assistant-v1') return { replyFormat: 'invalid-replies' }
  const replies: RemoteReply[] = []
  let previous = -1
  const ids = new Set<string>()
  for (const raw of envelope.replies) {
    const row = record(raw)
    if (row?.version !== 1 || !nonempty(row.sessionId) || !natural(row.seq) || row.seq <= previous
      || (typeof envelope.sessionId === 'string' && row.sessionId !== envelope.sessionId)
      || !nonempty(row.messageId) || ids.has(`${row.sessionId}\0${row.messageId}`)) return { replyFormat: 'invalid-replies' }
    const reply = replyOf({ type: 'assistant/message', seq: row.seq, time: row.time as number, data: {
      turn: row.turn, step: row.step, message: { id: row.messageId, role: 'assistant', source: row.source, content: row.content }, usage: row.usage,
    } }, row.sessionId)
    if (reply === undefined) return { replyFormat: 'invalid-replies' }
    previous = reply.seq
    ids.add(`${reply.sessionId}\0${reply.messageId}`)
    replies.push(reply)
  }
  return { replies, replyFormat: 'committed-assistant-v1' }
}

/** Parse one per-message transport frame with exactly the array member validation. */
export function replyFrame(value: unknown, sessionId: string): RemoteReply | undefined {
  return replyFields({ sessionId, replyFormat: 'committed-assistant-v1', replies: [value] }).replies?.[0]
}

/**
 * Merge one-by-one transport frames into a final envelope that already carries a
 * valid committed array. A legacy/invalid envelope is returned unchanged: IO
 * frames must never invent message boundaries for an old peer.
 */
export function mergeReplyFrames(value: unknown, frames: readonly RemoteReply[]): unknown {
  if (frames.length === 0) return value
  const fields = replyFields(value)
  if (fields.replyFormat !== 'committed-assistant-v1' || fields.replies === undefined) return value
  const merged = new Map<string, RemoteReply>()
  for (const reply of fields.replies) merged.set(`${reply.sessionId}\0${reply.messageId}`, reply)
  for (const reply of frames) {
    const key = `${reply.sessionId}\0${reply.messageId}`
    if (!merged.has(key)) merged.set(key, reply)
  }
  const replies = [...merged.values()].sort((left, right) => left.seq - right.seq)
  if (replies.length === fields.replies.length) return value
  return {
    ...(value as Record<string, unknown>),
    replies,
    reply: replies.map(reply => reply.text).filter(Boolean).join('\n\n'),
  }
}

/** Pure tool presentation; each committed reply is visibly separate without writing local assistant events. */
export function renderRemoteReplies(value: unknown): string {
  const envelope = record(value)
  const fields = replyFields(value)
  if (fields.replies === undefined) {
    const legacy = typeof envelope?.reply === 'string' && envelope.reply !== '' ? envelope.reply : '(empty reply)'
    return `--- ${fields.replyFormat === 'legacy-text' ? 'legacy reply (message boundaries unavailable)' : 'invalid reply metadata; legacy text only'} ---\n${legacy}`
  }
  const replies = fields.replies
  if (replies.length === 0) return '--- committed remote replies: 0 ---'
  return replies.map((reply, index) => {
    const lines = [
      `--- remote reply ${index + 1}/${replies.length} [assistant · ${reply.provider}/${reply.model}] ---`,
      `session: ${reply.sessionId}  messageId: ${reply.messageId}  seq: ${reply.seq}  turn: ${reply.turn}  step: ${reply.step}  time: ${reply.time}`,
    ]
    for (const block of reply.content) {
      if (block.type === 'text') lines.push(block.text)
      else lines.push(`[remote ${block.type}: ${JSON.stringify(block.attachment)}; attachment belongs to remote session]`)
    }
    return lines.join('\n')
  }).join('\n\n')
}

/** Bounded history leaves retain public message metadata without exposing attempts, reasoning, or replayState. */
export function extractPublicEvents(events: readonly ReplyEvent[], fromSeq: number, limit: number, sessionId: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = []
  let turn: number | undefined
  let step: number | undefined
  const bounded = Number.isFinite(limit) && limit > 0 ? Math.min(1000, Math.floor(limit)) : 400
  for (const event of events) {
    const data = record(event.data)
    if (event.type === 'turn/start') { turn = typeof data?.turn === 'number' ? data.turn : undefined; step = undefined }
    if (event.type === 'step/start') step = typeof data?.step === 'number' ? data.step : undefined
    if (event.seq < fromSeq || event.type === 'assistant/attempt') continue
    const base: Record<string, unknown> = { seq: event.seq, type: event.type, time: event.time, ...(turn === undefined ? {} : { turn }), ...(step === undefined ? {} : { step }) }
    if (event.type === 'assistant/message') {
      const reply = replyOf(event, sessionId)
      if (reply === undefined) continue
      Object.assign(base, reply)
    } else if (event.type === 'user/message') {
      const content = publicContent(data?.content)
      const source = record(data?.source)
      base.messageId = data?.id
      base.content = content
      base.text = contentText(content)
      base.attachmentScope = 'remote-session'
      // Source fields are producer-defined JSON. Never serialize arbitrary runtime objects.
      base.source = source === undefined ? null : Object.fromEntries(Object.entries(source).filter(([key, field]) => key !== 'replayState' && (typeof field === 'string' || typeof field === 'number' || typeof field === 'boolean')))
    } else if (event.type === 'tool/call') {
      base.name = typeof data?.name === 'string' ? data.name : ''
      base.arguments = typeof data?.arguments === 'string' ? data.arguments.slice(0, 4000) : ''
    } else if (event.type === 'tool/result') {
      const message = record(data?.message)
      base.text = contentText(publicContent(message?.content)).slice(0, 4000)
      base.isError = message?.isError === true
    } else if (event.type === 'turn/end') {
      base.reason = record(data?.reason)?.kind ?? null
    }
    out.push(base)
    if (out.length >= bounded) break
  }
  return out
}
