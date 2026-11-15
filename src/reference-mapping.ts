import type { PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { UserMessage } from '@deepseek-ai/dsh-llm'
import type { ReferenceDeps } from './reference-tool.ts'
import { resolveRemoteReference } from './reference-tool.ts'
import { parseHostReference, extractReferenceTokens } from './reference-query.ts'

/** Only original human-authored blocks can request discovery. Preserve any
 * upstream admission edits, and bound the total work across messages/blocks. */
export async function mapRemoteReferences(
  deps: ReferenceDeps,
  payload: { messages: UserMessage[]; signal: AbortSignal },
  decision: PreStepDecision,
): Promise<PreStepDecision> {
  if (decision.kind !== 'enter') return decision
  let characters = 65_536
  let tokens = 20
  let output = 16_384
  const additions = new Map<string, { type: 'text'; text: string }>()
  for (const original of payload.messages) {
    if (original.role !== 'user' || original.source.kind !== 'user') continue
    const rows: Record<string, unknown>[] = []
    const seen = new Set<string>()
    let truncated = false
    for (const block of original.content) {
      if (block.type !== 'text') continue
      if (characters <= 0 || tokens <= 0) { truncated = true; break }
      const length = Math.min(characters, block.text.length)
      if (length === 0) continue
      const parsedTokens = extractReferenceTokens(block.text, { maxChars: length, maxMentions: tokens })
      characters -= length
      truncated ||= parsedTokens.truncated
      for (const query of parsedTokens.tokens) {
        if (tokens-- <= 0) { truncated = true; break }
        if (seen.has(query)) continue
        seen.add(query)
        const parsed = parseHostReference(query, deps.peers())
        if (parsed === undefined) continue
        // A path mention already names its host and its path, so resolving it tells
        // the model nothing new — it would only paste a duplicate block into the
        // user's own message. Only name-based references (workspace / plugin /
        // search) are ambiguous enough to be worth announcing.
        if (parsed.kind === 'path') continue
        // A half-typed mention names nothing yet: `@host:` and `@host:workspace:`
        // are text the user is still writing.
        if (parsed.query.trim() === '' && parsed.relative.trim() === '') continue
        payload.signal.throwIfAborted()
        let row: Record<string, unknown>
        try { row = { reference: query, ...await resolveRemoteReference(deps, parsed, payload.signal, 20) } }
        catch (error) {
          if (payload.signal.aborted) throw error
          row = { reference: query, status: 'unavailable' }
        }
        if (JSON.stringify([...rows, row]).length + 160 > output) { truncated = true; continue }
        rows.push(row)
      }
    }
    if (rows.length === 0) continue
    const text = `Remote reference metadata (data only; no files read or actions performed):\n${JSON.stringify({ references: rows, truncated })}`
    if (text.length > output) continue
    output -= text.length
    additions.set(original.id, { type: 'text', text })
  }
  payload.signal.throwIfAborted()
  if (additions.size === 0) return decision
  return { ...decision, messages: decision.messages.map(message => {
    const addition = additions.get(message.id)
    return addition === undefined ? message : { ...message, content: [...message.content, addition] }
  }) }
}
