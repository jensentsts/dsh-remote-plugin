/** Remote-owned Agent admission helpers; no transport, persistence backend or Agent ownership is bypassed. */
import type { UserMessage } from '@deepseek-ai/dsh-llm'

/** Producer source is extensible in DSH 0.2.2-rc.1; user role does not imply a local human. */
export interface RemoteInputSource {
  kind: 'dsh-remote'
  version: 1
  principal: string
  remoteSessionId: string
  operation: 'agent.prompt' | 'agent.note'
  traceId: string
}

declare module '@deepseek-ai/dsh-llm' {
  interface MessageSourceMap { 'dsh-remote': RemoteInputSource }
}

export type RemoteInputMode = 'queue' | 'steer' | 'auto'

/** Only the exact session-persistence absence failure permits creating that identity. */
export function isDefiniteSessionNotFound(error: unknown, sessionId: string): boolean {
  if (!(error instanceof Error)) return false
  const value = error as Error & { sessionId?: unknown, code?: unknown, details?: { sessionId?: unknown } }
  if (value.name === 'SessionPersistenceNotFoundError') return value.sessionId === sessionId
  return value.code === 'session/not-found' && value.details?.sessionId === sessionId
}

/** Parse the optional wire mode; omissions retain auto delivery for earlier clients. */
export function inputMode(value: unknown): RemoteInputMode {
  if (value === undefined || value === 'auto') return 'auto'
  if (value === 'queue' || value === 'steer') return value
  throw new Error('agent.note: mode must be queue, steer or auto')
}

/** Admit once and report the actual inbox boundary. A missing steer method is never silently queued. */
export function deliverInput(
  agent: { followup(message: UserMessage): void, steer?(message: UserMessage): void },
  message: UserMessage,
  requested: RemoteInputMode,
  busy: boolean,
): { mode: 'queue' | 'steer', processing: 'next-turn' | 'next-step' | 'starting' } {
  const mode = requested === 'auto' ? (busy ? 'steer' : 'queue') : requested
  if (mode === 'steer') {
    if (typeof agent.steer !== 'function') throw new Error('agent.note: this Agent has no steering capability')
    agent.steer(message)
  } else agent.followup(message)
  return { mode, processing: busy ? (mode === 'steer' ? 'next-step' : 'next-turn') : 'starting' }
}
