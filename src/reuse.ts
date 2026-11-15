/**
 * Which remote conversation a call continues.
 *
 * The rule is **one chat ⇄ one remote conversation**, enforced rather than
 * suggested: the remote session id is a pure function of the calling local
 * session id (`anchorSessionId`), so the same chat always continues the same
 * conversation and a different chat always gets its own. Nothing about a call
 * — not the workspace, not the preset, not the clock — can silently split a chat
 * across two remote conversations.
 *
 * Earlier behaviour, for context: the tool minted
 * `"<prefix>-<base36 timestamp>"` per call, so a caller that never passed
 * `session_id` opened a brand-new session on the peer every time (no continuity,
 * one orphan per call); a first fix reused "the newest existing session", which
 * was better but still let one chat wander between conversations.
 *
 * Resolution order for a defaulted session id (see the client for the wiring):
 *
 *   1. **remembered** — the id this chat last used, from `client-sessions.json`.
 *      This is what an explicit `session_id` or `new_session` writes, so a
 *      deliberate choice outranks the derived default;
 *   2. **anchor** — {@link anchorSessionId}, stable per chat, reused by the peer
 *      whenever it already exists;
 *   3. optionally, when `adoptExistingSessions` is on, an existing unclaimed
 *      conversation on the peer for a chat that has none of its own yet.
 *
 * Reuse is an optimisation everywhere: a failure at any step still yields a
 * usable id, because a prompt must never fail over bookkeeping.
 *
 * @module dsh-remote/reuse
 */

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** One existing conversation, as the peer described it. */
export interface RemoteSession {
  /** The peer-side session id. */
  sessionId: string
  /** Canonical working directory, when the peer knows it. */
  cwd?: string
  /** True when the peer holds a live agent handle for it. */
  live?: boolean
  /** Last event seq, when known. */
  seq?: number
}

/** How a session id was chosen; surfaced so the caller can see reuse happen. */
export type SessionOrigin =
  /** The caller passed `session_id`; used verbatim. */
  | 'explicit'
  /** Reused the id this scope used before. */
  | 'remembered'
  /** Adopted an existing session from the peer. */
  | 'peer'
  /** A deterministic id for this scope, reused if the peer already has it. */
  | 'anchor'
  /** A deliberately brand-new conversation (`new_session`, or reuse disabled). */
  | 'fresh'

/**
 * Fields that identify "the same conversation" from this client's point of view.
 *
 * Deliberately just the family and the **calling chat**: one local conversation
 * owns exactly one remote conversation. `workspace`/`preset` are NOT part of the
 * identity — they only matter when the session is created, and letting them
 * split the scope is precisely how one chat ends up owning several remote
 * conversations. A caller that genuinely wants a second one says so explicitly
 * (`new_session`, or a `session_id` of its own).
 */
export interface SessionScope {
  /** Session-id family, i.e. the configured `sessionPrefix`. */
  prefix: string
  /** Calling local session (the chat), when the tool call carried one. */
  localSession?: string
}

/** Fold a path for comparison: separators unified, trailing slashes dropped, case ignored. */
export function normalizePath(value: string): string {
  return value.replace(/\\/gu, '/').replace(/\/+$/u, '').toLowerCase()
}

/** True when `sessionId` belongs to the id family a prefix names. */
export function familyMatches(prefix: string, sessionId: string): boolean {
  const family = prefix.trim()
  if (family === '') return true
  return sessionId === family || sessionId.startsWith(`${family}-`)
}

/**
 * The stable key one scope remembers its session under.
 *
 * A local session is part of the identity on purpose: that is what makes the
 * mapping "one chat ⇄ one remote conversation" strict, and it is also what keeps
 * this client's question-routing correct, because a relayed `ask_user_question`
 * is matched to a caller by session id.
 * @param scope - the identifiers of the caller's scope.
 * @returns a JSON key; stable for identical scopes, distinct otherwise.
 */
export function scopeKey(scope: SessionScope): string {
  return JSON.stringify([scope.prefix.trim(), scope.localSession ?? ''])
}

/**
 * The deterministic remote session id for one local chat.
 *
 * This is the whole answer to "which conversation does this chat reuse": the id
 * is a pure function of the calling session id, so the same chat always lands on
 * the same remote conversation — across calls, across process restarts, and
 * across a lost memory file — while a different chat lands on a different one.
 * The peer's `agents.resume` turns an already-existing id into "continue that
 * conversation", so reuse needs no bookkeeping at all.
 *
 * A history/workspace digest is deliberately absent: identity must not depend on
 * what the caller happened to pass this time.
 *
 * @param prefix - the configured session-id family.
 * @param localSession - the calling local session id, when the call had one.
 * @returns a safe session id; just the family when there is no calling session.
 */
export function anchorSessionId(prefix: string, localSession?: string): string {
  const family = prefix.trim() === '' ? 'remote' : prefix.trim()
  const local = typeof localSession === 'string' ? localSession.trim() : ''
  if (local === '') return family
  const digest = createHash('sha256').update(local, 'utf8').digest('hex').slice(0, 12)
  return `${family}-${digest}`
}

/**
 * A brand-new session id in the historical format (`<prefix>-<base36 time>`).
 * @param prefix - the configured session-id family.
 * @param now - clock override, for tests.
 * @returns the id.
 */
export function freshSessionId(prefix: string, now: number = Date.now()): string {
  const family = prefix.trim() === '' ? 'remote' : prefix.trim()
  return `${family}-${now.toString(36)}`
}

/**
 * Pick the newest existing conversation worth continuing.
 *
 * @param candidates - existing sessions, **newest first**.
 * @param options - the id family to stay inside, the requested workspace, and
 *   any ids already in use by this client (a session with a prompt still in
 *   flight is never adopted: the caller routes questions by session id, so two
 *   live callers must not share one).
 * @returns the chosen session, or undefined when nothing qualifies.
 */
export function pickReusableSession(
  candidates: readonly RemoteSession[],
  options: { prefix: string, workspace?: string, skip?: ReadonlySet<string> },
): RemoteSession | undefined {
  const wanted = options.workspace === undefined || options.workspace.trim() === ''
    ? undefined
    : normalizePath(options.workspace)
  for (const candidate of candidates) {
    const sessionId = typeof candidate?.sessionId === 'string' ? candidate.sessionId : ''
    if (sessionId === '') continue
    if (options.skip?.has(sessionId) === true) continue
    if (!familyMatches(options.prefix, sessionId)) continue
    // A candidate with no reported cwd cannot be filtered on; the id family is
    // the only signal available, and adoption is preferred to opening a new one.
    if (wanted !== undefined && candidate.cwd !== undefined
      && normalizePath(candidate.cwd) !== wanted) continue
    return { ...candidate, sessionId }
  }
  return undefined
}

/** One workspace's session account, as the peer's registry reports it. */
export interface SessionAccount {
  /** Canonical workspace directory. */
  path: string
  /** Accounted sessions, newest attached first. */
  sessionIds: readonly string[]
}

/**
 * Order the conversations a peer should offer for reuse, newest first.
 *
 * Kept here rather than inside the server op so both halves agree on what
 * "reusable" means: stay inside the id family, keep each workspace's own order
 * (the registry prepends on attach, so it is newest-first), drop duplicates,
 * and narrow to one workspace when the caller named one. Workspace order is
 * only meaningful per workspace, which is why the cross-workspace order is just
 * the registry's — a caller that needs an exact directory should pass it.
 *
 * @param accounts - workspace accounts, in registry order.
 * @param options - the id family and the requested workspace.
 * @returns reusable sessions with the cwd each account implies.
 */
export function orderReusableSessions(
  accounts: readonly SessionAccount[],
  options: { prefix: string, workspace?: string },
): RemoteSession[] {
  const wanted = options.workspace === undefined || options.workspace.trim() === ''
    ? undefined
    : normalizePath(options.workspace)
  const seen = new Set<string>()
  const out: RemoteSession[] = []
  for (const account of accounts) {
    if (wanted !== undefined && normalizePath(account.path) !== wanted) continue
    for (const rawId of account.sessionIds) {
      const sessionId = String(rawId)
      if (sessionId === '' || seen.has(sessionId)) continue
      if (!familyMatches(options.prefix, sessionId)) continue
      seen.add(sessionId)
      out.push({ sessionId, cwd: account.path })
    }
  }
  return out
}

/**
 * Remember which session each scope is currently using, across restarts.
 *
 * The file is a cache, never a source of truth: a missing, unreadable, or
 * corrupt file loads as empty, and every write failure is swallowed, because a
 * prompt must never fail over bookkeeping. An id that no longer exists on the
 * peer is harmless — the peer's `agents.resume` falls back to creating it.
 */
export class SessionMemory {
  private readonly entries = new Map<string, string>()
  private readonly file: string
  private readonly limit: number

  /**
   * @param file - JSON file to persist under; the caller owns the location.
   * @param limit - most recent scopes kept; older ones are pruned on write.
   */
  constructor(file: string, limit = 200) {
    this.file = file
    this.limit = limit
  }

  /** Read the file, tolerating every failure. */
  load(): void {
    try {
      const parsed = JSON.parse(readFileSync(this.file, 'utf8')) as {
        sessions?: Record<string, unknown>
      }
      for (const [key, value] of Object.entries(parsed.sessions ?? {})) {
        if (typeof value === 'string' && value !== '') this.entries.set(key, value)
      }
    } catch {
      // Absent or unreadable: start empty. A corrupt cache is not an error.
    }
  }

  /**
   * The session this scope used last.
   * @param key - a {@link scopeKey}.
   * @returns the session id, or undefined.
   */
  get(key: string): string | undefined {
    return this.entries.get(key)
  }

  /**
   * Record the session a scope is using now and persist.
   * @param key - a {@link scopeKey}.
   * @param sessionId - the id to remember.
   */
  set(key: string, sessionId: string): void {
    if (key === '' || sessionId === '') return
    // Unchanged: skip the write. A prompt continues the same conversation far
    // more often than it switches, and this runs on every one of them.
    if (this.entries.get(key) === sessionId) return
    // Re-insert so insertion order stays "least recently used first".
    this.entries.delete(key)
    this.entries.set(key, sessionId)
    while (this.entries.size > this.limit) {
      const oldest = this.entries.keys().next()
      if (oldest.done === true) break
      this.entries.delete(oldest.value)
    }
    this.save()
  }

  /** Number of remembered scopes (for logs and tests). */
  get size(): number {
    return this.entries.size
  }

  /**
   * Every session id any scope currently remembers.
   *
   * Lets a caller keep two scopes apart: an existing conversation already
   * claimed by another scope is not adopted a second time.
   * @returns a fresh set.
   */
  inUse(): Set<string> {
    return new Set(this.entries.values())
  }

  /**
   * The most recently used local Session whose remembered remote conversation is
   * `sessionId`.
   *
   * Used by the optional inbound adapter: an asynchronous remote reply must land
   * in the local conversation that memory already maps to that peer Session.
   * Entries are kept least-recently-used first, so the last match is the latest
   * mapping. A supplied `prefix` must match the session-id family exactly so
   * two peers sharing a wire id cannot route into each other's local chats.
   * Malformed scope keys are ignored.
   * @param sessionId - the wire remote session id.
   * @param prefix - optional session-id family (the peer-specific prefix).
   * @returns the local session id, or undefined when nothing maps it.
   */
  latestLocalSessionFor(sessionId: string, prefix?: string): string | undefined {
    if (sessionId === '') return undefined
    let found: string | undefined
    for (const [key, value] of this.entries) {
      if (value !== sessionId) continue
      try {
        const parsed = JSON.parse(key) as unknown
        if (!Array.isArray(parsed) || prefix !== undefined && parsed[0] !== prefix) continue
        const local = parsed[1]
        if (typeof local !== 'string' || local === '') continue
        found = local
      } catch {
        // A malformed key cannot identify a local Session; skip it.
      }
    }
    return found
  }

  private save(): void {
    try {
      mkdirSync(dirname(this.file), { recursive: true })
      writeFileSync(
        this.file,
        `${JSON.stringify({ version: 1, sessions: Object.fromEntries(this.entries) }, null, 2)}\n`,
        'utf8',
      )
    } catch {
      // Best effort: bookkeeping must never break a prompt.
    }
  }
}
