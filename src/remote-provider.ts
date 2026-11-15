/**
 * The peer harness, presented to DSH as a one-shot **subagent provider**.
 *
 * This is what turns "a remote conversation" into "a task": the local chat groups
 * `subagent_*` calls as delegation, a background run shows up as a `subagent-N`
 * job, and cancellation flows through `dispose()` — which stops the peer's turn
 * through the peer's own `agent.interrupt` op rather than by dropping the socket.
 *
 * The seam explicitly allows a provider whose child is not a local Agent
 * (`localAgent: undefined`), and that is exactly a remote conversation: the peer
 * owns its own session, so there is no child Session to publish here. The
 * documented consequences are that such a run is **not** listed by `list_agents`,
 * cannot be opened from the subagent catalog, and has no `send_message`; the
 * model-facing contract is one-shot delegation with one result.
 *
 * Nothing here imports `@deepseek-ai/dsh-subagent` at module scope. This plugin
 * is installed by profile link and only carries a node_modules junction for the
 * packages it statically imports, so the kit arrives through
 * {@link RemoteProviderDeps.kit}, imported lazily by the caller. A machine
 * without that package must still be able to load this plugin.
 *
 * @module dsh-remote/remote-provider
 */

import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import { raceAbort } from './async.ts'
import type { RemoteReply, ReplyFormat } from './reply-codec.ts'

/** Terminal outcome of one remote run, structurally the seam's `SubagentResult`. */
export interface RemoteSubagentResult {
  /** The peer's assistant reply, as content blocks. */
  readonly output: readonly ContentBlock[]
  /** Provider-authored failure detail; kept free of peer payloads. */
  readonly diagnostic?: string
  /** Why the run ended. */
  readonly stopReason: string
  /** Genuine peer messages, separate from the provider's flattened compatibility output. */
  readonly replies?: readonly RemoteReply[]
  readonly replyFormat?: ReplyFormat
}

/** A published run, structurally the seam's `SubagentRun` for a remote child. */
export interface RemoteSubagentRun {
  /** Run id, unique in the parent namespace. */
  readonly id: string
  /** Always undefined: the child lives on another machine. */
  readonly localAgent: undefined
  readonly result: Promise<RemoteSubagentResult>
  /** Idempotent: cancel remaining work, stop the peer's turn, reach quiescence. */
  dispose(): Promise<void>
}

/** The peer-facing half of one run, as the provider needs it. */
export interface RemotePromptOutcome {
  /** The peer's assistant reply ('' when it produced none). */
  readonly reply: string
  readonly replies?: readonly RemoteReply[]
  readonly replyFormat?: ReplyFormat
  /** True when the peer reported that its turn was interrupted. */
  readonly interrupted?: boolean
  /** Whether the peer created this conversation on this call. */
  readonly created?: boolean
  /** The peer's turn reason, for diagnostics. */
  readonly reason?: string | null
}

/**
 * The three runtime pieces this provider needs from `@deepseek-ai/dsh-subagent`.
 *
 * Declared structurally on purpose: the module must typecheck and load without
 * that package present, and the caller hands the real exports in after a lazy
 * import.
 */
export interface RemoteSubagentKit {
  readonly NO_START_CAPABILITIES: {
    readonly agentOptions: boolean
    readonly outputSchema: boolean
    readonly depthLimit: boolean
    readonly toolFilter: boolean
    readonly persona: boolean
  }
  subprocessRunHandle(parts: {
    readonly id: string
    readonly result: Promise<RemoteSubagentResult>
    readonly signal: AbortSignal
    readonly onAbort: () => void
    readonly requestCancel: () => void
    readonly teardown: () => Promise<void>
  }): RemoteSubagentRun
  settleRunResult(parts: {
    readonly attempt: () => Promise<RemoteSubagentResult>
    readonly collectOutput: () => readonly ContentBlock[]
    readonly collectDiagnostic?: () => string | undefined
    readonly cancelled: () => boolean
    readonly onError?: (error: Error, stopReason: string) => void
    readonly signal: AbortSignal
    readonly onAbort: () => void
  }): Promise<RemoteSubagentResult>
}

/** Everything the provider does not own: the link, the mapping, and the kit. */
export interface RemoteProviderDeps {
  /** Prompt the peer's conversation and await its reply. */
  prompt(request: {
    sessionId: string
    text: string
    signal: AbortSignal
  }): Promise<RemotePromptOutcome>
  /** Stop the peer's turn through the peer's own plugin surface. */
  interrupt(sessionId: string): Promise<void>
  /** The remote conversation this parent chat continues (one chat ⇄ one session). */
  sessionFor(parentSessionId: string): string
  /** Lazily imported subagent kit. */
  kit: RemoteSubagentKit
  /** One-line logger; never throws. */
  log(message: string): void
  /** Provider name advertised to the registry (default `remote`). */
  name?: string
}

/** The provider as the registry consumes it (structurally `SubagentProvider`). */
export interface RemoteSubagentProvider {
  readonly name: string
  readonly capabilities: RemoteSubagentKit['NO_START_CAPABILITIES']
  readonly inheritsParentContext: boolean
  start(request: {
    readonly parent: { readonly session: { readonly id: unknown } }
    readonly prompt: readonly ContentBlock[]
    readonly signal: AbortSignal
  }): Promise<RemoteSubagentRun>
}

/** Join the text blocks of a prompt; other block kinds are not supported here. */
export function promptText(blocks: readonly ContentBlock[]): string {
  const parts: string[] = []
  for (const block of blocks) {
    const typed = block as { type?: unknown, text?: unknown }
    if (typed?.type === 'text' && typeof typed.text === 'string') parts.push(typed.text)
  }
  return parts.join('\n').trim()
}

/**
 * Build the `remote` subagent provider.
 *
 * One run = one prompt on the peer's conversation for the calling chat. The
 * result never rejects after publication (the seam's contract): a peer-reported
 * interrupt or a local stop settles as `aborted`, a peer turn that ended in
 * error settles as `error` with a short diagnostic, and anything thrown by the
 * transport is flattened by `settleRunResult` itself.
 *
 * @param deps - link, mapping, kit, and logging.
 * @returns the provider to hand to `ctx.subagents.registerProvider`.
 */
export function createRemoteProvider(deps: RemoteProviderDeps): RemoteSubagentProvider {
  const providerName = deps.name ?? 'remote'

  return {
    name: providerName,
    capabilities: deps.kit.NO_START_CAPABILITIES,
    // The peer has its own context: it does not see this chat's history.
    inheritsParentContext: false,

    async start(request: {
      readonly parent: { readonly session: { readonly id: unknown } }
      readonly prompt: readonly ContentBlock[]
      readonly signal: AbortSignal
    }): Promise<RemoteSubagentRun> {
      const parentSessionId = String(request.parent.session.id)
      const sessionId = deps.sessionFor(parentSessionId)
      const text = promptText(request.prompt)

      let output: readonly ContentBlock[] = []
      let diagnostic: string | undefined
      let cancelled = false
      let stopRequest: Promise<void> | undefined
      // Whether the peer still has work this run must stop. Disposing a run that
      // ended cleanly must NOT interrupt the conversation: the seam's consumer
      // always calls `dispose()`, and stopping the peer after a completed turn
      // would kill whatever the user asked for next.
      let stopNeeded = false
      // Whether the attempt already reached a terminal outcome. `dispose()` calls
      // `requestCancel()` BEFORE `teardown()`, so without this the "cancel"
      // signal of an ordinary post-run dispose would look like a local Stop.
      let settled = false

      // Stopping the peer is idempotent: a local Stop, a `dispose()`, and an
      // aborted signal can all ask, and the peer must not be interrupted twice
      // for one run (nor left running because the first ask lost a race).
      const askPeerToStop = (): Promise<void> => {
        stopRequest ??= Promise.resolve()
          .then(() => deps.interrupt(sessionId))
          .catch((error: unknown) => {
            deps.log(`${providerName}: could not interrupt ${sessionId} on the peer (${String(error)})`)
          })
        return stopRequest
      }

      // Our own latch, distinct from the request signal: the seam expects
      // `cancelled()` to be true before the attempt's rejection is observed.
      const local = new AbortController()
      const onAbort = (): void => {
        cancelled = true
        stopNeeded = true
        local.abort()
        void askPeerToStop()
      }
      request.signal.addEventListener('abort', onAbort, { once: true })
      if (request.signal.aborted) onAbort()

      const result = deps.kit.settleRunResult({
        signal: request.signal,
        onAbort,
        cancelled: () => cancelled,
        collectOutput: () => output,
        collectDiagnostic: () => diagnostic,
        onError: (error) => { diagnostic = `${providerName}: ${error.message}` },
        attempt: async () => {
          let outcome: RemotePromptOutcome
          try {
            outcome = await raceAbort(
              deps.prompt({ sessionId, text, signal: local.signal }),
              local.signal,
            )
          } catch (error) {
            // A transport fault leaves the peer possibly still working.
            stopNeeded = true
            throw error
          }
          if (outcome.interrupted === true) {
            // Preserve already committed public messages as history, not a usable
            // completed deliverable. Partial interrupted rows were filtered at source.
            stopNeeded = false
            settled = true
            return { output: [], stopReason: 'aborted',
              ...(outcome.replies === undefined ? {} : { replies: outcome.replies }),
              ...(outcome.replyFormat === undefined ? {} : { replyFormat: outcome.replyFormat }),
            }
          }
          // Remote attachment ids cannot be submitted as local attachment ids. Full
          // durable refs stay in replies; the local provider output is labelled text.
          output = outcome.replies === undefined
            ? (outcome.reply === '' ? [] : [{ type: 'text', text: outcome.reply }])
            : outcome.replies.flatMap(reply => reply.content.map(block => block.type === 'text'
              ? block : { type: 'text' as const, text: `[remote ${block.type}: ${JSON.stringify(block.attachment)}; session ${reply.sessionId}]` }))
          const messages = { ...(outcome.replies === undefined ? {} : { replies: outcome.replies }),
            ...(outcome.replyFormat === undefined ? {} : { replyFormat: outcome.replyFormat }) }
          if (outcome.reason === 'error' || outcome.reason === 'blocked') {
            stopNeeded = true
            settled = true
            diagnostic = `${providerName}: the peer's turn ended with reason "${String(outcome.reason)}"`
            return { output, diagnostic, stopReason: 'error', ...messages }
          }
          stopNeeded = false
          settled = true
          return { output, stopReason: 'completed', ...messages }
        },
      })

      return deps.kit.subprocessRunHandle({
        id: sessionId,
        result,
        signal: request.signal,
        onAbort,
        // Local cancellation: settle the run now; the peer is stopped by
        // teardown, which the seam always awaits. Only a dispose that arrives
        // BEFORE the attempt settled means "cancel the work".
        requestCancel: () => {
          if (!settled) stopNeeded = true
          cancelled = true
          local.abort()
        },
        teardown: async () => {
          if (stopNeeded) await askPeerToStop()
        },
      })
    },
  }
}
