/**
 * Running one command on the peer so that a local Stop reaches the PROCESS there.
 *
 * The transport cannot cancel anything by itself: `link.request` is a
 * request/reply exchange with a timeout. So "the local user pressed stop" has two
 * halves, and their ORDER is the whole point:
 *
 *   1. settle the call waiting here (the user's Stop must not be delayed by a slow
 *      or wedged link), and
 *   2. then ask the peer to stop the process, by the `execId` the command was sent
 *      with.
 *
 * The id is what makes (2) possible at all — without it the peer has no way to
 * match the cancel to the process, and the tool would look stopped while the work
 * kept running.
 *
 * Extracted from the tool so the wiring can be tested: this is the code path a
 * GUI Stop takes, and it cannot be exercised from the DSH side of the tests.
 *
 * @module dsh-remote/exec-client
 */

import { raceAbort } from './async.ts'

/** What {@link runCancellableExec} needs to run (and be able to stop) one command. */
export interface CancellableExecOptions {
  /** The id the peer will match a later `exec.cancel` against. */
  execId: string
  /** The `exec` arguments, minus the id. */
  args: Record<string, unknown>
  /** How long to wait for the peer's reply. */
  timeoutMs: number
  /** Local cancellation, when the caller has one. */
  signal?: AbortSignal
  /** Send the command; the id is added here so it can never be forgotten. */
  send: (args: Record<string, unknown>, timeoutMs: number) => Promise<Record<string, unknown>>
  /** Ask the peer to stop that process. Best effort — the caller never awaits it. */
  cancelRemote: (execId: string) => void
}

/**
 * Send the command and wait for it, forwarding a local cancellation to the peer.
 *
 * A reply that arrives first wins: a cancel is then NOT sent, so a Stop racing a
 * command that already finished cannot kill the next thing the peer runs.
 *
 * @param options - the command, its id, the transport calls, and the signal.
 * @returns the peer's reply.
 * @throws the abort error when the signal wins, or whatever the transport threw.
 */
export async function runCancellableExec(
  options: CancellableExecOptions,
): Promise<Record<string, unknown>> {
  const pending = options.send({ ...options.args, execId: options.execId }, options.timeoutMs)
  if (options.signal === undefined) return await pending
  try {
    return await raceAbort(pending, options.signal)
  } catch (error) {
    // Settle locally first, then ask the peer to stop — never the other way round,
    // or a slow link would delay the user's own cancellation.
    if ((error as { name?: string }).name === 'AbortError') options.cancelRemote(options.execId)
    throw error
  }
}
