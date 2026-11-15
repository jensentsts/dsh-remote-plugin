/**
 * Cancellation helpers shared by everything this plugin runs on the peer.
 *
 * The transport is a request/reply exchange (`link.request`) with a timeout and
 * no cancellation of its own, so "the local user pressed stop" has to settle the
 * waiting call by itself and then tell the peer to stop separately. Both the
 * subagent provider and the `remote_exec` tool need exactly that, so it lives
 * here rather than in either of them.
 *
 * @module dsh-remote/async
 */

/** A cancellation error the seams that check `name` can recognize. */
export function abortError(message = 'dsh-remote: the call was cancelled locally'): Error {
  const error = new Error(message)
  error.name = 'AbortError'
  return error
}

/**
 * Resolve `work`, or reject as soon as `signal` aborts.
 *
 * Whichever side loses the race is still observed by `Promise.race`, so nothing
 * rejects unhandled; the listener is removed on every path.
 *
 * @param work - the in-flight peer call.
 * @param signal - local cancellation.
 * @returns the work's value, or rejects with an `AbortError`.
 */
export async function raceAbort<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    void work.catch(() => {})
    throw abortError()
  }
  let release: (() => void) | undefined
  try {
    return await Promise.race([
      work,
      new Promise<never>((_resolve, reject) => {
        release = () => reject(abortError())
        signal.addEventListener('abort', release, { once: true })
      }),
    ])
  } finally {
    if (release !== undefined) signal.removeEventListener('abort', release)
  }
}
