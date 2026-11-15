/**
 * The peer's running child processes, addressable so a controller can stop one.
 *
 * `remote_exec` used to be unfinishable by the person who started it: the local
 * Stop cancelled the waiting tool call, and the command kept running on the
 * controlled machine until its own timeout. The command is a remote task like any
 * other, so a stop has to reach it — which needs the child handle kept somewhere
 * addressable, and that somewhere needs to be a pure object to be testable
 * without a cordis context or a shell.
 *
 * Deliberately tiny and synchronous: registering, cancelling, and releasing are
 * all called from process-callback contexts where a promise would only delay the
 * teardown that matters.
 *
 * @module dsh-remote/exec-registry
 */

/** One running child, reduced to the only thing the registry does with it. */
export interface CancellableChild {
  /** Stop the process (best effort; the caller decides how hard). */
  cancel(): void
}

/**
 * Running children by caller-supplied id.
 *
 * Ids come from the controller, so this is a plain map; an id reused while its
 * predecessor is still running replaces the entry rather than nesting, because
 * the older handle is already unreachable and only its own completion can
 * release it (which the disposer does, guarded by identity).
 */
export class ExecRegistry {
  private readonly running = new Map<string, CancellableChild>()

  /**
   * Track one child.
   * @param id - the caller's id for this execution.
   * @param child - the handle to cancel.
   * @returns the disposer to call when the child settles; idempotent, and a
   *   stale disposer can never remove a newer entry that reused the id.
   */
  add(id: string, child: CancellableChild): () => void {
    if (id === '') return () => {}
    this.running.set(id, child)
    let released = false
    return () => {
      if (released) return
      released = true
      if (this.running.get(id) === child) this.running.delete(id)
    }
  }

  /**
   * Cancel one running child.
   * @param id - the id the execution was registered under.
   * @returns true when something was running and was asked to stop.
   */
  cancel(id: string): boolean {
    const child = this.running.get(id)
    if (child === undefined) return false
    this.running.delete(id)
    try {
      child.cancel()
    } catch {
      // The child is already gone, or the platform refused; either way the
      // controller asked, and reporting "no such execution" would be a lie.
    }
    return true
  }

  /** How many children are tracked (for logs and tests). */
  get size(): number {
    return this.running.size
  }

  /** Whether an id is currently running. */
  has(id: string): boolean {
    return this.running.has(id)
  }

  /** Cancel everything; used when the process itself is going away. */
  cancelAll(): number {
    const ids = [...this.running.keys()]
    for (const id of ids) this.cancel(id)
    return ids.length
  }
}
