/**
 * `dsh-remote-server` —the half that runs on the machine being controlled.
 *
 * It listens on a loopback TCP port (the one a frp tunnel points at) and
 * serves a small RPC surface to a peer holding the pinned client key. Besides
 * plain shell/file operations, it can drive *this* DSH instance's agents: create
 * or resume a session, inject a user message, wait for the turn to settle, and
 * hand back the assistant's reply —which is what lets the peer treat this
 * harness as an agent.
 *
 * Security posture
 * ----------------
 * - Only loopback binds by default; the tunnel is the only way in.
 * - Mutual X25519 authentication with pinned keys; see `protocol.ts`.
 * - Failed handshakes are counted per source address and past a threshold the
 *   source is refused for a cooling-off window, so a public tunnel endpoint
 *   cannot be hammered.
 * - Every accepted operation is appended to an audit log next to the key file.
 *
 * @module dsh-remote/server
 */

import { AsyncLocalStorage } from 'node:async_hooks'
import { execFile } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { readFile, readdir, realpath, stat, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import type { Server, Socket } from 'node:net'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'

import type { Context, Volatile } from '@deepseek-ai/cordis'
import { isVolatile } from '@deepseek-ai/cosmokit'
import z from '@deepseek-ai/schemastery'
import { installModelSelection } from '@deepseek-ai/dsh-agent'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
// Type-only: carries the `ctx.settings` Context merge.
import type {} from '@deepseek-ai/dsh-settings'
import type { SettingsNamespace } from '@deepseek-ai/dsh-settings'
import type { ToolExecutionToken, ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { ToolCallId } from '@deepseek-ai/dsh-llm/brand'
import { SessionId } from '@deepseek-ai/dsh-session'
import type { SessionEvent } from '@deepseek-ai/dsh-session'
// Type-only: declares the `loader/volatile-update` event.
import type {} from '@deepseek-ai/cordis-plugin-loader'
// Runtime import also merges `ctx.agentPresets`; presets are what give a
// remotely created session its tool set.
import type {} from '@deepseek-ai/dsh-agent-preset-registry'
// Type-only: declares `ctx.systemPrompt`, which is how a driven session is told
// what it is.
import type {} from '@deepseek-ai/dsh-system-prompt'
// Type-only: declares `ctx.subagents`, so the capability catalog can list this
// machine's subagent providers.
import type {} from '@deepseek-ai/dsh-subagent'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'

import { HandshakeError, MAGIC, fingerprint, publicFromRaw, rawPublic, publicToPem, serverHandshake } from './protocol.ts'
import { KEY_SELECTOR_ACK, KEY_SELECTOR_DENIED, KEY_SELECTOR_MAGIC, readHandshakeField } from './link.ts'
import { listReferenceCatalog } from './reference-catalog.ts'
import { NetworkGuard, allowedOperations, expirationTime, networkLimits, validateRequestEnvelope, withAuthorization } from './network-guard.ts'
import type { AdmissionLease } from './network-guard.ts'
import { RelayHub } from './relay-hub.ts'
// Type-only: declares the `user-questions/request` waterfall that
// `ask_user_question` pauses inside. This half claims requests from the sessions
// IT manages and relays them to the controller, so the question is reviewed on
// the controlling side instead of being rendered here.
import type {} from '@deepseek-ai/dsh-user-questions'
import type { AskUserQuestionAnswer } from '@deepseek-ai/dsh-user-questions'
import { FsError } from '@deepseek-ai/dsh-fs'
import { assertPeerOperation, normalizePermission, requiredLevel, validatePeerNames } from './peers.ts'
import type { Session } from './protocol.ts'
import { ExecRegistry } from './exec-registry.ts'
import { Journal, summarizeEvent, summarizeOp } from './journal.ts'
import { createTransferServer } from './transfer-server.ts'
import { familyMatches, normalizePath, orderReusableSessions } from './reuse.ts'
import { extractUsageRecords } from './session-usage.ts'
import { extractPublicEvents, summarizeReplies } from './reply-codec.ts'
import type { RemoteReply } from './reply-codec.ts'
import { deliverInput, inputMode, isDefiniteSessionNotFound } from './agent-delivery.ts'
import { admitTracked, createMessageTraces } from './message-traces.ts'
import { createRemoteIoBridge } from './remote-io.ts'
import type { IoBinding, IoReceiveOutcome } from './remote-io.ts'
import {
  describeIdentity,
  dshHomePath,
  resolvePeerPublicKey,
  resolvePrivateKey,
  text,
} from './keys.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-server'

/** Settings namespace the GUI edits (`settings.yaml` —`dsh-remote-server:`). */
export const DSH_REMOTE_SERVER_SETTINGS_NAMESPACE = 'dsh-remote-server' as SettingsNamespace

/** Advertised to the peer so it can refuse an incompatible build. */
export const SERVER_VERSION = '0.5.3'

/**
 * Bumped on every source change.
 *
 * DSH does not re-import an already-loaded module, so after editing this
 * file the runtime may still be serving the previous build. Shipping the tag
 * in `sysinfo` turns "did my edit take effect?" into one tool call.
 */
export const BUILD = 'r27'

/**
 * Ops never written to the trajectory journal.
 *
 * `journal.read` is the original case: a reader must not grow what it reads, or
 * a polling controller would fill the journal with its own polling. Transfer
 * traffic joins it for the same reason at a larger scale: one 8 MiB file is
 * thousands of `fs.put.chunk` calls, and each `fs.get` is a read. Their
 * `begin`/`commit`/`abort` siblings are still journalled —one line per file.
 */
const NOT_JOURNALED_OPS = new Set(['journal.read', 'fs.put.chunk', 'fs.get', 'caps.list', 'references.list', 'relay.write', 'relay.status'])

/**
 * Tool names a controller may never run directly, unless its own `deniedTools`
 * says otherwise.
 *
 * Two families, for two different reasons:
 *
 *  * `remote_*` / `remote__*` are THIS plugin's bridge tools. Exposing them would
 *    let a controller drive a second controller and loop rights back around; the
 *    peer's own kernel should answer with the tool, not with the bridge.
 *  * Interactive tools assume a live agent and a human looking at THIS machine's
 *    UI (`ask_user_question`, plan approval, `present`). Called with no session
 *    they cannot do their job, and a controller must not be able to pop a dialog
 *    on a machine whose user is not part of the conversation.
 */
const DENIED_TOOL_PREFIXES = ['remote_', 'remote__']
const DEFAULT_DENIED_TOOLS = ['ask_user_question', 'exit_plan_mode', 'present']


/**
 * What a session this half drives is told about itself.
 *
 * The controlled side is not an ordinary chat: a remote controller drives it as
 * a task, and a human on THIS machine may be watching it, may type into it, and
 * may stop it. Saying so is what keeps the driven agent from behaving as if it
 * owned the conversation —and it is the counterpart of the controller-side
 * guidance the client half contributes.
 */
const CONTROLLED_GUIDANCE = [
  '## 你正被远端驱动（dsh-remote 受控端）',
  '本会话由另一台机器上的 DSH agent（控制方）以「subagent / task」的方式驱动：它派活、你交付，',
  + '把它当作你的用户，但不要假设它能看到本机屏幕或本机上下文。',
  '交付要自成一体：结论、关键命令输出、涉及的文件路径都写进回复；',
  + '对方拿到的就是你这一轮的回复和你留在会话里的事件。',
  '只做被要求的事，不要擅自扩大范围；需要人拍板时用 ask_user_question 提问',
  + '（它会转交给控制方，由控制方或其用户回答），不要自己替用户决定。',
  '本机可能有真人正在看这个会话，也可能直接插话或按停。',
  + '**任何一侧用户的打断与新指示优先级最高**：被中断就立刻停手、不要继续、不要重试；',
  + '出现新指示时以它为准，重新规划。',
].join('\n')

/**
 * Hard dependencies. `agentDefaultModel` matters as much as the registries: a
 * freshly created agent has no model route of its own, and without one its
 * first turn fails immediately with `reason: error`.
 */
export const inject = [
  'agentDefaultModel',
  'agentPresets',
  'agents',
  'sessions',
  // Needed so a remotely created session is owned by a workspace; without
  // that ownership the GUI has nothing to list it under.
  'workspaceRegistry',
]

/**
 * Plugin config. Every field is a `Volatile` reference: the listener, the
 * permission ceiling and the audit settings are all re-read per operation, so
 * a committed settings edit mutates the running value in place. The listener
 * is restarted off `loader/volatile-update` because a bind address/port change
 * cannot take effect without rebinding.
 */
/** One pinned controller. Empty authorizedPeers selects the legacy single pin. */
export interface AuthorizedPeer {
  peerPublicKey?: string
  peerPublicKeyFile?: string
  maxPermission?: number
  workspaceRoot?: string
  /** Explicit readable roots at levels 1/2; empty denies file contents/metadata. */
  readRoots?: string[]
  /** Empty retains the ordinary permission ceiling; nonempty matches exact ops only. */
  allowedOps?: string[]
  disabled?: boolean
  /** RFC3339 timestamp including Z or a UTC offset; empty means no expiry. */
  validUntil?: string
  /** Exact mesh nodes this identity may connect to; both ends must permit the pair. */
  relayTargets?: string[]
}

export interface Config {
  /** Bind address —keep `127.0.0.1` when frpc runs on this machine. */
  host: Volatile<string>
  /** Bind port —the frp tunnel's local port. */
  port: Volatile<number>
  /** Inline X25519 private key (PEM / 64 hex / base64); wins over the file. */
  privateKey: Volatile<string>
  /** File holding this side's private key; also where a generated one lands. */
  privateKeyFile: Volatile<string>
  /** Generate and persist a keypair when none exists yet (default true). */
  autoGenerateKey: Volatile<boolean>
  /** Inline pinned X25519 public key of the peer; wins over the file. */
  peerPublicKey: Volatile<string>
  /** File holding the peer's pinned public key. */
  peerPublicKeyFile: Volatile<string>
  /** Named pinned controllers; nonempty replaces (never supplements) the legacy pin. */
  authorizedPeers: Volatile<Record<string, AuthorizedPeer>>
  /** Enable opaque hub forwarding on this existing listener, off by default. */
  relayEnabled: Volatile<boolean>
  readRoots: Volatile<string[]>
  /** Explicit compatibility opt-in for clients without key selection. */
  allowLegacyHandshake: Volatile<boolean>
  maxConnections: Volatile<number>
  maxPendingHandshakes: Volatile<number>
  maxConnectionsPerAddress: Volatile<number>
  maxHandshakesPerMinute: Volatile<number>
  maxTrackedAddresses: Volatile<number>
  handshakeTimeoutMs: Volatile<number>
  maxInFlightPerPrincipal: Volatile<number>
  maxSessionMs: Volatile<number>
  /** Agent working directory for sessions created on request. */
  workspace: Volatile<string>
  /** Default preset for sessions created on request (empty = deployment default). */
  defaultPreset: Volatile<string>
  /** Refuse handshakes from a source after this many failures (default 8). */
  maxHandshakeFailures: Volatile<number>
  /** Cooling-off window in seconds after the threshold is hit (default 900). */
  lockoutSeconds: Volatile<number>
  /** Cap on a single `exec` timeout in milliseconds (default 600000). */
  maxExecTimeoutMs: Volatile<number>
  /**
   * Ceiling on what this machine will accept from a controller, `1 < 2 < 3`:
   * 1 read-only, 2 confined write, 3 unrestricted. Checked here as well as on
   * the controlling side, so the limit holds even if the controller is buggy,
   * compromised, or simply newer. Defaults to 3 (current behaviour); a real
   * deployment should lower it.
   */
  maxPermission: Volatile<number>
  /** Audit log path (default `${DSH_HOME}/dsh-remote/server-audit.log`). */
  auditFile: Volatile<string>
  /** Log every accepted operation (default true). */
  audit: Volatile<boolean>
  /**
   * Tell sessions created on request that a remote controller drives them, that
   * a human here may interrupt, and that interruptions win (default true).
   */
  promptGuidance: Volatile<boolean>
  /**
   * Admit controller input through the optional `super-agent-io` v1 service and
   * let it route each committed assistant message back one at a time (default
   * false).
   *
   * Off, or when the service/binding is unavailable, every existing remote path
   * runs exactly as before. On, the Session row carries IO's real external
   * producer source; it is never presented as a local human or a fake assistant.
   * IO's own `enabled`/`sendEnabled` gates still apply.
   */
  superAgentIo: Volatile<boolean>
  /**
   * Keep the trajectory journal: every operation this half serves, plus what it
   * observes in the sessions it drives (default true).
   *
   * It is the cheap half of the record: append-only, no model call involved, and
   * readable incrementally by a controller (`journal.read` with `fromSeq`).
   */
  journal: Volatile<boolean>
  /** Journal path (default `${DSH_HOME}/dsh-remote/journal.jsonl`). */
  journalFile: Volatile<string>
  /**
   * Heartbeat path (default `${DSH_HOME}/dsh-remote/server-heartbeat.json`).
   *
   * Rewritten once the listener is bound and again after every successful
   * handshake, carrying the build tag, so a deploy/restart script can tell "this
   * build is serving" from "something is listening" —the check that was missing
   * when a remote upgrade could not be verified or safely rolled back.
   */
  heartbeatFile: Volatile<string>
  /**
   * Largest file the chunked-transfer fast path (`fs.put.*`) accepts, in bytes.
   *
   * Enforced at `fs.put.begin` before a staging file exists, so a controller's
   * typo cannot fill this machine's disk. Defaults to 1 GiB.
   */
  transferMaxBytes: Volatile<number>
  /** Largest block `fs.get` serves, and the cap on a caller's `length` (8 MiB). */
  transferMaxChunkBytes: Volatile<number>
  /** How many uploads may be in flight at once (default 8). */
  transferMaxActive: Volatile<number>
  /**
   * Idle lifetime of an unfinished upload before it is discarded (10 min).
   *
   * A controller that dies mid-file must not leave a staging file forever; the
   * registry sweeps idle uploads on this interval and deletes their temp files.
   */
  transferUploadTtlMs: Volatile<number>
  /**
   * Largest original file whose content is returned as `before` by a commit.
   *
   * The commit answer feeds the controller's diff, so it is bounded: a large
   * file is reported only by size (`beforeBytes`), never embedded in a frame.
   */
  transferBeforeMaxBytes: Volatile<number>
  /**
   * Let a controller read this machine's function-call surface and call those
   * tools directly (`caps.list` / `caps.call` / `caps.cancel`, default true).
   *
   * This is the "remote plugins work like local plugins" switch: the controller
   * gets a catalog of this kernel's tools and a bridge that runs one of them —   * the tool body itself, on this machine —without creating or resuming a
   * session here. Off hides the catalog and refuses direct calls, while the
   * session-driving ops (`agent.*`) keep working.
   */
  capabilities: Volatile<boolean>
  /**
   * Agent preset whose tool surface the catalog describes, when the controller
   * names none (default: this deployment's default preset).
   *
   * Presets own the interesting tools (`standard`, `cordis`, —, so this is
   * which plugin set the catalog lists. An explicit `presetId` on a request wins.
   */
  capabilityPreset: Volatile<string>
  /**
   * Tool names (or trailing-`*` prefixes) a controller may NOT call directly
   * (`caps.call`).
   *
   * Defaults to the interactive tools that need a live agent and a human on THIS
   * machine's UI; this plugin's own `remote_*` bridge tools are always refused
   * regardless of this list, because exposing them would loop controllers back
   * around. Read live, per call.
   */
  deniedTools: Volatile<string[]>
  /**
   * Ceiling on one `caps.call` execution in milliseconds (default 600000).
   *
   * A direct tool call has no turn around it to end the work, so the peer caps
   * it here; the controller may ask for less, never more.
   */
  maxToolCallTimeoutMs: Volatile<number>
}

/**
 * Plain values behind every reference of a parsed {@link Config}. Everything
 * downstream —the listener, the audit log, the permission fence —reads these,
 * so it stays unaware of the volatile indirection.
 */
export type ResolvedConfig = { [K in keyof Config]-?: Config[K] extends Volatile<infer T> ? T : Config[K] }

export const Config = z.object({
  host: z.string().default('127.0.0.1').volatile(),
  port: z.number().default(11325).volatile(),
  // `role('secret')` keeps the value out of settings-GUI wire payloads.
  privateKey: z.string().role('secret').default('').volatile(),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.key')).volatile(),
  autoGenerateKey: z.boolean().default(true).volatile(),
  peerPublicKey: z.string().default('').volatile(),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.pub')).volatile(),
  authorizedPeers: z.dict(z.object({
    peerPublicKey: z.string().default(''),
    peerPublicKeyFile: z.string().default(''),
    maxPermission: z.number().default(1),
    workspaceRoot: z.string().default(''),
    readRoots: z.array(z.string()).default([]),
    allowedOps: z.array(z.string()).default([]),
    disabled: z.boolean().default(false),
    validUntil: z.string().default(''),
    relayTargets: z.array(z.string()).default([]),
  })).default({}).volatile(),
  relayEnabled: z.boolean().default(false).volatile(),
  readRoots: z.array(z.string()).default([]).volatile(),
  allowLegacyHandshake: z.boolean().default(false).volatile(),
  maxConnections: z.number().default(64).volatile(),
  maxPendingHandshakes: z.number().default(8).volatile(),
  maxConnectionsPerAddress: z.number().default(16).volatile(),
  maxHandshakesPerMinute: z.number().default(120).volatile(),
  maxTrackedAddresses: z.number().default(1024).volatile(),
  handshakeTimeoutMs: z.number().default(15_000).volatile(),
  maxInFlightPerPrincipal: z.number().default(16).volatile(),
  maxSessionMs: z.number().default(3_600_000).volatile(),
  workspace: z.string().default('').volatile(),
  defaultPreset: z.string().default('').volatile(),
  maxHandshakeFailures: z.number().default(8).volatile(),
  lockoutSeconds: z.number().default(900).volatile(),
  maxExecTimeoutMs: z.number().default(600_000).volatile(),
  // 3 preserves today's behaviour; lower it to actually fence this machine.
  maxPermission: z.number().default(3).volatile(),
  auditFile: z.string().default(dshHomePath('dsh-remote', 'server-audit.log')).volatile(),
  audit: z.boolean().default(true).volatile(),
  promptGuidance: z.boolean().default(true).volatile(),
  superAgentIo: z.boolean().default(false).volatile(),
  journal: z.boolean().default(true).volatile(),
  journalFile: z.string().default(dshHomePath('dsh-remote', 'journal.jsonl')).volatile(),
  heartbeatFile: z.string().default(dshHomePath('dsh-remote', 'server-heartbeat.json')).volatile(),
  /**
   * Largest file the chunked-transfer path accepts, in bytes (default 1 GiB).
   *
   * `fs.put.begin` refuses a declared size above it before any staging file is
   * created, so a typo in a controller cannot fill this machine's disk.
   */
  transferMaxBytes: z.number().default(1_073_741_824).volatile(),
  /** Largest block `fs.get` serves, and the cap on a caller's `length` (8 MiB). */
  transferMaxChunkBytes: z.number().default(8 * 1024 * 1024).volatile(),
  /** How many uploads may be in flight at once (default 8). */
  transferMaxActive: z.number().default(8).volatile(),
  /** Idle lifetime of an unfinished upload before it is discarded (10 min). */
  transferUploadTtlMs: z.number().default(600_000).volatile(),
  /** Largest original file whose text is returned as `before` by a commit (1 MiB). */
  transferBeforeMaxBytes: z.number().default(1_048_576).volatile(),
  capabilities: z.boolean().default(true).volatile(),
  capabilityPreset: z.string().default('').volatile(),
  deniedTools: z.array(z.string()).default([...DEFAULT_DENIED_TOOLS]).volatile(),
  maxToolCallTimeoutMs: z.number().default(600_000).volatile(),
})

/** Read the current plain value behind every reference of a parsed Config. */
function plainConfig(config: Config): ResolvedConfig {
  return Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, isVolatile(value) ? value.get() : value]),
  ) as ResolvedConfig
}

/** Minimal shapes we read off live session objects; never stringify these. */
type LiveMessage = {
  content?: unknown
}

/** Join the text blocks of a live message without copying the whole object. */
function messageText(message: LiveMessage | undefined): string {
  if (message === undefined) return ''
  const content = (message as { content?: unknown }).content
  const blocks = Array.isArray(content) ? content : content === undefined ? [] : [content]
  let out = ''
  for (const block of blocks) {
    const b = block as { type?: unknown, text?: unknown }
    if (b?.type === 'text' && typeof b.text === 'string') out += b.text
  }
  return out
}

/** Wait this long for the descendant sweep before falling back to `taskkill`. */
const KILL_SWEEP_TIMEOUT_MS = 20_000

/** How long to let `whenIdle()` prove it is already resolved before calling a turn live. */
const BUSY_PROBE_MS = 25

/**
 * Is this agent in the middle of a turn?
 *
 * An idle agent's `whenIdle()` is already resolved, so it settles within a
 * microtask; a busy one settles only when its turn ends. One macrotask is
 * therefore enough to tell them apart, and a turn that ends inside the probe is
 * reported idle —the harmless direction, since there was nothing left to stop.
 *
 * @param agent - the live agent handle for a session.
 */
async function agentBusy(agent: { whenIdle?: () => Promise<unknown> }): Promise<boolean> {
  if (typeof agent.whenIdle !== 'function') return true
  let idle = false
  void Promise.resolve(agent.whenIdle()).then(() => { idle = true }, () => { idle = true })
  await new Promise(resolve => { setTimeout(resolve, BUSY_PROBE_MS) })
  return !idle
}

/**
 * Stop a child process and every program it started.
 *
 * Three layers, because each one alone leaves something running:
 *
 * - `child.kill()` reaches only the shell this plugin spawned (powershell/cmd),
 *   not what that shell launched.
 * - `taskkill /PID <pid> /T /F` walks the tree by parent pid, but it kills as it
 *   walks, so a program the command launched **detached** (a `Start-Process`
 *   helper, the usual way to start something long-lived) can be orphaned before
 *   it is enumerated. Measured against a real peer on 2026-10-08: the command
 *   settled as cancelled, and its detached grandchild still wrote its file 20 s
 *   later —the stop looked complete and was not.
 * - So descendants are snapshotted **first**, while the parent still exists, and
 *   that snapshot is what gets killed; `taskkill /T` then only sweeps up.
 *
 * Best effort throughout: a controller asked for a stop, and a refused kill must
 * never turn into an op error.
 *
 * @param child - the shell process this plugin spawned for the command.
 */
export function killTree(child: ChildProcess): void {
  const pid = child.pid
  if (process.platform !== 'win32' || typeof pid !== 'number') {
    try {
      child.kill()
    } catch {
      // Already gone.
    }
    return
  }

  const sweep = (): void => {
    try {
      execFile('taskkill', ['/PID', String(pid), '/T', '/F'], () => { /* best effort */ })
    } catch {
      // Already gone.
    }
  }

  const script = [
    '$all = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId,ParentProcessId',
    `$queue = New-Object System.Collections.Queue; $queue.Enqueue(${pid})`,
    "$seen = New-Object 'System.Collections.Generic.HashSet[int]'",
    '$kill = New-Object System.Collections.ArrayList',
    'while ($queue.Count -gt 0) {',
    '  $cur = $queue.Dequeue()',
    '  foreach ($p in $all) { if ($p.ParentProcessId -eq $cur -and $seen.Add([int]$p.ProcessId)) { $queue.Enqueue([int]$p.ProcessId); [void]$kill.Add([int]$p.ProcessId) } }',
    '}',
    `[void]$kill.Add(${pid})`,
    'foreach ($id in $kill) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }',
    'Write-Output ("stopped " + $kill.Count + " process(es)")',
  ].join('\n')

  try {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { windowsHide: true, timeout: KILL_SWEEP_TIMEOUT_MS },
      () => { sweep() },
    )
  } catch {
    // No sweep process at all: the tree kill is the best that is left.
    sweep()
  }
}

/** One agent handle plus the serial chain that keeps its turns ordered. */
interface SessionState {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handle: any
  tail: Promise<unknown>
  principal: string
  wireId: string
}

/** An authenticated identity; never derived from a request's claimed peer name. */
interface ControllerConnection {
  session: Session
  principal: string
  name: string
  multi: boolean
  signal: AbortSignal
  serverIdentity: string
  authenticatedAt: number
  policy: ControllerPolicy
}

interface ControllerPolicy {
  ceiling: number
  workspaceRoot: string
  allowedOps: readonly string[]
  readRoots: readonly string[]
  expiresAt?: number
  signature: string
}

interface PrincipalResources {
  execs: ExecRegistry
  activeToolCalls: Map<string, AbortController>
  transfers: ReturnType<typeof createTransferServer>
  uploadPaths: Map<string, string>
  generation: AbortController
}

/**
 * Mount the listener.
 *
 * Every field is volatile, so the settings service derives this plugin's page
 * from its own `Config` schema and a committed edit mutates the running
 * references in place —the permission ceiling, audit settings and workspace
 * are re-read per operation. A bind address/port change still needs a rebind,
 * which `loader/volatile-update` supplies by restarting the listener.
 *
 * @param ctx - the plugin's cordis context.
 * @param config - resolved plugin config; the schema supplies every default.
 */
export function apply(ctx: Context, config: Config): void {
  const read = (): ResolvedConfig => plainConfig(config)
  const guard = new NetworkGuard(read)
  const sockets = new Set<Socket>()
  const pendingSockets = new Set<Socket>()
  const principalInFlight = new Map<string, number>()
  let disposed = false

  // Async context is transport-local attribution, never supplied by a caller.
  // Registries outlive sockets: reconnecting with the SAME proven key can stop
  // or continue its work, while another identity sees an independent id space.
  const requests = new AsyncLocalStorage<ControllerConnection>()
  const connection = (): ControllerConnection => {
    const current = requests.getStore()
    if (current === undefined) throw new Error('dsh-remote-server: missing authenticated request context')
    return current
  }
  const principalResources = new Map<string, PrincipalResources>()
  const resources = (): PrincipalResources => {
    const principal = connection().principal
    let owned = principalResources.get(principal)
    if (owned === undefined) {
      owned = {
        execs: new ExecRegistry(),
        activeToolCalls: new Map(),
        transfers: createTransferServer({ read, log: ctx.logger, home: dshHomePath() }),
        uploadPaths: new Map(),
        generation: new AbortController(),
      }
      principalResources.set(principal, owned)
    }
    return owned
  }

  let identity = resolvePrivateKey(read(), 'server.key')
  ctx.logger.info(`dsh-remote-server: identity ${describeIdentity(identity)}`)
  // Print the public half so the operator can hand it to the peer to pin.
  ctx.logger.info(
    `dsh-remote-server: public key (give this to the client)\n${publicToPem(identity.publicKey)}`,
  )

  const states = new Map<string, SessionState>()
  const ensuring = new Map<string, Promise<{ handle: unknown, created: boolean }>>()
  const messageTraces = createMessageTraces(ctx)
  ctx.effect(() => () => messageTraces.close())
  const fullKeyId = (key: Parameters<typeof rawPublic>[0]): string =>
    createHash('sha256').update(rawPublic(key)).digest('hex')

  /** Resolve allowlist eagerly and atomically; a bad entry never restores legacy. */
  const pinnedControllers = (): Array<{ name: string, key: ReturnType<typeof resolvePeerPublicKey>, principal: string }> => {
    const declared = read().authorizedPeers ?? {}
    validatePeerNames(Object.keys(declared))
    const seen = new Set<string>()
    return Object.entries(declared).map(([name, profile]) => {
      if (text(profile.peerPublicKey) === undefined && text(profile.peerPublicKeyFile) === undefined) {
        throw new Error(`authorizedPeers.${name}: a pinned public key or file is required`)
      }
      const key = resolvePeerPublicKey(profile, 'client.pub')
      const principal = fullKeyId(key)
      if (seen.has(principal)) throw new Error('authorizedPeers: each public key must identify exactly one peer')
      seen.add(principal)
      return { name, key, principal }
    })
  }
  pinnedControllers()

  /** Re-read the principal policy on every request and before queued side effects. */
  const policyFor = (controller: ControllerConnection): ControllerPolicy => {
    const current = read()
    if (disposed || controller.serverIdentity !== fullKeyId(identity.publicKey)
      ) {
      throw new FsError('authenticated connection expired or server identity changed', 'FS_PERMISSION_DENIED')
    }
    const pinned = pinnedControllers()
    let ceiling = normalizePermission(current.maxPermission)
    let workspaceRoot = text(current.workspace) ?? ''
    let allowedOps: readonly string[] = []
    let readRoots: readonly string[] = current.readRoots ?? []
    let expiresAt: number | undefined
    if (controller.multi) {
      const match = pinned.find(peer => peer.principal === controller.principal)
      if (match === undefined || match.name !== controller.name) throw new FsError('controller key or named identity is no longer authorized', 'FS_PERMISSION_DENIED')
      const profile = current.authorizedPeers[match.name] as AuthorizedPeer
      if (profile.disabled === true) throw new FsError('controller key is disabled', 'FS_PERMISSION_DENIED')
      expiresAt = expirationTime(profile.validUntil)
      if (expiresAt !== undefined && expiresAt <= Date.now()) throw new FsError('controller key has expired', 'FS_PERMISSION_DENIED')
      ceiling = Math.min(ceiling, normalizePermission(profile.maxPermission))
      workspaceRoot = text(profile.workspaceRoot) ?? ''
      allowedOps = allowedOperations(profile.allowedOps)
      readRoots = profile.readRoots ?? []
    } else if (pinned.length !== 0 || fullKeyId(resolvePeerPublicKey(current, 'client.pub')) !== controller.principal) {
      throw new FsError('legacy controller key is no longer authorized', 'FS_PERMISSION_DENIED')
    }
    if (!Array.isArray(readRoots) || readRoots.length > 32 || readRoots.some(root => typeof root !== 'string'
      || root.length > 4096 || /[\u0000-\u001f\u007f]/.test(root) || !isAbsolute(root))) {
      throw new FsError('readRoots must contain at most 32 absolute paths of at most 4096 characters', 'FS_PERMISSION_DENIED')
    }
    return { ceiling, workspaceRoot, allowedOps, readRoots, ...(expiresAt === undefined ? {} : { expiresAt }),
      signature: JSON.stringify([ceiling, workspaceRoot, allowedOps, readRoots, expiresAt ?? null, current.capabilities, current.deniedTools,
        current.relayEnabled, controller.multi ? current.authorizedPeers[controller.name]?.relayTargets : []]) }
  }
  const assertControllerOperation = (controller: ControllerConnection, op: string): ControllerPolicy => {
    const policy = policyFor(controller)
    assertPeerOperation(policy.ceiling, op, { peer: controller.name })
    if (policy.allowedOps.length !== 0 && !policy.allowedOps.includes(op)) {
      throw new FsError(`operation ${JSON.stringify(op)} is not in this controller's allowedOps`, 'FS_PERMISSION_DENIED')
    }
    return policy
  }

  const relayHub = new RelayHub({
    authorize: (owner, op) => {
      const controller = owner as ControllerConnection
      if (controller.signal.aborted) throw new FsError('mesh connection closed', 'FS_PERMISSION_DENIED')
      assertControllerOperation(controller, op)
      if (read().relayEnabled !== true || !controller.multi) throw new FsError('mesh forwarding requires relayEnabled and a named pinned identity', 'FS_PERMISSION_DENIED')
      const profile = read().authorizedPeers[controller.name]
      if (profile === undefined) throw new FsError('mesh identity is no longer authorized', 'FS_PERMISSION_DENIED')
      return { targets: profile.relayTargets ?? [] }
    },
  })

  const scopedSessionId = (wireId: string): string => {
    const controller = connection()
    if (!controller.multi) return wireId
    // The separator is unambiguous and the whole fingerprint is retained. The
    // wire id remains reversible for session discovery after a process restart.
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(wireId)) {
      throw new FsError('invalid remote session id', 'FS_PERMISSION_DENIED')
    }
    return `remote-${controller.principal}-${wireId}`
  }
  const wireSessionId = (id: string, controller = connection()): string | undefined => {
    if (!controller.multi) {
      const known = states.get(id)
      return known === undefined || known.principal === controller.principal ? id : undefined
    }
    const prefix = `remote-${controller.principal}-`
    return id.startsWith(prefix) ? id.slice(prefix.length) : undefined
  }
  const ownState = (wireId: string): SessionState | undefined => {
    const state = states.get(scopedSessionId(wireId))
    return state?.principal === connection().principal ? state : undefined
  }

  /** Server-side level-2 checks use native canonical paths, not lexical aliases. */
  const fencedPath = async (path: string, root: string): Promise<string> => {
    const denied = (): never => { throw new FsError('write is outside the declared workspace root', 'FS_PERMISSION_DENIED') }
    if (root === '' || !isAbsolute(root) || !isAbsolute(path) || /[\u0000-\u001f]/.test(path)) return denied()
    // Reject traversal/ADS/device spellings even if a later normalizer could
    // collapse them. They must never turn an apparently confined write outside.
    if (root.length > 4096 || path.length > 4096 || /[\u0000-\u001f\u007f]/.test(root)
      || path.replace(/\\/g, '/').split('/').some(part => part === '..')) return denied()
    if (process.platform === 'win32' && (/^[\\/]{2}/.test(path) || path.slice(2).includes(':')
      || path.replace(/\\/g, '/').split('/').slice(1).some(part => /[. ]$/.test(part)
        || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(part)))) return denied()
    const under = (child: string, parent: string): boolean => {
      const diff = relative(parent, child)
      return diff === '' || (!isAbsolute(diff) && diff !== '..' && !diff.startsWith(`..${sep}`))
    }
    const absoluteRoot = resolve(root)
    const target = resolve(path)
    if (!under(target, absoluteRoot)) return denied()
    const canonicalRoot = await realpath(absoluteRoot)
    let ancestor = target
    for (;;) {
      try {
        const canonical = await realpath(ancestor)
        if (!under(canonical, canonicalRoot)) return denied()
        return target
      } catch (error) {
        const code = (error as { code?: unknown }).code
        if (code !== 'ENOENT') throw error
        const parent = dirname(ancestor)
        if (parent === ancestor) return denied()
        ancestor = parent
      }
    }
  }

  /** Live controller connections, so a question can be relayed to one of them. */
  const controllers = new Map<Session, ControllerConnection>()
  const principalPolicies = new Map<string, ControllerConnection>()
  const cancelPrincipal = (principal: string, reason: Error): void => {
    relayHub.revoke(principal)
    const owned = principalResources.get(principal)
    if (owned !== undefined) {
      owned.generation.abort(reason)
      owned.execs.cancelAll()
      for (const call of owned.activeToolCalls.values()) call.abort(reason)
      owned.transfers.dispose()
      owned.uploadPaths.clear()
      principalResources.delete(principal)
    }
    for (const [localId, state] of states) {
      if (state.principal !== principal) continue
      stopRequested.set(localId, Date.now())
      try { state.handle?.agent?.cancel({ kind: 'hook', reason: reason.message }) } catch { /* best effort */ }
    }
    for (const controller of controllers.values()) {
      if (controller.principal === principal) controller.session.close()
    }
  }
  const enforcePolicies = (): void => {
    const cancelled = new Set<string>()
    for (const controller of principalPolicies.values()) {
      if (cancelled.has(controller.principal)) continue
      try {
        const next = policyFor(controller)
        if (next.signature !== controller.policy.signature) throw new Error('controller policy changed; reconnect required')
      } catch (error) {
        cancelled.add(controller.principal)
        principalPolicies.delete(controller.principal)
        cancelPrincipal(controller.principal, error instanceof Error ? error : new Error(String(error)))
      }
    }
  }
  /** Questions already handed to a controller and still awaiting its answer. */
  const relayed = new Map<string, {
    controller: Session
    resolve: (answer: unknown) => void
    reject: (error: Error) => void
  }>()

  /**
   * Message ids THIS half injected, per session.
   *
   * The whole "is this a human on the controlled machine, or our own prompt?"
   * distinction survives older messages that used kind:user; new inputs carry
   * kind:dsh-remote plus a durable traceId and never impersonate a local human.
   */
  const injected = new Map<string, Set<string>>()

  /** Ids above are only ever checked for membership; a bounded window is plenty. */
  const REMEMBERED_INJECTIONS = 64

  /** Remember one of OUR input message ids, bounded; used by the event feed. */
  const rememberInjection = (localId: string, messageId: string): void => {
    let known = injected.get(localId)
    if (known === undefined) {
      known = new Set<string>()
      injected.set(localId, known)
    }
    known.add(messageId)
    while (known.size > REMEMBERED_INJECTIONS) {
      const oldest = known.values().next()
      if (oldest.done === true) break
      known.delete(oldest.value)
    }
  }

  /**
   * External input ids handed to super-agent-io that this half is still waiting
   * to see committed. The IO source carries `externalMessageId`, so an early
   * `session/event` can be recognized before the receipt returns.
   */
  const pendingIoInputs = new Set<string>()
  const rememberIoInput = (externalMessageId: string): void => {
    pendingIoInputs.add(externalMessageId)
    while (pendingIoInputs.size > REMEMBERED_INJECTIONS) {
      const oldest = pendingIoInputs.values().next()
      if (oldest.done === true) break
      pendingIoInputs.delete(oldest.value)
    }
  }

  /**
   * Cancels this half asked for, per session, with when.
   *
   * The controller's `agent.interrupt` and a human pressing stop on this machine
   * produce the SAME `turn/end` reason (`{kind:'aborted', reason:{kind:'user'}}`),
   * so the only way not to tell a controller it interrupted itself is to remember
   * having asked.
   */
  const selfInterrupted = new Map<string, number>()

  /** Ids above are only ever checked for membership; a bounded window is plenty. */
  const SELF_INTERRUPT_TTL_MS = 60_000

  /**
   * Stops a controller asked for that no running turn has consumed yet.
   *
   * `agent.cancel()` is a documented no-op on an idle agent, and a controller's
   * stop can easily arrive in the window before a parked prompt starts its work
   * (measured: a stop 6 s into a 60 s command did nothing, because the turn had
   * not begun —the whole command then ran to completion). Latching the stop for
   * a bounded moment lets the prompt refuse to start instead of working for
   * nobody. The timestamp keeps a stale latch from swallowing a LATER prompt.
   */
  const stopRequested = new Map<string, number>()
  const STOP_LATCH_TTL_MS = 30_000

  /** True when a fresh stop is latched for this session, consuming it. */
  const consumeStop = (sessionId: string): boolean => {
    const askedAt = stopRequested.get(sessionId)
    if (askedAt === undefined) return false
    stopRequested.delete(sessionId)
    return Date.now() - askedAt < STOP_LATCH_TTL_MS
  }

  /** Session pushes can only reach connections authenticated as its owner. */
  const pushToControllers = (frame: Record<string, unknown>): void => {
    const localId = String(frame.sessionId ?? '')
    const state = states.get(localId)
    if (state === undefined) return
    for (const controller of controllers.values()) {
      if (controller.principal !== state.principal) continue
      try { policyFor(controller) } catch { continue }
      void controller.session.send({ ...frame, sessionId: state.wireId }).catch((error: unknown) => {
        ctx.logger.debug(`dsh-remote-server: could not push ${String(frame.kind ?? '?')}: ${String(error)}`)
      })
    }
  }

  /**
   * Hand one committed IO reply to every live controller of its principal.
   *
   * IO calls the transport once per real `assistant/message`; awaiting the link
   * sends preserves that order. `delivered` means at least one authenticated
   * controller accepted the frame, `failed` means none was connected (definite
   * no transmission), and `unknown` means a send may have raced a disconnect.
   */
  const deliverIoReply = async (
    binding: IoBinding,
    delivery: { deliveryId: string, traceIds?: readonly string[] },
    reply: RemoteReply,
  ): Promise<'delivered' | 'failed' | 'unknown'> => {
    // IO speaks the scoped local Session id; the controller only knows the wire
    // id. The public reply exposed here must use the same identity as the final
    // `replies` array, otherwise the client cannot dedupe the two channels.
    const wireReply: RemoteReply = { ...reply, sessionId: binding.wireId }
    let sent = 0
    let uncertain = false
    for (const controller of controllers.values()) {
      if (controller.principal !== binding.principal) continue
      try { policyFor(controller) } catch { continue }
      try {
        await controller.session.send({
          kind: 'assistant.reply',
          sessionId: binding.wireId,
          deliveryId: delivery.deliveryId,
          reply: wireReply,
          ...(delivery.traceIds === undefined || delivery.traceIds.length === 0 ? {} : { traceIds: delivery.traceIds }),
        })
        sent += 1
      } catch (error) {
        uncertain = true
        ctx.logger.debug(`dsh-remote-server: could not push an IO reply: ${String(error)}`)
      }
    }
    if (sent > 0) return 'delivered'
    return uncertain ? 'unknown' : 'failed'
  }

  const ioBridge = createRemoteIoBridge(ctx, {
    enabled: () => read().superAgentIo === true,
    log: (message, level) => {
      try {
        if (level === 'warn') ctx.logger.warn(message)
        else if (level === 'debug') ctx.logger.debug(message)
        else ctx.logger.info(message)
      } catch {
        // A hot-reload context may already be inactive; logging must not break
        // transport registration or the input fallback.
      }
    },
    deliver: (binding, delivery, reply) => deliverIoReply(binding, delivery, reply),
  })
  try {
    ctx.effect(() => () => ioBridge.dispose(), 'dsh-remote-server: super-agent-io bridge')
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register super-agent-io teardown (${String(error)})`)
  }

  /**
   * Admit one controller input through IO when it is enabled and usable.
   *
   * `unavailable` is deliberately narrow: only a definite pre-send refusal may
   * fall back to the original direct injection. `unknown` may already have been
   * admitted and must never be replayed by the caller.
   */
  const admitViaIo = async (request: {
    principal: string
    localId: string
    wireId: string
    text: string
    mode: 'queue' | 'steer' | 'auto'
    externalMessageId: string
  }): Promise<IoReceiveOutcome> => {
    if (read().superAgentIo !== true) return { kind: 'unavailable', reason: 'super-agent-io integration is disabled' }
    if (request.text.trim() === '') return { kind: 'unavailable', reason: 'empty input' }
    rememberIoInput(request.externalMessageId)
    const binding = await ioBridge.ensureBinding(request.principal, request.localId, request.wireId, `dsh-remote ${request.wireId}`)
    if (binding === undefined) {
      pendingIoInputs.delete(request.externalMessageId)
      return { kind: 'unavailable', reason: 'super-agent-io binding is unavailable' }
    }
    const outcome = await ioBridge.receive(binding, {
      text: request.text,
      mode: request.mode,
      externalMessageId: request.externalMessageId,
    })
    if (outcome.kind === 'unavailable') {
      pendingIoInputs.delete(request.externalMessageId)
      if (read().superAgentIo === true) {
        try {
          ctx.logger.debug(`dsh-remote-server: super-agent-io admission unavailable; using the ordinary path (${outcome.reason})`)
        } catch {
          // Inactive hot-reload context; the fallback itself must still run.
        }
      }
    }
    return outcome
  }

  /**
   * Tell the controller its catalog may be stale, without shipping the catalog.
   *
   * The tool registry emits `tools/change` for every registration change (a
   * plugin toggled, a preset recomposed, an MCP server connected). Debounced
   * because one catalog-changing operation often emits several, and coalesced
   * into one frame because the controller refetches with `caps.list` anyway —   * pushing the whole catalog would be redundant bytes on a tunnel.
   */
  let capsPushTimer: ReturnType<typeof setTimeout> | undefined
  const pushCapsChanged = (): void => {
    if (read().capabilities === false) return
    if (capsPushTimer !== undefined) clearTimeout(capsPushTimer)
    capsPushTimer = setTimeout(() => {
      capsPushTimer = undefined
      const frame = { kind: 'caps.changed', build: BUILD }
      // Every live controller, not just the newest: a worker-pool link and the
      // primary link each mirror the surface, and one of them being stale is
      // exactly the bug this push exists to prevent.
      for (const controller of controllers.values()) {
        try { policyFor(controller) } catch { continue }
        void controller.session.send(frame).catch((error: unknown) => {
          ctx.logger.debug(`dsh-remote-server: could not push caps.changed: ${String(error)}`)
        })
      }
    }, 800)
    capsPushTimer.unref?.()
  }
  try {
    ctx.on('tools/change', pushCapsChanged)
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not watch tools/change (${String(error)})`)
  }

  /**
   * Report the two things a controller must not have to guess.
   *
   * Read from the session's own committed log rather than inferred from timing,
   * because that log is the durable truth about what happened on this machine:
   *
   *  * a turn was cancelled —most importantly by THIS machine's user, which the
   *    controller has to hear about rather than silently continuing;
   *  * a human typed into a conversation a controller is driving.
   *
   * Both are filtered to sessions this half owns, and the whole body is
   * quarantined: a listener must never disturb the append it observes.
   */
  ctx.on('session/event', (session, event) => {
    const sessionId = String((session as { id?: unknown }).id ?? '')
    if (sessionId === '' || !states.has(sessionId)) return
    try {
      // The journal takes the observed shape first: one line per turn end, model
      // reply, or human message —the context an agent should read, not the raw
      // event payload.
      const shaped = summarizeEvent(event.type, event.data)
      if (shaped !== undefined) {
        const state = states.get(sessionId) as SessionState
        record({
          kind: shaped.kind,
          summary: shaped.summary,
          sessionId: state.wireId,
          detail: { ...shaped.detail, principal: state.principal },
        })
      }
      if (event.type === 'turn/end') {
        const why = (event.data as { reason?: { kind?: string, reason?: { kind?: string } } }).reason
        if (why?.kind !== 'aborted') return
        const cause = typeof why.reason?.kind === 'string' ? why.reason.kind : 'legacy'
        const askedAt = selfInterrupted.get(sessionId)
        if (askedAt !== undefined && Date.now() - askedAt < SELF_INTERRUPT_TTL_MS) {
          selfInterrupted.delete(sessionId)
          // The running turn consumed the stop it was for; the latch must not
          // survive to cancel some later prompt.
          stopRequested.delete(sessionId)
          // Tell the controller what it already knows; useful as an ack, and it
          // keeps the client from reading its own cancellation as a remote stop.
          pushToControllers({ kind: 'interrupt', sessionId, cause, origin: 'controller' })
          return
        }
        selfInterrupted.delete(sessionId)
        pushToControllers({ kind: 'interrupt', sessionId, cause, origin: 'remote-user', at: Date.now() })
        return
      }
      if (event.type !== 'user/message') return
      // For `user/message` the event data IS the message (no `{ message }` wrapper).
      const message = event.data as {
        id?: unknown
        content?: unknown
        source?: { kind?: unknown, rpcId?: unknown, externalMessageId?: unknown, transport?: unknown }
      }
      const id = String(message.id ?? '')
      if (message.source?.kind === 'dsh-remote') {
        const state = states.get(sessionId) as SessionState
        void messageTraces.anchor(state.principal, sessionId, id, event.seq, event.time).catch(error => {
          ctx.logger.warn(`dsh-remote-server: input trace could not be anchored: ${String(error)}`)
        })
        return
      }
      if (message.source?.kind === 'super-agent-io') {
        // Our own IO transport means this came from a controller, never a local
        // human. The external id closes the commit-before-receipt race; the
        // transport id also covers a receipt whose id was evicted.
        const externalId = typeof message.source.externalMessageId === 'string' ? message.source.externalMessageId : ''
        if (message.source.transport === 'dsh-remote' || (externalId !== '' && pendingIoInputs.has(externalId))) {
          if (id !== '') rememberInjection(sessionId, id)
          return
        }
      }
      if (id !== '' && injected.get(sessionId)?.has(id) === true) return
      const body = messageText(message as LiveMessage)
      if (body === '') return
      // The shipped Web UI stamps its request id as `rpcId`, which our own
      // injection can never carry; a bare `{kind:'user'}` without one is some
      // other program's message, reported as such instead of as a human.
      pushToControllers({
        kind: 'note',
        sessionId,
        human: message.source?.kind === 'user' && typeof message.source.rpcId === 'string',
        text: body.slice(0, 2000),
        at: Date.now(),
      })
    } catch (error) {
      ctx.logger.debug(`dsh-remote-server: session/event handling failed: ${String(error)}`)
    }
  }, { global: true })

  /**
   * How long a relayed question stays open before this half gives up.
   *
   * Generous on purpose: the controller's agent may have to consult its own user
   * before it can answer, and a human is not a 120-second operation.
   */
  const QUESTION_RELAY_TIMEOUT_MS = 30 * 60_000

  /** The session this server owns whose agent is the one asking, if any. */
  const sessionIdOfAgent = (agent: unknown): string | undefined => {
    for (const [sessionId, state] of states) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if ((state.handle as any)?.agent === agent) return sessionId
    }
    return undefined
  }

  /**
   * Relay `ask_user_question` to the controller for review.
   *
   * A session driven from the other machine asks through the same seam every
   * other UI uses. This half claims those requests and forwards them, so the
   * question is never rendered on this machine: the controller's agent reviews
   * it and either answers directly or asks its own user. A request from a session
   * this server does not own is delegated to `next()`, leaving this machine's own
   * UI untouched.
   */
  ctx.on('user-questions/request', async (request, next) => {
    const agent = (request as { agent?: unknown }).agent
    const sessionId = agent === undefined ? undefined : sessionIdOfAgent(agent)
    if (sessionId === undefined) return next()
    const state = states.get(sessionId) as SessionState
    const controller = [...controllers.values()].reverse().find(candidate => {
      if (candidate.principal !== state.principal) return false
      try { return policyFor(candidate).ceiling >= 3 } catch { return false }
    })?.session
    if (controller === undefined) return next()

    const qid = randomUUID()
    const answer = await new Promise<unknown>((resolve, reject) => {
      const finish = (settle: () => void): void => {
        clearTimeout(timer)
        request.signal?.removeEventListener('abort', onAbort)
        settle()
      }
      const onAbort = (): void => {
        relayed.delete(qid)
        finish(() => { reject(new Error('dsh-remote-server: the relayed question was aborted')) })
      }
      const timer = setTimeout(() => {
        relayed.delete(qid)
        finish(() => { reject(new Error('dsh-remote-server: the controller did not answer the relayed question')) })
      }, QUESTION_RELAY_TIMEOUT_MS)
      timer.unref?.()
      relayed.set(qid, {
        controller,
        resolve: (value) => { finish(() => { resolve(value) }) },
        reject: (error) => { finish(() => { reject(error) }) },
      })
      if (request.signal?.aborted === true) { onAbort(); return }
      request.signal?.addEventListener('abort', onAbort, { once: true })
      void controller.send({ kind: 'ask', qid, sessionId: state.wireId, questions: request.questions })
        .catch((error: unknown) => {
          const pending = relayed.get(qid)
          if (pending === undefined) return
          relayed.delete(qid)
          finish(() => { reject(error instanceof Error ? error : new Error(String(error))) })
        })
    })
    return answer as AskUserQuestionAnswer
    // `prepend` is load-bearing: this waterfall is ALSO projected to connected
    // clients by the remotes bridge, and a waterfall stops at the first listener
    // that returns a value. Without running first, this machine's own UI would
    // project the question and render a panel for a question the controller is
    // about to be asked instead —which is exactly what must not happen.
  }, { global: true, prepend: true })

  /** Append an audit record; never let logging break a request. */
  const audit = (peer: string, op: string, ok: boolean, extra?: Record<string, unknown>): void => {
    if (read().audit === false) return
    try {
      const file = read().auditFile ?? dshHomePath('dsh-remote', 'server-audit.log')
      mkdirSync(dirname(file), { recursive: true })
      appendFileSync(
        file,
        `${JSON.stringify({ ts: new Date().toISOString(), peer, op, ok, ...(extra ?? {}) })}\n`,
        'utf8',
      )
    } catch {
      // auditing is best effort
    }
  }

  /**
   * The trajectory journal: what this half did, and what it saw.
   *
   * Deliberately NOT a model-facing conversation: entries are appended by this
   * plugin as operations happen, so the record costs storage and nothing else.
   * Every append goes through {@link record}, which is best effort —recording
   * must never break the work it records.
   */
  const journal = new Journal({
    file: read().journalFile ?? dshHomePath('dsh-remote', 'journal.jsonl'),
  })
  journal.load()
  const record = (entry: Parameters<Journal['append']>[0]): void => {
    if (read().journal === false) return
    try {
      journal.append(entry)
    } catch {
      // The journal is a record, not a dependency.
    }
  }
  record({
    kind: 'note',
    summary: `server half started (build ${BUILD}); port ${read().port ?? 0}, workspace ${text(read().workspace) ?? process.cwd()}`,
  })


  /** Resolve or create an agent for a session id, reusing a live handle. */
  const ensureAgent = async (
    sessionId: string,
    presetId?: string,
    workspace?: string,
  ): Promise<{ handle: unknown, created: boolean }> => {
    const controller = connection()
    const generation = resources().generation.signal
    generation.throwIfAborted()
    const wireId = sessionId
    sessionId = scopedSessionId(wireId)
    const existing = states.get(sessionId)
    if (existing !== undefined) {
      if (existing.principal !== controller.principal) throw new FsError('session belongs to another controller', 'FS_PERMISSION_DENIED')
      return { handle: existing.handle, created: false }
    }
    const pending = ensuring.get(sessionId)
    if (pending !== undefined) {
      const resolved = await pending
      if (states.get(sessionId)?.principal !== controller.principal) {
        throw new FsError('session belongs to another controller', 'FS_PERMISSION_DENIED')
      }
      return resolved
    }
    const creating = Promise.resolve().then(async (): Promise<{ handle: unknown, created: boolean }> => {
    const agents = ctx.get('agents')
    const presets = ctx.get('agentPresets')
    if (agents === undefined) throw new Error('dsh-remote-server: the `agents` service is unavailable')

    const wantedPreset = text(presetId) ?? text(read().defaultPreset)
    const defaults = ctx.get('agentDefaultModel')?.currentSelection()
    const setup = async (agentCtx: Context): Promise<void> => {
      // Default route is supplied through agentOptions; this official listener
      // records route changes while persisted selections retain precedence.
      installModelSelection(agentCtx)
      // Tell the driven agent what it is: a task/subagent of a remote controller,
      // on a machine where a human may be watching and may speak at any moment.
      // Registered on the AGENT's ctx —scoping is positional, so this reaches
      // exactly this session and never leaks into this machine's own chats.
      if (read().promptGuidance !== false) {
        try {
          agentCtx.systemPrompt.section({
            name: 'dsh-remote:controlled',
            // Free slot before the first-party tool guidance (900/1000 are taken).
            order: 960,
            text: CONTROLLED_GUIDANCE,
          })
        } catch (error) {
          ctx.logger.debug(`dsh-remote-server: prompt guidance skipped: ${String(error)}`)
        }
      }
      if (presets === undefined) return
      const preset = await presets.resolve(wantedPreset)
      await presets.mount(agentCtx, preset.id)
    }

    // Resolve the directory through the workspace registry: `create()` is
    // create-or-get and yields the canonical path, plus the handle we need to
    // attach the session afterwards. A session made with `agents.create`
    // alone is durable but unowned, and an unowned session never shows up in
    // the GUI sidebar.
    const requested = text(workspace) ?? text(read().workspace) ?? process.cwd()
    const registry = ctx.get('workspaceRegistry')
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let owner: any
    if (registry !== undefined) {
      try {
        owner = await registry.create(requested)
      } catch (error) {
        ctx.logger.warn(`dsh-remote-server: workspace registry refused ${requested}: ${String(error)}`)
      }
    }
    const cwd: string = typeof owner?.path === 'string' ? owner.path : requested

    let handle: unknown
    let created = false
    try {
      policyFor(controller)
      generation.throwIfAborted()
      handle = await agents.resume({ resumeSessionId: SessionId(sessionId), setup, signal: generation,
        ...(defaults === undefined ? {} : { agentOptions: defaults }),
      })
    } catch (error) {
      generation.throwIfAborted()
      policyFor(controller)
      // Remote-owned cold sessions need this setup and caller lifetime. The ordinary
      // sessionController.resolveAgent API accepts neither; it must not silently
      // replace this principal-scoped lifecycle or preset/model composition.
      if (!isDefiniteSessionNotFound(error, sessionId)) throw error
      ctx.logger.debug(`dsh-remote-server: session ${sessionId} definitely absent; creating`)
      const preset = presets === undefined ? undefined : await presets.resolve(wantedPreset)
      handle = await agents.create({
        sessionId: SessionId(sessionId),
        signal: generation,
        ...(defaults === undefined ? {} : { agentOptions: defaults }),
        meta: {
          cwd,
          ...(preset === undefined ? {} : { agentPreset: preset.id }),
        },
        setup,
      })
      created = true
      // Claim the session for the workspace, and give it a findable title.
      try {
        await owner?.attachSession(SessionId(sessionId))
      } catch (attachError) {
        ctx.logger.warn(`dsh-remote-server: attachSession failed: ${String(attachError)}`)
      }
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const session = (handle as any).agent.session
        ctx.get('sessionTitle')?.rename(session, `remote: ${sessionId}`)
      } catch (titleError) {
        ctx.logger.debug(`dsh-remote-server: title rename skipped: ${String(titleError)}`)
      }
    }
    if (generation.aborted) {
      try { (handle as { agent?: { cancel(cause: unknown): void } }).agent?.cancel({ kind: 'hook', reason: 'controller authorization revoked' }) } catch { /* best effort */ }
      generation.throwIfAborted()
    }
    policyFor(controller)
    states.set(sessionId, { handle, tail: Promise.resolve(), principal: controller.principal, wireId })
    return { handle, created }
    })
    ensuring.set(sessionId, creating)
    try {
      return await creating
    } finally {
      if (ensuring.get(sessionId) === creating) ensuring.delete(sessionId)
    }
  }

  /** Run one prompt on a session, serialized against that session's own chain. */
  const prompt = async (
    sessionId: string,
    promptText: string,
    timeoutMs: number,
    presetId?: string,
    workspace?: string,
  ): Promise<Record<string, unknown>> => {
    const generation = resources().generation.signal
    const { handle, created } = await ensureAgent(sessionId, presetId, workspace)
    const localId = scopedSessionId(sessionId)
    const state = ownState(sessionId) as SessionState
    const resumeOf = state.tail
    let release: () => void = () => {}
    state.tail = new Promise<void>(resolve => { release = resolve })

    await withAuthorization(resumeOf, generation)
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const agent = (handle as any).agent
      const sessions = ctx.get('sessions')
      const startedAt = Date.now()
      await withAuthorization(agent.whenIdle(), generation)
      // A stop that arrived before this prompt started its work: honour it by NOT
      // starting. `cancel()` cannot help here (idle agent = no-op), and running
      // the work anyway is exactly what "interrupt" must not do.
      if (consumeStop(localId)) {
        return {
          sessionId,
          created,
          reply: '',
          replies: [],
          replyFormat: 'committed-assistant-v1',
          reason: 'aborted',
          error: null,
          interrupted: true,
          interruptCause: 'user',
          seq: agent.session.seq,
          durationMs: Date.now() - startedAt,
        }
      }
      // A queued prompt may outlive a settings change; authorize at the actual
      // point of injection as well as when its request entered the dispatcher.
      generation.throwIfAborted()
      assertControllerOperation(connection(), 'agent.prompt')
      const principal = connection().principal
      const firstSeq: number = agent.session.seq
      const ioAdmission = await admitViaIo({
        principal,
        localId,
        wireId: sessionId,
        text: promptText,
        mode: 'queue',
        externalMessageId: randomUUID(),
      })
      if (ioAdmission.kind === 'unknown') {
        // IO may already have admitted this input. Falling back would inject a
        // second copy; the controller is told not to resend instead.
        throw new Error(`dsh-remote-server: super-agent-io admission outcome is unknown; do not resend (${ioAdmission.reason})`)
      }
      let inputMessageId: string
      let inputTraceId: string
      let inputTransport: 'super-agent-io' | 'dsh-remote'
      if (ioAdmission.kind === 'accepted') {
        inputMessageId = ioAdmission.receipt.messageId
        inputTraceId = ioAdmission.receipt.traceId
        inputTransport = 'super-agent-io'
        rememberInjection(localId, inputMessageId)
      } else {
        const message = createUserMessage({
          content: [{ type: 'text', text: promptText }],
          source: { kind: 'dsh-remote', version: 1, principal,
            remoteSessionId: sessionId, operation: 'agent.prompt', traceId: randomUUID() },
        })
        inputMessageId = String(message.id)
        inputTraceId = message.source.traceId
        inputTransport = 'dsh-remote'
        // Remember OUR message id: it is what later tells this half's own prompt
        // apart from a human typing into the same conversation.
        rememberInjection(localId, inputMessageId)
        await admitTracked(await messageTraces.store(), {
          version: 1, traceId: message.source.traceId, principal,
          sessionId: localId, remoteSessionId: sessionId, messageId: inputMessageId, seq: null,
          time: Date.now(), operation: 'agent.prompt', requestedMode: 'queue', mode: 'queue', state: 'admitting',
        }, () => {
          generation.throwIfAborted()
          assertControllerOperation(connection(), 'agent.prompt')
          agent.followup(message)
        })
      }
      if (timeoutMs > 0) {
        await Promise.race([
          withAuthorization(agent.whenIdle(), generation),
          new Promise((_resolve, reject) => {
            const timer = setTimeout(() => reject(new Error(`prompt timed out after ${timeoutMs} ms`)), timeoutMs)
            timer.unref?.()
          }),
        ])
      } else {
        await withAuthorization(agent.whenIdle(), generation)
      }
      if (sessions !== undefined) await sessions.flush(agent.session)

      const events: readonly SessionEvent[] = agent.session.snapshotEvents()
      const outcome = summarizeReplies(events, firstSeq, sessionId)
      const input = events.find(event => event.type === 'user/message' && event.data.id === inputMessageId)
      if (input !== undefined && inputTransport === 'dsh-remote') {
        await messageTraces.anchor(principal, localId, inputMessageId, input.seq, input.time)
      }
      return {
        sessionId,
        created,
        reply: outcome.text,
        input: { messageId: inputMessageId, traceId: inputTraceId, seq: input?.seq ?? null, transport: inputTransport },
        replies: outcome.replies,
        replyFormat: outcome.replyFormat,
        reason: outcome.reason,
        error: outcome.error,
        // A cancelled turn is not a reply: say so, and say who cancelled it, so
        // the controller stops instead of reading an empty answer as a result.
        ...(outcome.interruptCause === null
          ? {}
          : { interrupted: true, interruptCause: outcome.interruptCause }),
        seq: agent.session.seq,
        durationMs: Date.now() - startedAt,
      }
    } finally {
      release()
    }
  }

  /**
   * Decode a child process's output without guessing wrong.
   *
   * Windows mixes encodings: PowerShell's own cmdlets emit .NET strings in the
   * console encoding, while native tools (`whoami.exe`, `ipconfig.exe`, —write
   * bytes in the ANSI/OEM code page. Decoding both as UTF-8 turns the native half
   * into U+FFFD. So: strict UTF-8 first, then the Chinese ANSI code page, then a
   * lossy fallback. (The raw bytes are still available to the caller if needed.)
   *
   * @param buf - raw bytes from the child.
   * @returns the best-effort text.
   */
  const decodeOutput = (buf: Buffer): string => {
    if (buf.length === 0) return ''
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(buf)
    } catch {
      // Not valid UTF-8 —almost always a native tool writing GBK/ANSI.
    }
    for (const encoding of ['gbk', 'big5', 'shift_jis', 'windows-1252']) {
      try {
        return new TextDecoder(encoding).decode(buf)
      } catch {
        // TextDecoder lacks this encoding (Node built without full ICU); try next.
      }
    }
    return buf.toString('utf8')
  }

  /** Execute a shell command and capture both streams. */
  const exec = (
    command: string,
    shell: string,
    timeoutMs: number,
    cwd?: string,
    execId?: string,
  ): Promise<Record<string, unknown>> => new Promise((resolve, reject) => {
    const execs = resources().execs
    if (execId !== undefined && execs.has(execId)) { reject(new Error('execId is already running')); return }
    const cap = read().maxExecTimeoutMs ?? 600_000
    const limit = Math.min(timeoutMs > 0 ? timeoutMs : 120_000, cap)
    const argv = shell === 'cmd'
      ? ['cmd', '/c', command]
      : ['powershell', '-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference='Continue';${command}`]
    const startedAt = Date.now()
    // A stop has to be distinguishable from the timeout below: both surface as a
    // killed child, and only one of them is the user's own doing.
    let cancelled = false
    let release: () => void = () => {}
    const child = execFile(
      argv[0] as string,
      argv.slice(1),
      {
        timeout: limit,
        cwd: text(cwd) ?? undefined,
        windowsHide: true,
        maxBuffer: 64 * 1024 * 1024,
        // Capture raw bytes: the decoder above needs to see them undamaged.
        encoding: 'buffer',
      },
      (error, stdoutRaw, stderrRaw) => {
        release()
        const stdout = decodeOutput(stdoutRaw as unknown as Buffer)
        const stderr = decodeOutput(stderrRaw as unknown as Buffer)
        const killed = error !== null && (error as { killed?: boolean }).killed === true
        if (cancelled || (killed && cancelled)) {
          resolve({
            exit: null,
            timedOut: false,
            cancelled: true,
            stdout,
            stderr: `${stderr}\n[dsh-remote] stopped by the controller`,
            durationMs: Date.now() - startedAt,
          })
          return
        }
        if (killed) {
          resolve({
            exit: null,
            timedOut: true,
            stdout,
            stderr: `${stderr}\n[dsh-remote] timed out after ${limit} ms`,
            durationMs: Date.now() - startedAt,
          })
          return
        }
        if (error !== null && typeof (error as { code?: unknown }).code !== 'number') {
          reject(error)
          return
        }
        resolve({
          exit: error === null ? 0 : ((error as { code?: number }).code ?? null),
          timedOut: false,
          stdout,
          stderr,
          durationMs: Date.now() - startedAt,
        })
      },
    )
    // Registered after the handle exists: a stop arriving in the microseconds
    // before that is a miss, which is why the client also settles locally.
    if (execId !== undefined && execId !== '') {
      release = execs.add(execId, {
        cancel: () => {
          cancelled = true
          killTree(child)
        },
      })
    }
  })

  /**
   * The version token a guarded write round-trips.
   *
   * mtime+size is cheap and good enough to catch "the file changed since you
   * read it", which is the whole job of the guard. It is explicitly NOT a
   * content hash: a same-millisecond, same-size edit would slip past, and that
   * is a deliberate cost trade rather than an oversight.
   * @param path - the file to describe.
   * @returns the token.
   */
  const fsVersionOf = async (path: string): Promise<string> => {
    const info = await stat(path)
    return `${info.mtimeMs}:${info.size}`
  }

  // ---------------------------------------------------------------------------
  // Capability federation: catalog + direct kernel invocation
  //
  // The controller's model calls a local mirror; the mirror sends `caps.call`;
  // this half runs the peer's OWN registered tool body. No agent and no session
  // are created or resumed: a capability call must never appear as a
  // conversation on this machine. `caps.list` needs no session either —the
  // preset registry already mounts each preset into its own scope, so the tool
  // surface can be enumerated by taking a scope lease.
  // ---------------------------------------------------------------------------

  /** Why this half refuses to run `name` directly, if it does. */
  const deniedToolReason = (name: string): string | undefined => {
    for (const prefix of DENIED_TOOL_PREFIXES) {
      if (name.startsWith(prefix)) return 'it is dsh-remote\'s own bridge tool; calling it would loop controllers back around'
    }
    for (const entry of read().deniedTools ?? []) {
      const pattern = typeof entry === 'string' ? entry.trim() : ''
      if (pattern === '') continue
      const matches = pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern
      if (matches) return 'this machine\'s configuration denies direct calls to it'
    }
    return undefined
  }

  /** The preset a capability request addresses: explicit, then config, then default. */
  const capabilityPresetArg = (presetId: unknown): string =>
    (typeof presetId === 'string' && presetId.trim() !== '' ? presetId.trim() : (text(read().capabilityPreset) ?? ''))

  /** Retain one preset scope (never an agent), use it, then release it. */
  const acquireCapabilityScope = async (presetId: unknown): Promise<{
    key: object
    presetId: string
    release: () => Promise<void>
  }> => {
    const presets = ctx.get('agentPresets')
    if (presets === undefined) throw new Error('dsh-remote-server: the `agentPresets` service is unavailable')
    const wanted = capabilityPresetArg(presetId)
    // `acquireScope` retains the live generation of the preset's already-mounted
    // scope: no agent, no session, just the tool layer that preset contributes.
    const lease = await presets.acquireScope(wanted === '' ? undefined : wanted) as unknown as {
      key: object
      [Symbol.asyncDispose]: () => Promise<void>
    }
    try {
      const resolved = await presets.resolve(wanted === '' ? undefined : wanted)
      return {
        key: lease.key,
        presetId: resolved.id,
        release: async () => { await lease[Symbol.asyncDispose]() },
      }
    } catch (error) {
      await lease[Symbol.asyncDispose]()
      throw error
    }
  }

  /** Read this machine's function-call surface for one preset. */
  const capabilityCatalog = async (presetId: unknown): Promise<Record<string, unknown>> => {
    if (read().capabilities === false) {
      return {
        available: false,
        reason: 'direct capability calls are disabled on this machine (dsh-remote-server: capabilities=false)',
        presetId: '',
      }
    }
    const presets = ctx.get('agentPresets')
    const tools = ctx.get('tools')
    if (presets === undefined || tools === undefined) {
      return {
        available: false,
        reason: 'this DSH does not provide the `tools`/`agentPresets` services',
        presetId: '',
      }
    }
    const lease = await acquireCapabilityScope(presetId)
    try {
      // `schemas(scope)` is the exact model-facing surface that preset sees: its
      // own plugins' tools plus the host-level ones, minus that scope's
      // restrictions. Nothing is instantiated for this read.
      const rows = tools.schemas(lease.key).map(schema => {
        const reason = deniedToolReason(schema.name)
        const definition = tools.get(schema.name, lease.key)
        const globalDefinition = tools.get(schema.name)
        return {
          name: schema.name,
          description: schema.description,
          parameters: schema.parameters,
          origin: definition !== undefined && definition === globalDefinition ? 'global' : 'preset',
          callable: reason === undefined,
          ...(reason === undefined ? {} : { reason }),
        }
      }).sort((left, right) => left.name.localeCompare(right.name))
      const roster = await presets.list()
      const presetsRows = roster.map(preset => ({
        id: preset.id,
        ...(preset.name === undefined ? {} : { name: preset.name }),
        ...(preset.description === undefined ? {} : { description: preset.description }),
        isDefault: preset.id === presets.defaultId,
        ...(preset.broken === undefined ? {} : { broken: preset.broken }),
      }))
      const plugins = (await presets.compositionInventory()).map(row => ({
        presetId: row.id,
        ...(row.name === undefined ? {} : { name: row.name }),
        isDefault: row.isDefault,
        ...(row.broken === undefined ? {} : { broken: row.broken }),
        rows: row.rows.map(plugin => ({
          id: plugin.entryId,
          name: plugin.moduleName,
          enabled: plugin.enabled,
          ...(plugin.condition === undefined ? {} : { condition: plugin.condition }),
        })),
      }))
      const sessions = (ctx.get('agents')?.list() ?? []).flatMap((agent) => {
        const exposedId = wireSessionId(String(agent.id))
        if (exposedId === undefined) return []
        const agentPreset = presets.composedPreset(agent.ctx)
        const cwd = agent.session.header.cwd
        return {
          sessionId: exposedId,
          status: String(agent.status),
          ...(agentPreset === undefined ? {} : { presetId: agentPreset }),
          ...(typeof cwd === 'string' && cwd !== '' ? { cwd } : {}),
        }
      })
      const subagentProviders = (ctx.get('subagents')?.list() ?? []).map(name => String(name))
      return {
        available: true,
        build: BUILD,
        presetId: lease.presetId,
        presets: presetsRows,
        tools: rows,
        plugins,
        sessions,
        subagentProviders,
      }
    } finally {
      await lease.release()
    }
  }

  /** Losslessly JSON-able copy of a tool's rendered content, for the wire. */
  const wireJson = (value: unknown): unknown => {
    try {
      return JSON.parse(JSON.stringify(value ?? null)) as unknown
    } catch {
      return [{ type: 'text', text: String(value) }]
    }
  }

  /**
   * Run one of this machine's tools directly, on the controller's behalf.
   *
   * The body runs with no `exec.agent`: that is what keeps the call out of any
   * conversation here. Tools whose doc says they need a live agent
   * (`subagent`, `todo_write`, — therefore fail with their own clear error
   * instead of silently opening a session —the operator asked for "activate the
   * peer's function", not "start chatting with the peer".
   */
  const callCapability = async (args: Record<string, unknown>): Promise<Record<string, unknown>> => {
    const activeToolCalls = resources().activeToolCalls
    if (read().capabilities === false) {
      throw new Error('dsh-remote-server: direct capability calls are disabled on this machine (capabilities=false)')
    }
    const name = String(args.name ?? '')
    if (name === '') throw new Error('caps.call: `name` is required')
    const denial = deniedToolReason(name)
    if (denial !== undefined) throw new Error(`caps.call: refusing ${JSON.stringify(name)}: ${denial}`)
    const tools = ctx.get('tools')
    if (tools === undefined) throw new Error('dsh-remote-server: the `tools` service is unavailable')

    const callId = typeof args.callId === 'string' && args.callId !== '' ? args.callId : randomUUID()
    if (activeToolCalls.has(callId)) throw new Error(`caps.call: callId ${JSON.stringify(callId)} is already running`)
    const callArgs = args.arguments === undefined || args.arguments === null ? {} : args.arguments
    const ceiling = Math.max(1_000, read().maxToolCallTimeoutMs ?? 600_000)
    const requested = Number(args.timeoutMs ?? ceiling)
    const timeoutMs = Number.isFinite(requested) ? Math.min(Math.max(Math.floor(requested), 1_000), ceiling) : ceiling

    // Reserve BEFORE the first await so same-principal concurrent duplicate ids
    // cannot overwrite the cancellation target while a scope is being acquired.
    const controller = new AbortController()
    activeToolCalls.set(callId, controller)
    let lease: Awaited<ReturnType<typeof acquireCapabilityScope>> | undefined
    try {
      lease = await acquireCapabilityScope(args.presetId)
      if (controller.signal.aborted) throw controller.signal.reason
      const definition = tools.get(name, lease.key)
      if (definition === undefined) {
        throw new Error(
          `caps.call: the peer exposes no tool named ${JSON.stringify(name)}`
          + ` in preset ${JSON.stringify(lease.presetId)}`,
        )
      }
      const timer = setTimeout(() => {
        const timeout = new Error(`the peer's ${name} call timed out after ${timeoutMs} ms`)
        timeout.name = 'AbortError'
        controller.abort(timeout)
      }, timeoutMs)
      timer.unref?.()
      const startedAt = Date.now()
      const signal = controller.signal
      const callIdBrand = (connection().multi
        ? `remote-${connection().principal}-${createHash('sha256').update(callId).digest('hex')}`
        : callId) as unknown as ToolCallId
      const exec = {
        token: Symbol('dsh-remote:caps.call') as unknown as ToolExecutionToken,
        callId: callIdBrand,
        rootCallId: callIdBrand,
        name,
        arguments: callArgs,
        signal,
        deferContext: () => {},
        concludeTurn: () => {},
      } as unknown as ToolRunContext
      try {
        // Race the abort so a stop/timeout answers immediately; the body keeps
        // draining in the background when it ignores the signal, exactly like a
        // local Stop on a tool that cannot be interrupted. The reason carried by
        // the signal is preserved so the controller can tell a timeout from a
        // user stop.
        assertControllerOperation(connection(), 'caps.call')
        const body = definition.execute(callArgs, exec).then((value) => {
          const content = definition.output.render(callArgs, value as JsonValue)
          return { value, content }
        })
        body.catch(() => {})
        const aborted = new Promise<never>((_resolve, reject) => {
          const onAbort = (): void => {
            reject(signal.reason instanceof Error ? signal.reason : new Error(`the peer cancelled ${name}`))
          }
          if (signal.aborted) { onAbort(); return }
          signal.addEventListener('abort', onAbort, { once: true })
        })
        const { value, content } = await Promise.race([body, aborted])
        return {
          callId,
          ...(value === undefined ? {} : { value: wireJson(value) }),
          content: wireJson(content),
          durationMs: Date.now() - startedAt,
        }
      } finally {
        clearTimeout(timer)
      }
    } finally {
      if (activeToolCalls.get(callId) === controller) activeToolCalls.delete(callId)
      await lease?.release()
    }
  }

  const ops: Record<string, (args: Record<string, unknown>) => Promise<Record<string, unknown>>> = {
    'relay.register': async () => relayHub.register(connection()),
    'relay.open': async args => relayHub.open(connection(), args),
    'relay.accept': async args => relayHub.accept(connection(), args),
    'relay.write': async args => relayHub.write(connection(), args),
    'relay.close': async args => relayHub.close(connection(), args),
    'relay.status': async () => relayHub.status(connection()),
    ping: async () => ({ pong: true, version: SERVER_VERSION, pid: process.pid }),

    sysinfo: async () => ({
      hostname: process.env.COMPUTERNAME ?? process.env.HOSTNAME ?? '',
      platform: process.platform,
      arch: process.arch,
      node: process.version,
      pid: process.pid,
      cwd: process.cwd(),
      dshHome: dshHomePath(),
      identity: fingerprint(identity.publicKey),
      build: BUILD,
      features: { replies: 'committed-assistant-v1', inputSource: 'dsh-remote-v1', noteModes: ['queue', 'steer', 'auto'] },
      sessions: [...states.values()].filter(state => state.principal === connection().principal).map(state => state.wireId),
      // Advertised so a controller can tell an op exists BEFORE spending a round
      // trip on it: `agent.sessions` is what lets an older controller fall back
      // to the plain `sessions` list above instead of erroring.
      ops: Object.keys(ops),
    }),

    exec: async args => exec(
      String(args.cmd ?? ''),
      String(args.shell ?? 'powershell'),
      Number(args.timeoutMs ?? 120_000),
      typeof args.cwd === 'string' ? args.cwd : undefined,
      // Optional: without it the command simply cannot be stopped later.
      typeof args.execId === 'string' ? args.execId : undefined,
    ),

    /**
     * Read the trajectory journal.
     *
     * The cheap way to pull this machine's history into a controller's context.
     * `fromSeq` omitted means "the tail" (the newest `limit` entries) — what a
     * reader that has never looked wants; pass the `nextSeq` from the previous
     * read and only what is new comes back. Entries are one line each unless
     * `full` asks for the detail.
     */
    'journal.read': async args => {
      const limit = Number(args.limit ?? 100)
      const asked = args.fromSeq
      const bounded = Number.isFinite(limit) && limit > 0 ? Math.min(Math.floor(limit), 500) : 100
      const from = asked === undefined
        ? Math.max(0, journal.lastSeq - bounded)
        : Number(asked)
      // Read details internally even for compact callers so owner attribution
      // cannot be omitted to turn this into a cross-principal journal read.
      const page = journal.read(from, bounded, true)
      const entries = page.entries.filter(entry => entry.detail?.principal === connection().principal
        || (!connection().multi && entry.detail?.principal === undefined)).map(entry => {
          const detail = entry.detail === undefined ? undefined : { ...entry.detail }
          if (detail !== undefined) delete detail.principal
          const { detail: _private, ...compact } = entry
          return args.full === true ? { ...compact, ...(detail === undefined ? {} : { detail }) } : compact
        })
      return {
        ...page,
        entries,
        count: entries.length,
        total: connection().multi ? entries.length : page.total,
        ...(asked === undefined ? { tail: true } : {}),
        lastSeq: journal.lastSeq,
        written: journal.writtenCount,
      }
    },

    /**
     * Stop a command this half is running for a controller.
     *
     * The counterpart of the local Stop: the controller settles its own call at
     * once (it cannot wait for a reply that may be minutes away) and then asks
     * here, so the work actually stops instead of running to its timeout.
     */
    'exec.cancel': async args => {
      const execId = String(args.execId ?? '')
      if (execId === '') throw new Error('exec.cancel: execId is required')
      return { execId, cancelled: resources().execs.cancel(execId) }
    },

    'fs.read': async args => {
      const path = String(args.path ?? '')
      const data = await readFile(path)
      const offset = Number(args.offset ?? 0)
      const length = Number(args.length ?? data.length)
      const slice = data.subarray(offset, offset + length)
      return {
        size: data.length,
        offset,
        read: slice.length,
        eof: offset + slice.length >= data.length,
        dataB64: slice.toString('base64'),
      }
    },

    'fs.write': async args => {
      const path = String(args.path ?? '')
      const data = Buffer.from(String(args.dataB64 ?? ''), 'base64')
      const offset = Number(args.offset ?? 0)
      const expectedVersion = typeof args.expectedVersion === 'string' ? args.expectedVersion : undefined
      const createOnly = args.createOnly === true
      const before = await readFile(path).catch(() => undefined)

      // The guard runs BEFORE the write, so a stale write is refused rather than
      // silently clobbering whatever the other side changed.
      if (createOnly && before !== undefined) {
        throw new FsError(`cannot overwrite existing "${path}" without reading it first`, 'FS_NOT_OBSERVED')
      }
      if (expectedVersion !== undefined) {
        if (before === undefined) {
          throw new FsError(`cannot write "${path}": file no longer exists`, 'FS_STALE_VERSION')
        }
        if ((await fsVersionOf(path)) !== expectedVersion) {
          throw new FsError(`cannot write "${path}": file changed since it was read`, 'FS_STALE_VERSION')
        }
      }

      mkdirSync(dirname(path), { recursive: true })
      if (offset > 0) {
        const existing = before ?? Buffer.alloc(0)
        const merged = Buffer.concat([existing.subarray(0, offset), data])
        await writeFile(path, merged)
      } else {
        await writeFile(path, data)
      }
      return {
        written: data.length,
        size: (await stat(path)).size,
        version: await fsVersionOf(path),
        created: before === undefined,
        before: before === undefined || offset > 0 ? null : decodeOutput(before),
      }
    },

    'fs.edit': async args => {
      const path = String(args.path ?? '')
      const oldString = String(args.oldString ?? '')
      const newString = String(args.newString ?? '')
      const replaceAll = args.replaceAll === true
      const expectedVersion = typeof args.expectedVersion === 'string' ? args.expectedVersion : undefined
      if (oldString === '') throw new FsError('oldString must not be empty', 'FS_EDIT_NOT_FOUND')

      const before = await readFile(path).catch(() => undefined)
      // Same ordering as the local backend: a stale guard is reported before
      // match failures, so an edit based on an old read says FS_STALE_VERSION
      // rather than blaming the text.
      if (before === undefined) {
        throw new FsError(`cannot edit "${path}": file changed since it was read`, 'FS_STALE_VERSION')
      }
      if (expectedVersion !== undefined && (await fsVersionOf(path)) !== expectedVersion) {
        throw new FsError(`cannot edit "${path}": file changed since it was read`, 'FS_STALE_VERSION')
      }

      const text = decodeOutput(before)
      const count = text.split(oldString).length - 1
      if (count === 0) {
        throw new FsError(`cannot edit "${path}": the text to replace was not found`, 'FS_EDIT_NOT_FOUND')
      }
      if (count > 1 && !replaceAll) {
        throw new FsError(`cannot edit "${path}": the text to replace appears ${count} times`, 'FS_AMBIGUOUS_EDIT')
      }
      const after = replaceAll ? text.split(oldString).join(newString) : text.replace(oldString, newString)
      await writeFile(path, Buffer.from(after, 'utf8'))
      return { version: await fsVersionOf(path), before: text, after }
    },

    'fs.list': async args => {
      const path = String(args.path ?? '.')
      const entries = await readdir(path, { withFileTypes: true })
      const rows = await Promise.all(entries.map(async (entry) => {
        const info = await stat(`${path}/${entry.name}`).catch(() => undefined)
        return {
          name: entry.name,
          isDir: entry.isDirectory(),
          size: info?.size ?? 0,
          mtimeMs: info?.mtimeMs ?? 0,
        }
      }))
      rows.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1))
      return { path, count: rows.length, entries: rows }
    },

    'fs.stat': async args => {
      const path = String(args.path ?? '')
      try {
        const info = await stat(path)
        return {
          exists: true,
          isDir: info.isDirectory(),
          size: info.size,
          mtimeMs: info.mtimeMs,
          version: `${info.mtimeMs}:${info.size}`,
        }
      } catch {
        return { exists: false }
      }
    },

    'fs.hash': async args => {
      const data = await readFile(String(args.path ?? ''))
      return {
        algo: 'sha256',
        hash: createHash('sha256').update(data).digest('hex'),
        bytes: data.length,
      }
    },

    /**
     * Chunked, per-block-compressed transfers — the fast path for large files.
     *
     * These are NEW ops on purpose: `fs.read`/`fs.write` stay exactly as they
     * were, so a controller that does not know these (or an old peer that does
     * not advertise them) keeps working. A controller capability-negotiates from
     * `sysinfo.ops`. Permissions: `begin` is fenced on its `path` like any write;
     * `chunk`/`commit`/`abort` carry only an `uploadId`, which cannot name a
     * different path because the path was fixed at `begin`.
     */
    'fs.put.begin': async args => {
      const owned = resources()
      const result = await owned.transfers.begin(args)
      owned.uploadPaths.set(String(result.uploadId), String(args.path))
      return result
    },
    'fs.put.chunk': async args => resources().transfers.chunk(args),
    'fs.put.commit': async args => {
      const owned = resources()
      try { return await owned.transfers.commit(args) }
      finally { owned.uploadPaths.delete(String(args.uploadId ?? '')) }
    },
    'fs.put.abort': async args => {
      const owned = resources()
      try { return await owned.transfers.abort(args) }
      finally { owned.uploadPaths.delete(String(args.uploadId ?? '')) }
    },
    'fs.get': async args => resources().transfers.get(args),

    // Authenticated read-only metadata; never mounts or creates an Agent.
    'references.list': async args => listReferenceCatalog(ctx, args, connection().signal),

    'preset.list': async () => {
      const presets = ctx.get('agentPresets')
      if (presets === undefined) return { available: false, presets: [] }
      const list = await presets.list()
      return {
        available: true,
        defaultId: presets.defaultId,
        presets: list.map((preset: { id: string, name?: string, broken?: string }) => ({
          id: preset.id,
          name: preset.name ?? '',
          broken: preset.broken ?? null,
        })),
      }
    },

    /**
     * This machine's function-call surface, for a controller to mirror locally.
     *
     * Read-only and session-free: the answer is the set of tools one agent
     * preset contributes (plus host-level tools), that preset's plugin
     * inventory, the deployment's presets (its subagent types), its subagent
     * providers, and the live sessions that exist right now — the last purely as
     * information; nothing here drives them.
     *
     * `callable:false` is reported rather than omitted: a controller should be
     * able to tell "the peer has this tool but refuses it" from "the peer does
     * not have it", especially for the bridge tools whose absence prevents a
     * loop.
     */
    'caps.list': async args => capabilityCatalog(args.presetId),

    /**
     * Run ONE of this machine's registered tools directly.
     *
     * The peer's own tool body executes here with no agent and no session. This
     * is the fast path a controller uses instead of spending a whole remote turn
     * on "please run tool X": the tool's schema was already mirrored locally, so
     * the model called it as if it were local, and only the body ran here.
     *
     * `callId` is caller-chosen so a local stop can address this exact call with
     * `caps.cancel`; it is required for that to work but optional for the call
     * itself (a random id is minted).
     */
    'caps.call': async args => callCapability(args),

    /**
     * Stop one direct tool call this half is running for a controller.
     *
     * Best effort, like `exec.cancel`: the controller has already settled its
     * own call, and this asks the work here to stop instead of letting it run to
     * its timeout. A body that ignores its AbortSignal still drains; nothing in
     * the same process can hard-kill it.
     */
    'caps.cancel': async args => {
      const callId = String(args.callId ?? '')
      if (callId === '') throw new Error('caps.cancel: callId is required')
      const controller = resources().activeToolCalls.get(callId)
      if (controller === undefined) return { callId, cancelled: false }
      const reason = new Error('the controller cancelled this tool call')
      reason.name = 'AbortError'
      controller.abort(reason)
      return { callId, cancelled: true }
    },

    'agent.prompt': async args => {
      const sessionId = String(args.sessionId ?? '')
      if (sessionId === '') throw new Error('agent.prompt: sessionId is required')
      return prompt(
        sessionId,
        String(args.text ?? ''),
        Number(args.timeoutMs ?? 0),
        typeof args.presetId === 'string' ? args.presetId : undefined,
        typeof args.workspace === 'string' ? args.workspace : undefined,
      )
    },

    /**
     * Inject one controller message WITHOUT waiting for a turn to finish.
     *
     * The sibling of `agent.prompt` for the "send_message to a running remote
     * subagent" flow: the controller is driving a long turn and has new
     * instructions, but must not block on the delivery. queue uses followup for
     * the next turn; steer uses the nearest admitted step; auto steers a busy
     * Agent and queues an idle Agent. Steering does not cancel a prepared request.
     * The returned mode and processing fields describe the actual placement.
     *
     * Input normally carries producer source kind:dsh-remote and persists its
     * admission trace before waking the Agent; when the optional superAgentIo
     * adapter is active it uses IO's real external source instead. Unknown
     * admission is never retried or re-injected here.
     */
    'agent.note': async args => {
      const sessionId = String(args.sessionId ?? '')
      if (sessionId === '') throw new Error('agent.note: sessionId is required')
      const noteText = String(args.text ?? '')
      if (noteText.trim() === '') throw new Error('agent.note: text is required')
      const requestedMode = inputMode(args.mode)
      const generation = resources().generation.signal
      const { handle, created } = await ensureAgent(
        sessionId,
        typeof args.presetId === 'string' ? args.presetId : undefined,
        typeof args.workspace === 'string' ? args.workspace : undefined,
      )
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const agent = (handle as any).agent
      const busy = await agentBusy(agent)
      generation.throwIfAborted()
      assertControllerOperation(connection(), 'agent.note')
      const principal = connection().principal
      const localId = scopedSessionId(sessionId)
      const mode = requestedMode === 'auto' ? (busy ? 'steer' : 'queue') : requestedMode
      const ioAdmission = await admitViaIo({
        principal,
        localId,
        wireId: sessionId,
        text: noteText,
        mode: requestedMode,
        externalMessageId: randomUUID(),
      })
      if (ioAdmission.kind === 'unknown') {
        throw new Error(`dsh-remote-server: super-agent-io admission outcome is unknown; do not resend (${ioAdmission.reason})`)
      }
      if (ioAdmission.kind === 'accepted') {
        const actual = ioAdmission.receipt.mode
        rememberInjection(localId, ioAdmission.receipt.messageId)
        return {
          sessionId,
          created,
          accepted: true,
          messageId: ioAdmission.receipt.messageId,
          traceId: ioAdmission.receipt.traceId,
          seq: agent.session.seq,
          requestedMode,
          mode: actual,
          processing: busy ? (actual === 'steer' ? 'next-step' : 'next-turn') : 'starting',
          transport: 'super-agent-io',
        }
      }
      const message = createUserMessage({
        content: [{ type: 'text', text: noteText }],
        source: { kind: 'dsh-remote', version: 1, principal,
          remoteSessionId: sessionId, operation: 'agent.note', traceId: randomUUID() },
      })
      rememberInjection(localId, String(message.id))
      let placement: ReturnType<typeof deliverInput> = { mode, processing: busy ? (mode === 'steer' ? 'next-step' : 'next-turn') : 'starting' }
      await admitTracked(await messageTraces.store(), {
        version: 1, traceId: message.source.traceId, principal,
        sessionId: localId, remoteSessionId: sessionId, messageId: String(message.id), seq: null,
        time: Date.now(), operation: 'agent.note', requestedMode, mode, state: 'admitting',
      }, () => {
        generation.throwIfAborted()
        assertControllerOperation(connection(), 'agent.note')
        placement = deliverInput(agent, message, requestedMode, busy)
      })
      return {
        sessionId,
        created,
        accepted: true,
        messageId: String(message.id),
        traceId: message.source.traceId,
        seq: agent.session.seq,
        requestedMode,
        transport: 'dsh-remote',
        ...placement,
      }
    },

    'agent.ensure': async args => {
      const sessionId = String(args.sessionId ?? '')
      if (sessionId === '') throw new Error('agent.ensure: sessionId is required')
      const { created } = await ensureAgent(
        sessionId,
        typeof args.presetId === 'string' ? args.presetId : undefined,
        typeof args.workspace === 'string' ? args.workspace : undefined,
      )
      return { sessionId, created }
    },

    /**
     * Existing conversations on this machine, newest first.
     *
     * Read-only, and deliberately the cheapest useful answer to "may I continue
     * something instead of opening another session?": the controlling half calls
     * it when it has no session id to reuse. Rows come from the workspace
     * registry (that is where sessions created on request are accounted, live or
     * not), each workspace in `sessionIds` order — newest attached first — with
     * live handles this server owns appended for anything the registry does not
     * know about. A caller that needs an exact workspace should pass
     * `workspace`, because the cross-workspace order is otherwise just registry
     * order.
     */
    'agent.sessions': async args => {
      const prefix = typeof args.prefix === 'string' ? args.prefix.trim() : ''
      const requested = typeof args.workspace === 'string' ? args.workspace.trim() : ''
      const wanted = requested === '' ? undefined : normalizePath(requested)
      const rows: Array<Record<string, unknown>> = []
      const seen = new Set<string>()

      const add = (rawId: unknown, cwd: string | undefined): void => {
        const localId = String(rawId)
        const sessionId = wireSessionId(localId)
        if (sessionId === undefined || sessionId === '' || seen.has(sessionId)) return
        if (!familyMatches(prefix, sessionId)) return
        seen.add(sessionId)
        const live = ctx.get('sessions')?.get(SessionId(localId))
        const headerCwd = (live as { header?: { cwd?: unknown } } | undefined)?.header?.cwd
        rows.push({
          sessionId,
          cwd: cwd ?? (typeof headerCwd === 'string' ? headerCwd : null),
          live: live !== undefined,
          seq: typeof live?.seq === 'number' ? live.seq : 0,
        })
      }

      // `list()` is synchronous and yields header-validated accounts, so an id
      // whose session file is gone never shows up as reusable.
      const accounts = (ctx.get('workspaceRegistry')?.list() ?? [])
        .map((workspace: { path: string, sessionIds: readonly unknown[] }) => ({
          path: workspace.path,
          sessionIds: workspace.sessionIds.map(String).filter(id => wireSessionId(id) !== undefined),
        }))
      // Match the external family after removing the authenticated namespace.
      for (const reusable of orderReusableSessions(accounts, { prefix: '', workspace: requested })) {
        add(reusable.sessionId, reusable.cwd)
      }
      // Live handles this server owns that no workspace accounted for.
      for (const [sessionId, state] of states) {
        if (state.principal !== connection().principal || seen.has(state.wireId) || !familyMatches(prefix, state.wireId)) continue
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const cwd = (state.handle as any)?.agent?.session?.header?.cwd
        const known = typeof cwd === 'string' ? cwd : undefined
        if (wanted !== undefined && known !== undefined && normalizePath(known) !== wanted) continue
        add(sessionId, known)
      }

      return { prefix, workspace: requested, count: rows.length, sessions: rows }
    },

    'agent.interrupt': async args => {
      const sessionId = String(args.sessionId ?? '')
      const state = ownState(sessionId)
      const localId = scopedSessionId(sessionId)
      if (state === undefined) return { interrupted: false, reason: 'no live handle for that session' }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const agent = (state.handle as any).agent
      // Ask BEFORE cancelling whether there is anything to stop. `cancel()` is a
      // documented no-op on an idle agent, so answering `interrupted: true`
      // unconditionally claims a stop that never happened —measured against a
      // real peer, where the turn had already completed and the controller was
      // still told "interrupted". The latch below is what stops a turn that has
      // not started yet, and that case is reported separately.
      const busy = await agentBusy(agent)
      assertControllerOperation(connection(), 'agent.interrupt')
      // Record it as OURS before cancelling: a controller-requested stop and a
      // human pressing stop on this machine end the turn with the SAME reason, so
      // the event feed alone cannot tell them apart.
      selfInterrupted.set(localId, Date.now())
      // Latch it too: if this stop lands while the session is idle (the parked
      // prompt has not started its work yet), `cancel()` below is a no-op, and
      // only the latch stops the work from starting at all.
      stopRequested.set(localId, Date.now())
      // `Agent.interrupt()` no longer exists; it is now the synchronous
      // `cancel(cause)`. The old `typeof agent.interrupt === 'function'` guard
      // meant this op always reported "no interrupt()" instead of cancelling.
      agent.cancel({ kind: 'user' })
      return busy
        ? { interrupted: true }
        : { interrupted: false, latched: true, reason: 'that session had no turn running; the stop is latched for the next one' }
    },

    'agent.events': async args => {
      const sessionId = String(args.sessionId ?? '')
      const state = ownState(sessionId)
      if (state === undefined) throw new Error('agent.events: no live handle for that session')
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const session = (state.handle as any).agent.session
      const events: readonly SessionEvent[] = session.snapshotEvents()
      return {
        sessionId,
        seq: session.seq,
        fromSeq: Number(args.fromSeq ?? 0),
        events: extractPublicEvents(events, Number(args.fromSeq ?? 0), Number(args.limit ?? 400), sessionId),
        replyFormat: 'committed-assistant-v1',
      }
    },

    /**
     * Token usage for every model call in one live session.
     *
     * This is the read side of the controller's cost meter. Only tokens and the
     * route that produced them are reported — never a price: price tables and
     * peak/off-peak windows live on the controlling machine, where they can be
     * updated without redeploying this one. The controller polls with `fromSeq`
     * as an exclusive cursor; `records` never repeats a call the streaming
     * chunk and final message both reported (see session-usage.ts).
     *
     * `nextSeq` is the cursor for the next poll, and it is deliberately NOT
     * always `seq`. When the page was truncated by `limit` it is the seq of the
     * last returned record — advancing to `seq` there would skip every record
     * the line could not fit. Only an untruncated pass may jump to the newest
     * scanned event seq (or `fromSeq` when nothing newer exists), so a poller
     * can leave a quiet session without rescanning it forever. Callers must use
     * `nextSeq` as the next call's `fromSeq`.
     *
     * A session with no live handle is a normal answer, not an error: the
     * controller may still be finishing a call for a session whose handle was
     * torn down, and it should see `available: false` rather than a failed op.
     * The response keeps the same field set in both cases (`nextSeq = fromSeq`)
     * so the controller needs no branch just to move its cursor.
     */
    'usage.read': async args => {
      const sessionId = String(args.sessionId ?? '')
      if (sessionId === '') throw new Error('usage.read: sessionId is required')
      const requestedFrom = Number(args.fromSeq ?? 0)
      const fromSeq = Number.isSafeInteger(requestedFrom) && requestedFrom >= 0 ? requestedFrom : 0
      const state = ownState(sessionId)
      if (state === undefined) {
        return {
          sessionId,
          available: false,
          reason: 'no live handle for that session',
          seq: 0,
          fromSeq,
          // Nothing was scanned, so the cursor must not move.
          nextSeq: fromSeq,
          records: [],
        }
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const session = (state.handle as any).agent.session
      const events: readonly SessionEvent[] = session.snapshotEvents()
      const extracted = extractUsageRecords(events, {
        fromSeq,
        limit: Number(args.limit ?? 500),
      })
      return {
        sessionId,
        available: true,
        seq: Number(session.seq ?? 0),
        fromSeq,
        nextSeq: extracted.nextSeq,
        records: extracted.records,
      }
    },
  }

  /** Handle one authenticated connection. */
  const serve = async (socket: Socket, peer: string, lease: AdmissionLease): Promise<void> => {
    const handshakeIdentity = identity
    const deadline = setTimeout(() => { socket.destroy() }, networkLimits(read()).handshakeTimeoutMs)
    deadline.unref?.()
    let session: Session
    let registered: Session | undefined
    let authenticated: ControllerConnection
    const lifetime = new AbortController()
    try {
      socket.setNoDelay(true)
      const declared = pinnedControllers()
      const multi = declared.length !== 0
      const prefix = await readHandshakeField(socket, MAGIC.length)
      let key: ReturnType<typeof resolvePeerPublicKey>
      let name = 'legacy'
      if (prefix !== null && prefix.equals(KEY_SELECTOR_MAGIC)) {
        const selected = await readHandshakeField(socket, 64)
        if (selected === null) throw new HandshakeError('peer closed during key selection')
        const selectedId = fullKeyId(publicFromRaw(selected.subarray(0, 32)))
        const allowed = multi ? declared.find(candidate => candidate.principal === selectedId) : undefined
        key = allowed?.key ?? (multi ? publicFromRaw(selected.subarray(0, 32)) : resolvePeerPublicKey(read(), 'client.pub'))
        if ((multi && allowed === undefined) || fullKeyId(key) !== selectedId) {
          socket.write(KEY_SELECTOR_DENIED)
          throw new HandshakeError('unknown client public key')
        }
        name = allowed?.name ?? name
        socket.write(KEY_SELECTOR_ACK)
      } else if (prefix !== null && prefix.equals(MAGIC) && !multi && read().allowLegacyHandshake === true) {
        // Old clients send DSHR2 directly; put only the peeked magic back.
        socket.unshift(prefix)
        key = resolvePeerPublicKey(read(), 'client.pub')
      } else {
        throw new HandshakeError('peer must select an authorized key before the DSHR2 handshake')
      }
      // Selection is NOT authentication. No principal exists until tag_c proves
      // possession of the selected pin's matching static private key.
      session = await serverHandshake(socket, handshakeIdentity.key, key)
      socket.setTimeout(0)
      authenticated = { session, principal: fullKeyId(key), name, multi, signal: lifetime.signal,
        serverIdentity: fullKeyId(handshakeIdentity.publicKey), authenticatedAt: Date.now(), policy: {} as ControllerPolicy }
      authenticated.policy = policyFor(authenticated)
      lease.authenticated()
      clearTimeout(deadline)
      pendingSockets.delete(socket)
      principalPolicies.set(authenticated.principal, authenticated)
      ctx.logger.info(`dsh-remote-server: ${peer} authenticated as ${name}`)
      registered = session
      controllers.set(session, authenticated)
      // A connected controller is the other half of the proof a deploy script
      // needs: the new build not only loaded, it completed a handshake.
      beatHeartbeat()
    } catch (error) {
      clearTimeout(deadline)
      pendingSockets.delete(socket)
      lease.failed()
      audit(peer, '-', false, {
        reason: error instanceof HandshakeError ? 'handshake_failed' : 'handshake_error',
        detail: error instanceof Error ? error.message : String(error),
      })
      socket.destroy()
      return
    }

    /**
     * Handle one request. Never throws, so a dispatched task can never reject
     * unhandled when the socket disappears mid-flight.
     */
    const handleRequest = async (link: Session, request: Record<string, unknown>): Promise<void> => {
      const id = request.id
      const op = String(request.op ?? '')
      const handler = Object.hasOwn(ops, op) ? ops[op] : undefined
      if (handler === undefined) {
        try {
          await link.send({ id, ok: false, error: `unknown op ${JSON.stringify(op)}` })
        } catch { /* the link is gone; there is nowhere to report into */ }
        audit(peer, op, false, { reason: 'unknown_op' })
        return
      }
      const startedAt = Date.now()
      try {
        // Enforced here as well as on the controller: the same shared rule, so
        // the two ends can never disagree about what a level admits.
        const result = await requests.run(authenticated, async () => {
          const policy = assertControllerOperation(authenticated, op)
          const args = { ...request }
          if (policy.ceiling < 3 && ['fs.read', 'fs.hash', 'fs.get', 'fs.stat', 'fs.list'].includes(op)) {
            let accepted: string | undefined
            for (const root of policy.readRoots) {
              try { accepted = await fencedPath(String(request.path ?? ''), root); break } catch { /* try another explicit root */ }
            }
            if (accepted === undefined) throw new FsError('file read is outside the authorized readRoots', 'FS_PERMISSION_DENIED')
            args.path = accepted
          }
          if (policy.ceiling === 2 && requiredLevel(op) === 2) {
            const upload = op.startsWith('fs.put.') && op !== 'fs.put.begin'
            const target = upload
              ? resources().uploadPaths.get(String(request.uploadId ?? ''))
              : typeof request.path === 'string' ? request.path : undefined
            if (target === undefined) throw new FsError('unknown upload or missing confined path', 'FS_PERMISSION_DENIED')
            const canonical = await fencedPath(target, policy.workspaceRoot)
            if (!upload) args.path = canonical
          }
          // Canonical path resolution may yield while a settings edit revokes
          // this principal. Never dispatch under the policy captured before it.
          authenticated.signal.throwIfAborted()
          if (assertControllerOperation(authenticated, op).signature !== policy.signature) {
            throw new FsError('controller policy changed before dispatch', 'FS_PERMISSION_DENIED')
          }
          return await handler(args)
        })
        await link.send({ id, ok: true, ...result })
        const ms = Date.now() - startedAt
        audit(peer, op, true, { ms })
        journalizeOp(op, request, { ok: true, ms, result })
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        const code = (error as { code?: unknown }).code
        try {
          await link.send({
            id,
            ok: false,
            error: message,
            ...(typeof code === 'string' && /^FS_[A-Z_]+$/.test(code) ? { code } : {}),
          })
        } catch { /* ditto */ }
        const ms = Date.now() - startedAt
        audit(peer, op, false, { ms, error: message.slice(0, 500) })
        journalizeOp(op, request, { ok: false, ms, error: message })
      }
    }

    /**
     * Record one served request.
     *
     * Readers are excluded on purpose: a reader must not grow the thing it
     * reads, or a polling controller would fill the journal with its own polling.
     * Transfer blocks are excluded for the same reason at a larger scale —one
     * 8 MiB file is thousands of `fs.put.chunk` calls whose summaries would drown
     * the record; `begin`/`commit` still leave one line each, and `fs.get` is a
     * read like `journal.read`.
     */
    function journalizeOp(
      op: string,
      request: Record<string, unknown>,
      outcome: { ok: boolean, ms: number, result?: Record<string, unknown>, error?: string },
    ): void {
      if (NOT_JOURNALED_OPS.has(op)) return
      const { summary, detail } = summarizeOp(op, request, outcome)
      record({
        kind: 'op',
        summary,
        op,
        ok: outcome.ok,
        ms: outcome.ms,
        ...(typeof request.sessionId === 'string' && request.sessionId !== ''
          ? { sessionId: request.sessionId }
          : {}),
        detail: { ...detail, principal: authenticated.principal },
      })
    }

    const remaining = Math.min(networkLimits(read()).maxSessionMs,
      authenticated.policy.expiresAt === undefined ? Number.MAX_SAFE_INTEGER : authenticated.policy.expiresAt - Date.now())
    const expiryTimer = setTimeout(() => {
      // Session age is connection-local. A stale socket's timer must never kill
      // a fresh socket or work accepted for the same persistent key identity.
      enforcePolicies()
      session.close()
    }, Math.max(1, remaining))
    expiryTimer.unref?.()
    try {
      // No wait queue: the shared principal budget cannot be evaded by opening
      // more sockets, nor can saturated ordinary work block cancel/answers.
      let lastId = 0
      for (;;) {
        const request = await session.recv()
        if (request === null) break
        const envelope = validateRequestEnvelope(request, lastId)
        enforcePolicies()
        if (envelope.type === 'answer') {
          const pending = relayed.get(envelope.qid)
          if (pending !== undefined && pending.controller === session) {
            assertControllerOperation(authenticated, 'agent.prompt')
            relayed.delete(envelope.qid)
            pending.resolve(request.answer)
          }
          continue
        }
        lastId = envelope.id
        const controls = envelope.op === 'exec.cancel' || envelope.op === 'caps.cancel' || envelope.op === 'agent.interrupt'
          || envelope.op === 'relay.accept' || envelope.op === 'relay.close'
        const active = principalInFlight.get(authenticated.principal) ?? 0
        if (!controls && active >= networkLimits(read()).maxInFlightPerPrincipal) {
          await session.send({ id: envelope.id, ok: false, error: 'principal request concurrency limit exceeded' })
          continue
        }
        if (controls) {
          await handleRequest(session, request)
          continue
        }
        principalInFlight.set(authenticated.principal, active + 1)
        void handleRequest(session, request).finally(() => {
          const current = (principalInFlight.get(authenticated.principal) ?? 1) - 1
          if (current <= 0) principalInFlight.delete(authenticated.principal)
          else principalInFlight.set(authenticated.principal, current)
        })
      }
    } catch (error) {
      ctx.logger.debug(`dsh-remote-server: ${peer} session ended: ${String(error)}`)
    } finally {
      clearTimeout(expiryTimer)
      lifetime.abort(new Error('controller connection closed'))
      if (registered !== undefined) {
        relayHub.detach(registered)
        controllers.delete(registered)
        // Anything still waiting on a question this controller was asked can
        // never be answered now: fail it rather than parking the peer's tool call
        // for the full relay timeout.
        for (const [qid, pending] of relayed) {
          if (pending.controller !== registered) continue
          relayed.delete(qid)
          pending.reject(new Error('dsh-remote-server: the controller disconnected before answering'))
        }
      }
      socket.destroy()
    }
  }

  let listener: Server | undefined
  let listeningAt = ''
  const stop = (): void => {
    listener?.close()
    listener = undefined
    listeningAt = ''
    for (const socket of sockets) socket.destroy()
  }

  /**
   * Prove to a deploy script that THIS build is the one serving.
   *
   * "The port is open" cannot distinguish a healthy new half from a half-broken
   * one, and cannot distinguish it from the old one still running —which is
   * exactly the blind spot that made a remote upgrade unrecoverable: the watchdog
   * had nothing to check but the port. This file carries the build tag, so a
   * script can say "r14 is serving" instead of "something is listening", and
   * `controllers` tells it whether the controller actually got in.
   *
   * Best effort by construction: a heartbeat must never be the reason a request
   * fails.
   */
  const beatHeartbeat = (): void => {
    try {
      const file = read().heartbeatFile ?? dshHomePath('dsh-remote', 'server-heartbeat.json')
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, `${JSON.stringify({
        build: BUILD,
        at: new Date().toISOString(),
        pid: process.pid,
        port: read().port ?? 0,
        host: read().host ?? '127.0.0.1',
        controllers: controllers.size,
        journalSeq: journal.lastSeq,
      })}\n`, 'utf8')
    } catch {
      // Diagnostics, not a dependency.
    }
  }

  const start = (): void => {
    stop()
    const current = read()
    const server = createServer((socket: Socket) => {
      const peer = `${socket.remoteAddress ?? '?'}:${socket.remotePort ?? 0}`
      const lease = disposed ? undefined : guard.admit(socket.remoteAddress ?? '?')
      if (lease === undefined) { socket.destroy(); return }
      sockets.add(socket)
      pendingSockets.add(socket)
      socket.once('close', () => {
        sockets.delete(socket)
        pendingSockets.delete(socket)
        lease.release()
      })
      void serve(socket, peer, lease).catch(error => {
        ctx.logger.debug(`dsh-remote-server: connection failed: ${String(error)}`)
        socket.destroy()
      })
    })
    server.on('error', (error: Error) => {
      ctx.logger.error(`dsh-remote-server: listener error: ${error.message}`)
    })
    server.listen(current.port ?? 11325, current.host ?? '127.0.0.1', () => {
      ctx.logger.info(
        `dsh-remote-server: listening on ${current.host ?? '127.0.0.1'}:${current.port ?? 11325}`,
      )
      // Written only once the bind succeeded: its presence means "this build
      // loaded AND is accepting", which is what a deploy script needs to decide
      // between committing the upgrade and rolling back.
      beatHeartbeat()
    })
    listener = server
    listeningAt = JSON.stringify([current.host, current.port])
  }

  const refreshPolicy = (): void => {
    try {
      const next = resolvePrivateKey(read(), 'server.key')
      if (fullKeyId(next.publicKey) !== fullKeyId(identity.publicKey)) {
        identity = next
        for (const principal of principalPolicies.keys()) cancelPrincipal(principal, new Error('server identity rotated'))
        principalPolicies.clear()
        for (const socket of pendingSockets) socket.destroy()
      }
    } catch (error) {
      for (const principal of principalPolicies.keys()) cancelPrincipal(principal, new Error('server identity is unavailable'))
      principalPolicies.clear()
      stop()
      ctx.logger.warn(`dsh-remote-server: identity update rejected: ${String(error)}`)
      return
    }
    enforcePolicies()
    const current = read()
    if (listeningAt !== JSON.stringify([current.host, current.port])) start()
  }

  // The settings service publishes this plugin's page from the `Config` schema
  // above; volatile edits land in the running references. A changed bind
  // address or port cannot take effect without rebinding, so restart.
  ctx.on('loader/volatile-update', refreshPolicy)

  start()
  // Enforce expiry even on disconnected principals whose accepted work is still
  // running. Settings edits invoke the same check immediately through the hook.
  const policyTimer = setInterval(() => { if (!disposed) refreshPolicy() }, 100)
  policyTimer.unref?.()
  // Teardown is best effort: on a hot reload the loader may already have
  // deactivated this context, and ctx.effect() throws in that window —which
  // would abort apply() and leave the previous build serving.
  try {
    ctx.effect(() => () => {
      disposed = true
      relayHub.dispose()
      clearInterval(policyTimer)
      for (const principal of principalPolicies.keys()) cancelPrincipal(principal, new Error('server disposed'))
      principalPolicies.clear()
      stop()
    }, 'dsh-remote-server: stop listener')
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register teardown (${String(error)})`)
  }
  // An in-flight upload holds a staging file next to its target. Releasing the
  // context without deleting it would leave `*.dshremote-upload` litter behind
  // on the peer's disk, so disposal is part of the upload's lifetime.
  try {
    ctx.effect(() => () => {
      if (capsPushTimer !== undefined) clearTimeout(capsPushTimer)
      for (const controller of controllers.keys()) controller.close()
      for (const owned of principalResources.values()) {
        owned.execs.cancelAll()
        for (const call of owned.activeToolCalls.values()) call.abort(new Error('server disposed'))
        owned.transfers.dispose()
        owned.uploadPaths.clear()
      }
      principalResources.clear()
    }, 'dsh-remote-server: transfers')
  } catch (error) {
    ctx.logger.warn(`dsh-remote-server: could not register transfer teardown (${String(error)})`)
  }
}
