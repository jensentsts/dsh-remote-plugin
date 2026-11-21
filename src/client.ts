/**
 * `dsh-remote-client` —the half that runs on the machine doing the driving.
 *
 * It dials the peer's listener, authenticates with pinned keys, and registers
 * the model-facing tools. The headline tool is `remote_agent_prompt`: it injects
 * a user message into a session on the *peer* harness, waits for the turn to
 * settle, and returns the assistant's reply —so this harness can use the other
 * one as an agent, with itself as that agent's user.
 *
 * One authenticated session is kept open and reused, and it is transparently
 * re-established when the tunnel drops a connection, so a tool call costs a
 * single round trip rather than a handshake per call.
 *
 * @module dsh-remote/client
 */

import type { Context, Volatile } from '@deepseek-ai/cordis'
import { isVolatile } from '@deepseek-ai/cosmokit'
import { createHash, randomUUID } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises'
import { dirname } from 'node:path'
import z from '@deepseek-ai/schemastery'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolDefinition } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
// Type-only: carries the `ctx.settings` and `ctx.tools` Context merges.
import type {} from '@deepseek-ai/dsh-settings'
import type { SettingsNamespace } from '@deepseek-ai/dsh-settings'
// Type-only: declares the `loader/volatile-update` event.
import type {} from '@deepseek-ai/cordis-plugin-loader'
// Type-only: declares `ctx.systemPrompt` and the `system-prompt/*` events.
import type {} from '@deepseek-ai/dsh-system-prompt'
// Type-only: declares `ctx.subagents` (the provider registration below).
import type {} from '@deepseek-ai/dsh-subagent'
// Type-only: declares the `agent/created` / `agent/disposed` events the mirror
// installers follow.
import type {} from '@deepseek-ai/dsh-agent'

import { LinkClient } from './link.ts'
import { meshSocketFactory } from './mesh-transport.ts'
import { PeerProfileSchema, PeerRegistry, assertPeerOperation, validatePeerNames } from './peers.ts'
import { configuredPeers, configuredDefaultPeer, defaultEndpoint } from './peer-configuration.ts'
import { createReferenceTool } from './reference-tool.ts'
import { mapRemoteReferences } from './reference-mapping.ts'
import type { PeerProfile } from './peers.ts'
import { fingerprint } from './protocol.ts'
import { createRemoteProvider } from './remote-provider.ts'
import { mergeReplyFrames, renderRemoteReplies, replyFields, replyFrame } from './reply-codec.ts'
import type { RemoteReply } from './reply-codec.ts'
import { createInboundIoAdapter, inboundExternalId, inboundReplySource, inboundSenderId, inboundText } from './remote-inbound.ts'
import type { RemoteInputMode } from './agent-delivery.ts'
import type { RemotePromptOutcome, RemoteSubagentKit } from './remote-provider.ts'
import { raceAbort } from './async.ts'
import { runCancellableExec } from './exec-client.ts'
import { REMOTE_SUBAGENT_TOOL, createRemoteSubagentTool } from './subagent-tool.ts'
import { createRunTools } from './remote-runs.ts'
import type { RunPromptRequest, RunSettlement, RunToolDeps } from './remote-runs.ts'
import { createPoolTools } from './remote-pool.ts'
import type { PoolDeps, PoolPeerProfile } from './remote-pool.ts'
import { createTeamTaskHooks } from './remote-team.ts'
import type { TeamFacade } from './remote-team.ts'
import {
  createOpProbe,
  downloadToFile,
  isAbortError as isTransferAbortError,
  uploadBuffer,
  uploadFile,
} from './transfer-client.ts'
import type { TransferOptions, TransferRequest } from './transfer-client.ts'
import { formatJournal } from './journal.ts'
import type { JournalView } from './journal.ts'
import {
  createProxySpecs,
  formatCatalog,
  parseCallResult,
  parseCatalog,
  proxyResultText,
} from './capabilities.ts'
import type {
  CapabilityCallResult,
  CapabilityCatalog,
  ProxySpec,
  SkippedTool,
} from './capabilities.ts'
import {
  anchorSessionId,
  freshSessionId,
  pickReusableSession,
  scopeKey,
  SessionMemory,
} from './reuse.ts'
import type { RemoteSession, SessionOrigin, SessionScope } from './reuse.ts'
import { RemoteCostStore, sanitizeSample } from './cost-report.ts'
import type { RemoteUsageRecord } from './cost-report.ts'
import {
  describeIdentity,
  dshHomePath,
  resolvePeerPublicKey,
  resolvePrivateKey,
  rawPublic,
  text,
} from './keys.ts'

/** Stable Cordis plugin name. */
export const name = 'dsh-remote-client'

/** Settings namespace the GUI edits (`settings.yaml` —`dsh-remote-client:`). */
export const DSH_REMOTE_CLIENT_SETTINGS_NAMESPACE = 'dsh-remote-client' as SettingsNamespace

/** Advertised in `remote_ping` results. */
export const CLIENT_VERSION = '0.5.3'

/**
 * Bumped on every source change, and surfaced in `remote_ping`.
 *
 * DSH does not re-import an already-loaded module, so after editing this file
 * the runtime keeps serving the previous build until a restart. Shipping the tag
 * on the wire turns "did my edit take effect?" into one tool call —the same
 * trick the server half uses.
 */
export const BUILD = 'c20'

/**
 * Plugin config. Every dial- and tool-time field is a `Volatile` reference, so
 * a committed settings edit mutates the running value in place instead of
 * remounting the plugin. `toolEnabled` stays ordinary on purpose: toggling the
 * tool set is a structural change, so it should re-run `apply`.
 */
export interface Config {
  /**
   * Peer host —whatever address actually reaches the other machine
   * (a frp tunnel endpoint, a LAN name, a Tailscale name, —.
   * Required: this plugin ships no default, on purpose.
   */
  host: Volatile<string>
  /** Peer port. Required, alongside `host`. */
  port: Volatile<number>
  /** Optional target node reached over the active mesh connection. */
  relayTarget: Volatile<string>
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
  /** Per-request socket timeout in milliseconds (default 120000). */
  timeoutMs: Volatile<number>
  /** Explicit pre-selector compatibility; false prevents automatic downgrade. */
  allowLegacyHandshake: Volatile<boolean>
  /** Maximum authenticated connection lifetime before fresh proof (default 1 h). */
  maxSessionMs: Volatile<number>
  /**
   * Chunk size in bytes for the chunked fast transfer path (default 1048576).
   *
   * Clamped to 64 KiB..8 MiB by the transfer module. Only used when the peer
   * advertises the `fs.put.*` / `fs.get` ops; an older peer keeps the legacy
   * single-frame path and ignores this.
   */
  transferChunkBytes: Volatile<number>
  /** Chunk requests kept in flight on the fast path (default 4, clamped 1..8). */
  transferConcurrency: Volatile<number>
  /** gzip each chunk when it clearly shrinks it (default true). */
  transferCompression: Volatile<boolean>
  /**
   * `remote_fs_write` uses the chunked fast path only when the UTF-8 content is
   * at least this many bytes (default 65536) and the peer advertises the ops.
   *
   * Below the threshold the single-frame `fs.write` is one round trip and wins;
   * above it, chunking + gzip is what lifts multi-megabyte writes off the floor.
   */
  transferFastPathBytes: Volatile<number>
  /** Register the model-facing tools (default true). */
  toolEnabled?: boolean
  /** Default session id prefix used by `remote_agent_prompt` when none is given. */
  sessionPrefix: Volatile<string>
  /**
   * Continue an existing remote conversation instead of opening a new one when
   * `remote_agent_prompt` gets no `session_id` (default true).
   *
   * On: the id is derived from the calling chat, so that chat always continues
   * the one conversation it owns —see `reuse.ts`. Off restores the old
   * behaviour, where every such call opened a brand-new session.
   */
  reuseSessions: Volatile<boolean>
  /**
   * When a chat has no conversation of its own yet, also adopt an *unclaimed*
   * one that already exists on the peer instead of creating another
   * (default false).
   *
   * Off by default on purpose: conversation identity should be derived from the
   * chat, not guessed from whatever happens to be lying around on the peer. Turn
   * this on to sweep up conversations left by an older build.
   */
  adoptExistingSessions: Volatile<boolean>
  /**
   * File remembering which conversation each scope uses
   * (default `${DSH_HOME}/dsh-remote/client-sessions.json`). Read once when the
   * plugin loads, unlike the volatile fields around it.
   *
   * A cache only: it may be deleted at any time, and a missing or corrupt file
   * degrades to "no memory" rather than to an error.
   */
  sessionMemoryFile: Volatile<string>
  /**
   * Contribute a system-prompt section telling local chats what this link is
   * for and which remote conversation they own (default true).
   */
  promptGuidance: Volatile<boolean>
  /**
   * Put asynchronous remote committed replies into the local Session that memory
   * already maps to that remote conversation, through the optional public
   * `superAgentIo` v1 service (default false).
   *
   * Only replies with no foreground/background RPC to return to are admitted
   * (typically the output of `agent.note`). A reply already delivered in an RPC
   * `replies` result is never injected a second time. The inbound binding has
   * `sendEnabled:false`, so the local agent's reaction is never routed back to
   * the peer automatically. Without the service, or with this switch off, the
   * ordinary RPC path is unchanged.
   */
  superAgentIoInbound: Volatile<boolean>
  /**
   * Present the peer as a DSH **subagent provider** named `remote`, with the
   * `subagent_remote` delegation tool (default true).
   *
   * On by default because it is what makes "the remote conversation is a task"
   * true rather than optional: delegation is grouped as a subagent, and a local
   * Stop reaches the peer through `agent.interrupt`. Needs
   * `@deepseek-ai/dsh-subagent` resolvable from this plugin; the kit is imported
   * lazily and a machine without it just logs a warning, so this default cannot
   * make the plugin unloadable. Toggling it is live —no composition edit, no
   * restart. Adding the official `tool-subagent` row instead would additionally
   * give background runs (same tool name, so use one or the other).
   */
  subagentProvider: Volatile<boolean>
  /**
   * Register the background-run control plane —`remote_run_start`,
   * `remote_run_status`, `remote_run_cancel` and `remote_send_message`
   * (default true).
   *
   * A background run is the same peer prompt as `remote_agent_prompt`, except
   * the tool answers as soon as the request is on the wire and the outcome is
   * collected later from the run registry (one chat —one remote conversation
   * still holds). Off leaves the four tools unregistered; the delegation tool
   * and the foreground prompt are unaffected. The tool set is chosen when
   * `apply` runs, while the system-prompt hint below follows the live value.
   */
  backgroundRuns: Volatile<boolean>
  /**
   * Most background runs allowed at the same time (default 8).
   *
   * Enforced by `remote_run_start`, read live: a run the model forgot to collect
   * still occupies a slot until it settles (or is pruned as settled), so this is
   * the ceiling that keeps a chat from burying the peer in queued turns.
   */
  maxBackgroundRuns: Volatile<number>
  /**
   * Report the peer's token usage to the local `dsh-cost-meter` by maintaining
   * `${DSH_HOME}/storages/cost-meter/external_usage.json` (default true).
   *
   * After every remote turn this side asks the peer for the new `usage.read`
   * records and appends them to a small local store, then rewrites the whole
   * snapshot atomically (cost-meter re-reads it on every state refresh). Off
   * means nothing is collected and no cost file is written. Checked live on
   * every turn, so flipping it takes effect without a remount.
   */
  costReporting: Volatile<boolean>
  /**
   * Snapshot source-name prefix, before the peer name (default `remote/`).
   *
   * The source shown in cost-meter is `costSourcePrefix + peerName`, e.g.
   * `remote/default`. Sources already in the snapshot that do NOT start with
   * this prefix belong to other producers and are preserved verbatim.
   */
  costSourcePrefix: Volatile<string>
  /**
   * File holding this plugin's remote-usage records and per-session cursors
   * (default `${DSH_HOME}/dsh-remote/client-cost.json`).
   *
   * A cache: a missing or corrupt file degrades to "no history", never to an
   * error. Kept across restarts so only new peer events are fetched each turn.
   */
  costStoreFile: Volatile<string>
  /**
   * The cost-meter snapshot this plugin produces
   * (default `${DSH_HOME}/storages/cost-meter/external_usage.json`).
   *
   * This is cost-meter's one official third-party data entry point; write it
   * only through this plugin so the whole-snapshot atomic-replace contract and
   * cost-meter's strict validation keep holding.
   */
  costSnapshotFile: Volatile<string>
  /**
   * The single peer's name, used when only `host`/`port` are configured.
   * Defaults to `default`. Declaring `peers` instead makes this moot.
   */
  peerName: Volatile<string>
  /**
   * Named peers. This is the **one** place a deployment declares a peer: the
   * registry below is published as a service, so the peer filesystem provider
   * mounts the same declarations instead of repeating the addresses.
   */
  peers: Volatile<Record<string, PeerProfile>>
  /**
   * The peer a bare `rmt:` path means (empty = the first declared peer).
   *
   * This is the "default remote machine" of the `@rmt:/…` spelling; named peers
   * stay addressable as `@<peer>:/…`. Read live by the filesystem provider
   * through the shared registry, so editing it needs no restart.
   */
  defaultPeer: Volatile<string>
  /**
   * Mirror the peer's function-call surface onto this machine (default true).
   *
   * The peer answers `caps.list` with the tools one of its agent presets
   * contributes (plus host-level tools). Each callable one is registered here
   * under its OWN name (zero prefix: a local tool of the same name shadows it,
   * so nothing local is ever overridden), and its body runs on the peer through
   * `caps.call` —the peer's own tool body, no agent and no session there.
   *
   * Off means no mirrors and no catalog watches; `remote_capabilities` and
   * `remote_tool_call` also go away, because both would be dead ends.
   */
  remoteCapabilities: Volatile<boolean>
  /**
   * Agent preset on the peer whose tool surface is mirrored, when the peer's
   * default should not be used (default: empty = the peer's default preset).
   *
   * A preset is where the interesting tools live (`standard`, `cordis`, —, so
   * this picks which plugin set becomes callable here.
   */
  capabilityPreset: Volatile<string>
  /**
   * Re-read the peer's catalog on this interval, in seconds (default 300; 0
   * disables the timer).
   *
   * The peer also pushes `caps.changed` when its tool registry changes, so this
   * is the slow safety net for a missed frame, not the main path.
   */
  capabilityRefreshSeconds: Volatile<number>
  /**
   * Wait for one `caps.call` at most this long, in milliseconds (default
   * 600000). Capped by the peer's own `maxToolCallTimeoutMs`.
   */
  capabilityTimeoutMs: Volatile<number>
  /**
   * Extra names (or trailing-`*` prefixes) to keep out of the local mirror
   * (default empty).
   *
   * The peer already refuses its own bridge and interactive tools; this is the
   * controller-side belt for a deployment that wants one specific remote tool
   * unreachable even though the peer would run it.
   */
  capabilityDeny: Volatile<string[]>
}

/**
 * Plain values behind every reference of a parsed {@link Config}. Downstream
 * code (link, keys, peer registry) reads these, so it stays unaware of the
 * volatile indirection.
 */
export type ResolvedConfig = { [K in keyof Config]-?: Config[K] extends Volatile<infer T> ? T : Config[K] }

export const Config = z.object({
  // No defaults: the link is a per-deployment fact, not a product constant.
  host: z.string().default('').volatile(),
  port: z.number().default(0).volatile(),
  relayTarget: z.string().default('').volatile(),
  // `role('secret')` keeps the value out of settings-GUI wire payloads.
  privateKey: z.string().role('secret').default('').volatile(),
  privateKeyFile: z.string().default(dshHomePath('dsh-remote', 'client.key')).volatile(),
  autoGenerateKey: z.boolean().default(true).volatile(),
  peerPublicKey: z.string().default('').volatile(),
  peerPublicKeyFile: z.string().default(dshHomePath('dsh-remote', 'server.pub')).volatile(),
  timeoutMs: z.number().default(120_000).volatile(),
  allowLegacyHandshake: z.boolean().default(false).volatile(),
  maxSessionMs: z.number().default(3_600_000).volatile(),
  transferChunkBytes: z.number().default(1_048_576).volatile(),
  transferConcurrency: z.number().default(4).volatile(),
  transferCompression: z.boolean().default(true).volatile(),
  transferFastPathBytes: z.number().default(524_288).volatile(),
  toolEnabled: z.boolean().default(true),
  sessionPrefix: z.string().default('remote').volatile(),
  reuseSessions: z.boolean().default(true).volatile(),
  adoptExistingSessions: z.boolean().default(false).volatile(),
  sessionMemoryFile: z.string().default(dshHomePath('dsh-remote', 'client-sessions.json')).volatile(),
  promptGuidance: z.boolean().default(true).volatile(),
  superAgentIoInbound: z.boolean().default(false).volatile(),
  subagentProvider: z.boolean().default(true).volatile(),
  backgroundRuns: z.boolean().default(true).volatile(),
  maxBackgroundRuns: z.number().default(8).volatile(),
  costReporting: z.boolean().default(true).volatile(),
  costSourcePrefix: z.string().default('remote/').volatile(),
  costStoreFile: z.string().default(dshHomePath('dsh-remote', 'client-cost.json')).volatile(),
  costSnapshotFile: z.string().default(dshHomePath('storages', 'cost-meter', 'external_usage.json')).volatile(),
  peerName: z.string().default('default').volatile(),
  peers: z.dict(PeerProfileSchema).default({}).volatile(),
  defaultPeer: z.string().default('').volatile(),
  remoteCapabilities: z.boolean().default(true).volatile(),
  capabilityPreset: z.string().default('').volatile(),
  capabilityRefreshSeconds: z.number().default(300).volatile(),
  capabilityTimeoutMs: z.number().default(600_000).volatile(),
  capabilityDeny: z.array(z.string()).default([]).volatile(),
})

/** Read the current plain value behind every reference of a parsed Config. */
function plainConfig(config: Config): ResolvedConfig {
  return Object.fromEntries(
    Object.entries(config).map(([key, value]) => [key, isVolatile(value) ? value.get() : value]),
  ) as ResolvedConfig
}


/** Render a result the way the model should read it. */
function renderText(text: string): Array<{ type: 'text', text: string }> {
  return [{ type: 'text', text }]
}

function fmtBytes(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / 1024 / 1024).toFixed(1)} MB`
}

/**
 * Mount the client: register the remote tools and publish the peer registry.
 *
 * Every dial-time field is volatile, so the settings service derives this
 * plugin's page from its own `Config` schema and a committed edit mutates the
 * running references in place. `loader/volatile-update` then drops the live
 * session so endpoint or key changes are never served by a link dialled from
 * the old values.
 *
 * @param ctx - the plugin's cordis context.
 * @param config - resolved plugin config; the schema supplies every default.
 */
export function apply(ctx: Context, config: Config): void {
  const read = (): ResolvedConfig => plainConfig(config)
  const log = (message: string): void => { ctx.logger.info(message) }

  // Report our identity at boot and make sure the peer key is reachable, so a
  // misconfiguration shows up in the log rather than on the first tool call.
  try {
    const identity = resolvePrivateKey(read(), 'client.key')
    log(`dsh-remote-client: identity ${describeIdentity(identity)}`)
    resolvePeerPublicKey(read(), 'server.pub')
  } catch (error) {
    log(`dsh-remote-client: ${error instanceof Error ? error.message : String(error)}`)
  }
  const peersNow = (): Record<string, PeerProfile> => configuredPeers(read())
  const defaultPeerNow = (): string => configuredDefaultPeer(read())
  const endpointNow = (): PeerProfile => defaultEndpoint(read())
  const sessionPrefixNow = (): string => {
    const current = read()
    const base = text(current.sessionPrefix) ?? 'remote'
    const peer = operationPeer.getStore()?.name ?? defaultPeerNow()
    const legacy = text(current.peerName) ?? 'default'
    return peer === legacy ? base : `${base}-${createHash('sha256').update(peer).digest('hex').slice(0, 10)}`
  }
  validatePeerNames(Object.keys(peersNow()))
  if (Object.keys(peersNow()).length === 0) {
    log(
      'dsh-remote-client: no peer endpoint configured yet — set `host` and `port` in '
      + "this plugin's settings (dsh-remote-client) before calling remote_* tools.",
    )
  }

  // Pin an operation's destination for its whole async lifetime. A settings edit
  // must never redirect an already-running task's cancellation to another host.
  const operationPeer = new AsyncLocalStorage<{ name: string; profile: PeerProfile; link: LinkClient }>()
  const controlLinks = new Map<string, { profile: PeerProfile; link: LinkClient }>()
  const sessionBindings = new Map<string, { name: string; authority: string }>()
  let retired = false
  const authorityOf = (profile: PeerProfile): string => createHash('sha256').update(JSON.stringify([
    profile.host, profile.port, profile.relayTarget ?? '', profile.allowLegacyHandshake === true,
    rawPublic(resolvePeerPublicKey(profile, 'server.pub')).toString('hex'),
    rawPublic(resolvePrivateKey(profile, 'client.key').publicKey).toString('hex'),
  ])).digest('hex')
  let onControlEvent: (frame: Record<string, unknown>) => void = () => {}
  const controlFor = (name = defaultPeerNow()) => {
    if (retired) throw new Error('Remote plugin disposed; old callbacks cannot reconnect')
    const latest = peersNow()[name]
    if (latest === undefined) throw new Error(`Unknown or revoked peer "${name}"`)
    const profile = { ...latest }
    const key = `${name}\0${createHash('sha256').update(JSON.stringify(profile)).digest('hex')}`
    let entry = controlLinks.get(key)
    if (entry === undefined) {
      const transport = new LinkClient(() => {
        const live = peersNow()[name]
        if (live === undefined) throw new Error('Remote host was revoked')
        return live
      }, log, `dsh-remote:${name}`, meshSocketFactory(ctx))
      transport.onEvent(frame => operationPeer.run({ name, profile, link: transport }, () => onControlEvent(frame)))
      entry = { profile, link: transport }
      controlLinks.set(key, entry)
    }
    return { name, ...entry }
  }
  const link = {
    async request(op: string, args: Record<string, unknown> = {}, timeoutMs?: number, options: { retries?: number } = {}) {
      if (retired) throw new Error('Remote plugin disposed')
      const current = operationPeer.getStore() ?? controlFor()
      const sessionId = typeof args.sessionId === 'string' ? args.sessionId : undefined
      const binding = sessionId === undefined ? undefined : sessionBindings.get(sessionId)
      if (binding !== undefined && (op === 'agent.prompt' || op === 'agent.ensure') && binding.name !== current.name) {
        throw new Error('This remote session ID is bound to another host; choose its original host or a distinct explicit session ID')
      }
      const target = binding === undefined ? current : controlFor(binding.name)
      const latest = peersNow()[target.name]
      if (latest === undefined) throw new Error('Remote host was revoked')
      const authority = authorityOf(latest)
      if (authority !== authorityOf(target.profile) || binding !== undefined && authority !== binding.authority) {
        throw new Error('Remote identity or endpoint changed; an existing session cannot migrate to new trust automatically')
      }
      if (sessionId !== undefined && (op === 'agent.prompt' || op === 'agent.ensure')) sessionBindings.set(sessionId, { name: target.name, authority })
      assertPeerOperation(latest.maxPermission ?? 1, op, {
        peer: target.name, workspaceRoot: latest.workspaceRoot ?? '',
        ...(typeof args.path === 'string' ? { path: args.path } : {}),
      })
      return target.link.request(op, args, timeoutMs, options)
    },
    get connected() { return (operationPeer.getStore() ?? controlFor()).link.connected },
    notify(payload: Record<string, unknown>) {
      if (retired) throw new Error('Remote plugin disposed')
      const qid = typeof payload.qid === 'string' ? payload.qid : ''
      const question = relayedQuestions.get(qid)
      const binding = question === undefined ? undefined : sessionBindings.get(question.sessionId)
      const target = binding === undefined ? operationPeer.getStore() ?? controlFor() : controlFor(binding.name)
      const latest = peersNow()[target.name]
      if (latest === undefined || binding !== undefined && authorityOf(latest) !== binding.authority) throw new Error('Question destination is no longer authorized')
      assertPeerOperation(latest.maxPermission ?? 1, 'agent.prompt', { peer: target.name })
      return target.link.notify(payload)
    },
    onEvent(handler: (frame: Record<string, unknown>) => void) { onControlEvent = handler },
    close() { for (const entry of controlLinks.values()) entry.link.dispose(); controlLinks.clear() },
    dispose() { retired = true; this.close() },
  }
  const bindOperation = (definition: ToolDefinition): ToolDefinition => ({
    ...definition,
    execute: async (args, exec) => operationPeer.run(operationPeer.getStore() ?? controlFor(), () => definition.execute(args, exec)),
  })

  // ---------------------------------------------------------------------------
  // Capability federation —the peer's tools, called as if they were local
  //
  // The peer lists its function-call surface (`caps.list`) and runs one tool
  // body on request (`caps.call`). Each callable tool is mirrored here under its
  // OWN name (zero prefix), inside the scope of the agent that may call it —  // never in the global layer.
  //
  // Scope placement is the whole safety argument. A global registration would
  // fight every host plugin for a name: a mirror of the peer's
  // `load_workspace_dependencies` took the global name first and the real
  // `dsh-tool-workspace-dependencies` plugin then failed its own registration
  // at boot. An agent scope has no such contest —a name already visible to
  // that agent (its preset's tools, host plugins) is simply SKIPPED, so local
  // capabilities always win and no other plugin can ever collide with a mirror.
  //
  // Nothing here creates or resumes a remote conversation: a catalog read takes
  // a preset-scope lease on the peer, and a call runs the tool definition there.
  // ---------------------------------------------------------------------------

  /** Agent preset the peer should describe; undefined = its deployment default. */
  const capabilityPresetArg = (): string | undefined => text(read().capabilityPreset)

  /** Timeout for one mirrored call, in milliseconds. */
  const capabilityCallTimeout = (): number => {
    const configured = Number(read().capabilityTimeoutMs ?? 600_000)
    return Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : 600_000
  }

  /** Whether a peer endpoint is configured at all (mirroring is opted out elsewhere). */
  const endpointConfigured = (): boolean => {
    try { const endpoint = endpointNow(); return text(endpoint.host) !== undefined && (endpoint.port ?? 0) > 0 }
    catch { return false }
  }

  /** Peer tools this controller keeps out of the mirror, on top of the peer's own refusals. */
  const capabilityDeniedLocally = (name: string): boolean => {
    for (const entry of read().capabilityDeny ?? []) {
      const pattern = typeof entry === 'string' ? entry.trim() : ''
      if (pattern === '') continue
      if (pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern) return true
    }
    return false
  }

  let capabilityCatalog: CapabilityCatalog | undefined
  let capabilityGeneration = 0
  let capabilityCatalogAt = 0
  let capabilityInFlight: Promise<CapabilityCatalog | undefined> | undefined
  /** Fingerprint of the last catalog the mirrors were built from. */
  let capabilityCatalogFingerprint = ''
  /** Peer reported no `caps.list` (an older build): stop asking. */
  let capabilityUnsupported = false
  let capabilityWarned = false
  /** Last logged mirror counts, so a periodic refetch stays quiet when unchanged. */
  let capabilityMirrorSummary = ''
  let capabilityWatch: ReturnType<typeof setInterval> | undefined

  /** Mirrors installed into one live agent's own scope. */
  interface AgentMirrorInstall {
    /** Disposes the inject fiber (awaitable): unregisters every tool it added. */
    dispose: () => unknown
    /** Mirror names this agent got. */
    names: Set<string>
    /** Catalog entries left out for THIS agent, and why. */
    skipped: SkippedTool[]
  }
  /** Agent object -> the mirrors installed in its scope. */
  const agentMirrors = new Map<object, AgentMirrorInstall>()

  /** The live Agent registry, when the composition has one. */
  const liveAgents = (): Array<{ ctx: Context, id?: unknown }> => {
    try {
      const service = (ctx as unknown as { get?: (name: string) => unknown }).get?.('agents') as
        | { list?: () => unknown }
        | undefined
      const list = service?.list?.()
      return Array.isArray(list) ? list as Array<{ ctx: Context, id?: unknown }> : []
    } catch {
      return []
    }
  }

  /**
   * Drop one agent's mirrors (its scope is going away, or the catalog changed).
   *
   * Awaitable on purpose: tool unregistration settles asynchronously, and a
   * reinstall that raced it would hit "already registered in this scope" and
   * silently leave that agent without mirrors until the next refresh.
   */
  const teardownAgentMirrors = async (agent: object): Promise<void> => {
    const entry = agentMirrors.get(agent)
    if (entry === undefined) return
    agentMirrors.delete(agent)
    try {
      await entry.dispose()
    } catch (error) {
      ctx.logger.debug(`dsh-remote-client: could not withdraw one agent's mirrors (${String(error)})`)
    }
  }

  /** Drop every agent's mirrors (feature off, or the peer has no catalog). */
  const withdrawCapabilityMirrors = async (): Promise<void> => {
    for (const agent of [...agentMirrors.keys()]) await teardownAgentMirrors(agent)
    capabilityMirrorSummary = ''
  }

  /**
   * Run one peer tool directly.
   *
   * Deliberately non-idempotent from the transport's point of view: a dropped
   * reply means the body MAY already have run on the peer, so replaying could
   * run it twice. `retries: 0` is the same rule the file writer's commit takes.
   */
  const callPeerTool = async (
    name: string,
    args: Record<string, unknown>,
    signal?: AbortSignal,
    options: { presetId?: string, timeoutMs?: number, peer?: string } = {},
  ): Promise<CapabilityCallResult> => {
    const callId = `caps-${randomUUID()}`
    const presetId = options.presetId ?? capabilityPresetArg()
    const requested = options.timeoutMs !== undefined && Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
      ? Math.floor(options.timeoutMs)
      : capabilityCallTimeout()
    const destination = options.peer === undefined || options.peer === defaultPeerNow() ? link : poolLinkFor(options.peer)
    const pending = destination.request(
      'caps.call',
      {
        callId,
        name,
        arguments: args,
        ...(presetId === undefined ? {} : { presetId }),
      },
      Math.min(requested, capabilityCallTimeout()),
      { retries: 0 },
    )
    try {
      const reply = signal === undefined ? await pending : await raceAbort(pending, signal)
      return parseCallResult(reply)
    } catch (error) {
      if ((error as { name?: string } | null)?.name === 'AbortError') {
        // The local call has already settled; the work on the peer still needs
        // its own stop, exactly like `remote_exec`'s process.
        void destination.request('caps.cancel', { callId }, 10_000, { retries: 0 }).catch(() => {})
      }
      throw error
    }
  }

  /** Build the local ToolDefinition that mirrors one peer tool. */
  const mirrorDefinition = (spec: ProxySpec): ToolDefinition => ({
    name: spec.name,
    description: spec.description,
    parameters: spec.parameters,
    output: {
      schema: {},
      render: (_args: unknown, value: JsonValue) => renderText(proxyResultText(
        parseCallResult(value as unknown as Record<string, unknown>),
      )),
    },
    async execute(args: unknown, exec: { signal?: AbortSignal }): Promise<JsonValue> {
      const result = await spec.call((args ?? {}) as Record<string, unknown>, exec?.signal)
      return {
        content: result.content,
        ...(result.durationMs === undefined ? {} : { durationMs: result.durationMs }),
      } as unknown as JsonValue
    },
  } as unknown as ToolDefinition)

  /** A catalog's stable identity: unchanged means no re-registration churn. */
  const catalogIdentity = (catalog: CapabilityCatalog): string => createHash('sha256')
    .update(JSON.stringify({
      presetId: catalog.presetId,
      tools: [...catalog.tools]
        .sort((left, right) => left.name.localeCompare(right.name))
        .map(tool => [tool.name, tool.callable, tool.description, tool.parameters]),
    }))
    .digest('hex')

  /**
   * Install mirrors into ONE agent's own scope.
   *
   * `toolsCtx.tools.schemas(agent)` is the complete visible surface for that
   * agent (host tools + its preset's tools + its own layer). A peer tool whose
   * name is already in that set is skipped: local wins, and a mirror can never
   * shadow or collision with a plugin that registered first OR later.
   *
   * The injected fiber owns every registration, so dropping it removes exactly
   * these mirrors and nothing else.
   */
  const installAgentMirrors = (agent: { ctx: Context, id?: unknown }): void => {
    if (read().remoteCapabilities === false) return
    const catalog = capabilityCatalog
    if (catalog === undefined || !catalog.available) return
    if (typeof agent?.ctx?.inject !== 'function') return
    const key = agent as unknown as object
    if (agentMirrors.has(key)) return
    const names = new Set<string>()
    const skipped: SkippedTool[] = []
    const installedGeneration = capabilityGeneration
    const destination = controlFor()
    const fiber = agent.ctx.inject(['tools'], (toolsCtx: Context) => {
      const visible = new Set(toolsCtx.tools.schemas(agent as never).map(row => row.name))
      const allowed = catalog.tools.filter(tool => !capabilityDeniedLocally(tool.name))
      const denied = catalog.tools
        .filter(tool => capabilityDeniedLocally(tool.name))
        .map(tool => ({ name: tool.name, reason: 'denied by this controller (capabilityDeny)' }))
      const result = createProxySpecs({ ...catalog, tools: allowed }, (name, args, signal) => {
        if (installedGeneration !== capabilityGeneration) throw new Error('Remote configuration changed; refresh the capability catalog before calling this tool')
        return operationPeer.run(destination, () => callPeerTool(name, args, signal))
      }, name => visible.has(name))
      skipped.push(...result.skipped, ...denied)
      for (const spec of result.specs) {
        try {
          toolsCtx.tools.register(mirrorDefinition(spec))
          names.add(spec.name)
        } catch (error) {
          skipped.push({
            name: spec.name,
            reason: `could not register locally: ${error instanceof Error ? error.message : String(error)}`,
          })
        }
      }
      skipped.sort((left, right) => left.name.localeCompare(right.name))
    })
    agentMirrors.set(key, {
      names,
      skipped,
      dispose: () => {
        // `inject` returns a Cordis Fiber; a fake context in a self-test may hand
        // back a plain disposer instead, so accept both. Returning the promise
        // matters: tool unregistration settles asynchronously.
        const disposable = fiber as unknown as
          | { dispose?: () => unknown }
          | (() => void)
          | undefined
        if (typeof disposable === 'function') return disposable()
        return disposable?.dispose?.()
      },
    })
  }

  /** `installAgentMirrors`, but one agent's failure can never break the sweep. */
  const installAgentMirrorsSafe = (agent: { ctx: Context, id?: unknown }): void => {
    try {
      installAgentMirrors(agent)
    } catch (error) {
      ctx.logger.debug(`dsh-remote-client: could not mirror into one agent scope (${String(error)})`)
    }
  }

  /** Rebuild mirrors so every live agent matches the current catalog. */
  const syncCapabilityMirrors = async (force = false): Promise<void> => {
    const catalog = capabilityCatalog
    if (read().remoteCapabilities === false || catalog === undefined || !catalog.available) {
      await withdrawCapabilityMirrors()
      return
    }
    const identity = catalogIdentity(catalog)
    if (!force && identity === capabilityCatalogFingerprint) {
      // Unchanged catalog: only cover agents that appeared while the tools
      // service was unavailable (normally `agent/created` already did this).
      for (const agent of liveAgents()) installAgentMirrorsSafe(agent)
      return
    }
    capabilityCatalogFingerprint = identity
    await withdrawCapabilityMirrors()
    for (const agent of liveAgents()) installAgentMirrorsSafe(agent)

    const mirrored = new Set<string>()
    let worstSkipped = 0
    for (const entry of agentMirrors.values()) {
      for (const name of entry.names) mirrored.add(name)
      worstSkipped = Math.max(worstSkipped, entry.skipped.length)
    }
    const summary = `${mirrored.size}/${catalog.tools.length}/${worstSkipped}/${agentMirrors.size}`
    if (summary !== capabilityMirrorSummary) {
      capabilityMirrorSummary = summary
      log(
        `dsh-remote-client: mirrored ${mirrored.size}/${catalog.tools.length} remote tools `
        + `into ${agentMirrors.size} agent scope(s)`
        + (worstSkipped === 0 ? '' : ` (${worstSkipped} skipped per agent)`),
      )
    }
  }

  /**
   * Read the peer's catalog (cached for `capabilityRefreshSeconds`) and mirror it.
   *
   * An older peer answers "unknown op" to `caps.list`; that is not an error to
   * retry every call, so it latches the feature off for this process and logs
   * once. Any other failure keeps the last catalog and is retried later.
   */
  const refreshCapabilityCatalog = async (force = false): Promise<CapabilityCatalog | undefined> => {
    if (read().remoteCapabilities === false || capabilityUnsupported) return capabilityCatalog
    if (!endpointConfigured()) return capabilityCatalog
    const seconds = Number(read().capabilityRefreshSeconds ?? 300)
    const ttlMs = (Number.isFinite(seconds) && seconds > 0 ? Math.max(30, seconds) : 300) * 1000
    if (!force && capabilityCatalog !== undefined && Date.now() - capabilityCatalogAt < ttlMs) return capabilityCatalog
    if (capabilityInFlight !== undefined) return await capabilityInFlight
    const generation = capabilityGeneration
    capabilityInFlight = (async () => {
      try {
        const presetId = capabilityPresetArg()
        const reply = await link.request(
          'caps.list',
          presetId === undefined ? {} : { presetId },
          Math.max(read().timeoutMs ?? 120_000, 30_000),
        )
        if (generation !== capabilityGeneration) return capabilityCatalog
        capabilityCatalog = parseCatalog(reply)
        capabilityCatalogAt = Date.now()
        capabilityWarned = false
        if (!capabilityCatalog.available) {
          ctx.logger.debug(
            `dsh-remote-client: peer capability catalog unavailable: ${capabilityCatalog.reason ?? 'no reason given'}`,
          )
        }
        await syncCapabilityMirrors()
        return capabilityCatalog
      } catch (error) {
        if (generation !== capabilityGeneration) return capabilityCatalog
        const message = error instanceof Error ? error.message : String(error)
        if (/unknown op|unsupported op/iu.test(message)) {
          capabilityUnsupported = true
          log(
            'dsh-remote-client: the peer predates capability federation (no caps.list); '
            + 'remote tools are not mirrored',
          )
        } else if (!capabilityWarned) {
          capabilityWarned = true
          log(`dsh-remote-client: capability catalog fetch failed (${message}); will retry`)
        }
        return capabilityCatalog
      } finally {
        if (generation === capabilityGeneration) capabilityInFlight = undefined
      }
    })()
    return await capabilityInFlight
  }

  /** Poll the peer slowly; its `tools/change` push is the fast path. */
  const startCapabilityWatch = (): void => {
    if (capabilityWatch !== undefined) return
    const seconds = Number(read().capabilityRefreshSeconds ?? 300)
    if (!Number.isFinite(seconds) || seconds <= 0) return
    capabilityWatch = setInterval(() => { void refreshCapabilityCatalog(true) }, Math.max(30, seconds) * 1000)
    capabilityWatch.unref?.()
  }

  /**
   * Start mirroring once the local tools service exists.
   *
   * Mirrors are per agent, so this only has to cover agents that already exist
   * and install the event listeners for the ones that come later.
   */
  const attachCapabilityMirrors = (): void => {
    if (read().remoteCapabilities === false) return
    try {
      ctx.on('agent/created', ({ agent }: { agent: { ctx: Context, id?: unknown } }) => {
        installAgentMirrorsSafe(agent)
      })
      ctx.on('agent/disposed', ({ agent }: { agent: { ctx: Context, id?: unknown } }) => {
        void teardownAgentMirrors(agent as unknown as object)
      })
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not watch agent lifecycle (${String(error)})`)
    }
    // A catalog fetched before this moment is applied now; otherwise this starts
    // the first fetch in the background and mirrors land via `syncCapabilityMirrors`.
    void syncCapabilityMirrors()
    void refreshCapabilityCatalog(capabilityCatalog === undefined)
    startCapabilityWatch()
  }

  /** Mirror names one agent actually got. */
  const mirroredNamesFor = (agent: unknown): Set<string> => {
    if (agent === undefined || agent === null) return new Set<string>()
    const entry = agentMirrors.get(agent as object)
    return new Set(entry?.names ?? [])
  }

  /** The text a catalog listing gets: the peer's own rendering, plus local notes. */
  const renderCapabilityCatalog = (tool?: string, agent?: unknown): string => {
    const catalog = capabilityCatalog
    if (catalog === undefined) {
      return endpointConfigured()
        ? '还没有取到远端能力目录；这通常意味着对端连不上或版本过旧。'
        : '还没有配置对端 host/port，无法读取远端能力目录。'
    }
    const mirrored = mirroredNamesFor(agent)
    // A callable tool this agent did NOT get is hidden here by a local tool of
    // the same name (the install step skipped it) or by `capabilityDeny`.
    const shadowed = new Set(catalog.tools
      .filter(toolRow => toolRow.callable && !mirrored.has(toolRow.name) && !capabilityDeniedLocally(toolRow.name))
      .map(toolRow => toolRow.name))
    return formatCatalog(catalog, { ...(tool === undefined ? {} : { tool }), shadowed })
  }

  /** Read one catalog straight from the peer, for a one-off preset query. */
  const readPeerCatalog = async (presetId?: string, peer?: string): Promise<CapabilityCatalog> => {
    const destination = peer === undefined || peer === defaultPeerNow() ? link : poolLinkFor(peer)
    const reply = await destination.request(
      'caps.list',
      presetId === undefined || presetId === '' ? {} : { presetId },
      Math.max(read().timeoutMs ?? 120_000, 30_000),
    )
    return parseCatalog(reply)
  }

  /** The JSON payload `remote_capabilities` returns beside its rendered text. */
  const catalogSummary = (catalog: CapabilityCatalog, agent?: unknown): Record<string, unknown> => {
    const mirrored = mirroredNamesFor(agent)
    return {
      available: catalog.available,
      ...(catalog.reason === undefined ? {} : { reason: catalog.reason }),
      presetId: catalog.presetId,
      tools: catalog.tools.map((tool) => ({
        name: tool.name,
        callable: tool.callable,
        origin: tool.origin,
        mirrored: mirrored.has(tool.name),
        ...(tool.reason === undefined ? {} : { reason: tool.reason }),
      })),
      presets: catalog.presets,
      plugins: catalog.plugins,
      sessions: catalog.sessions,
      subagentProviders: catalog.subagentProviders,
    }
  }


  // ---------------------------------------------------------------------------
  // Fast (chunked + compressed) file transfer
  //
  // The plain `fs.write`/`fs.read` ops move a whole file in one base64 frame,
  // which over a tunnel is slow and timeout-prone. Recent peers advertise
  // `fs.put.*` + `fs.get`; this side uses them only when advertised, and every
  // call site keeps the legacy op as the fallback so an older peer is unaffected.
  // ---------------------------------------------------------------------------

  /** `link.request` in the shape the transfer module expects. */
  const transferRequest: TransferRequest = (op, args, timeoutMs) => link.request(op, args, timeoutMs)

  /**
   * Cached "does the peer support the fast path?" probe (10 minutes, failures
   * never cached). See `transfer-client.ts` for why failures must not stick.
   */
  const fastTransferSupported = createOpProbe(transferRequest)

  /** Current transfer knobs, read live from the volatile config. */
  const transferOptions = (signal?: AbortSignal): TransferOptions => ({
    chunkSize: read().transferChunkBytes,
    concurrency: read().transferConcurrency,
    compression: read().transferCompression !== false,
    ...(signal === undefined ? {} : { signal }),
  })

  /**
   * Is this failure "the peer does not know this op after all"?
   *
   * Only that case may fall back to the legacy path: a real error (permission,
   * stale version, checksum) must surface, and a cancellation must never be
   * silently retried through another route.
   */
  const isUnknownTransferOp = (error: unknown): boolean => {
    if (isTransferAbortError(error)) return false
    const code = (error as { peerCode?: unknown } | null)?.peerCode
    if (code === 'FS_UNSUPPORTED' || code === 'FS_UNKNOWN_OP') return true
    const message = error instanceof Error ? error.message : String(error)
    return /unknown op|unsupported op|not supported|no such op/iu.test(message)
  }

  /** Reject as an `AbortError` once a local Stop has fired. */
  const throwIfAborted = (signal?: AbortSignal): void => {
    if (signal?.aborted !== true) return
    const error = new Error('transfer aborted')
    error.name = 'AbortError'
    throw error
  }

  /**
   * Did the upload fail at the `commit` request itself?
   *
   * That is the one phase whose outcome is genuinely unknown: the peer may have
   * renamed the target while the reply was lost on the wire. Callers must NOT
   * blindly replay the write (it could clobber a file that is already correct);
   * they surface the error with a "verify first" hint instead.
   */
  const commitOutcomeUnknown = (error: unknown): boolean =>
    (error as { transferPhase?: unknown } | null)?.transferPhase === 'commit'

  /** Wrap an ambiguous commit failure in a message the model can act on. */
  const ambiguousCommitError = (error: unknown): Error => new Error(
    `${error instanceof Error ? error.message : String(error)}`
    + '；目标可能已写入（commit 结果未知），请先查看/校验目标文件再决定是否重试',
  )

  /** Mbit/s, the same unit the transfer module reports. */
  const rateMbps = (bytes: number, durationMs: number): number =>
    bytes <= 0 || durationMs <= 0
      ? 0
      : Math.round((bytes * 8) / 1e6 / (durationMs / 1000) * 100) / 100

  /** `<target>.<random>.dshremote-tmp` in the target directory, so rename is local. */
  const tempPathFor = (localPath: string): string =>
    `${localPath}.${randomUUID().replace(/-/gu, '').slice(0, 12)}.dshremote-tmp`

  /** Rename over an existing target, tolerating Windows EPERM/EBUSY close races. */
  const replaceLocalFile = async (tempPath: string, targetPath: string): Promise<void> => {
    try {
      await rename(tempPath, targetPath)
      return
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code !== 'EEXIST' && code !== 'EPERM' && code !== 'EACCES' && code !== 'EBUSY') throw error
    }
    await rm(targetPath, { force: true })
    await rename(tempPath, targetPath)
  }

  /**
   * Legacy whole-file upload: one `fs.write` frame.
   *
   * Used only when the peer does not advertise the chunked ops (or the cached
   * probe was stale), so an older peer keeps working —slowly, but correctly.
   * This is the same shape `remote_fs_write` used before the fast path existed.
   */
  const legacyUploadFile = async (
    localPath: string,
    remotePath: string,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> => {
    const startedAt = Date.now()
    throwIfAborted(signal)
    const data = await readFile(localPath)
    throwIfAborted(signal)
    const reply = await link.request('fs.write', {
      path: remotePath,
      dataB64: data.toString('base64'),
    })
    const durationMs = Math.max(0, Date.now() - startedAt)
    return {
      bytes: data.length,
      sha256: createHash('sha256').update(data).digest('hex'),
      created: reply.created === true,
      version: typeof reply.version === 'string' ? reply.version : null,
      durationMs,
      rateMbps: rateMbps(data.length, durationMs),
      legacy: true,
    }
  }

  /**
   * Legacy download: `fs.stat` then repeated `fs.read` pages into a temp file.
   *
   * The old peer re-reads the whole file per `fs.read`, so this is the slow path
   * by design; it exists so `remote_get_file` still works against an older peer
   * and still verifies the result with `fs.hash` before replacing the target.
   */
  const legacyDownloadFile = async (
    remotePath: string,
    localPath: string,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> => {
    const startedAt = Date.now()
    throwIfAborted(signal)
    const info = await link.request('fs.stat', { path: remotePath })
    if (info.exists !== true) {
      const error = new Error(`cannot read "${remotePath}": not found`)
      ;(error as Error & { peerCode?: string }).peerCode = 'FS_NOT_FOUND'
      throw error
    }
    if (info.isDir === true) throw new Error(`cannot read "${remotePath}": not a regular file`)
    const size = Number(info.size)
    if (!Number.isFinite(size) || size < 0) {
      throw new Error(`transfer: peer reported an invalid size for "${remotePath}"`)
    }
    const tempPath = tempPathFor(localPath)
    await mkdir(dirname(localPath), { recursive: true })
    const handle = await open(tempPath, 'wx')
    const hash = createHash('sha256')
    let closed = false
    let renamed = false
    try {
      let offset = 0
      while (offset < size) {
        throwIfAborted(signal)
        const reply = await link.request('fs.read', {
          path: remotePath,
          offset,
          length: Math.min(1_048_576, size - offset),
        })
        const data = Buffer.from(String(reply.dataB64 ?? ''), 'base64')
        if (data.length === 0) break
        await handle.write(data, 0, data.length, offset)
        hash.update(data)
        offset += data.length
        if (reply.eof === true) break
      }
      await handle.close()
      closed = true
      const localSha = hash.digest('hex')
      const remote = await link.request('fs.hash', { path: remotePath })
      if (String(remote.hash ?? '').toLowerCase() !== localSha) {
        throw new Error('transfer: checksum mismatch')
      }
      throwIfAborted(signal)
      await replaceLocalFile(tempPath, localPath)
      renamed = true
      const durationMs = Math.max(0, Date.now() - startedAt)
      return {
        bytes: offset,
        sha256: localSha,
        durationMs,
        rateMbps: rateMbps(offset, durationMs),
        legacy: true,
      }
    } finally {
      if (!closed) await handle.close().catch(() => { /* best effort */ })
      if (!renamed) await rm(tempPath, { force: true }).catch(() => { /* best effort */ })
    }
  }

  // ---------------------------------------------------------------------------
  // Remote usage reporting (see `cost-report.ts` for the why and the contract)
  //
  // The full path is: after a remote turn settles, ask the peer for the usage
  // records this plugin has not seen yet (`usage.read` with a per-session
  // cursor), merge them into a local store, and atomically replace
  // `${DSH_HOME}/storages/cost-meter/external_usage.json` —the only supported
  // third-party entry point of the local cost-meter plugin. Every failure here
  // is a debug log line and nothing more: reporting must never influence a tool
  // result, a provider run, or the model's view of the world.
  // ---------------------------------------------------------------------------

  /** Source name cost-meter displays: `costSourcePrefix` + peer name. */
  const costSourceName = (): string => {
    const current = read()
    const prefix = text(current.costSourcePrefix) ?? 'remote/'
    const peer = defaultPeerNow() || 'default'
    return `${prefix}${peer}`
  }

  /**
   * The store for the CURRENT paths/source name.
   *
   * Rebuilt lazily when the settings change, so a hot edit of `costStoreFile` or
   * `costSnapshotFile` takes effect on the next turn instead of at next boot.
   * `costReporting` is deliberately not part of the key: its switch is checked
   * live by the collector and by the start-up refresh.
   */
  let costStore: RemoteCostStore | undefined
  let costStoreKey = ''
  const currentCostStore = (): RemoteCostStore => {
    const current = read()
    const storeFile = text(current.costStoreFile) ?? dshHomePath('dsh-remote', 'client-cost.json')
    const snapshotFile = text(current.costSnapshotFile)
      ?? dshHomePath('storages', 'cost-meter', 'external_usage.json')
    const prefix = text(current.costSourcePrefix) ?? 'remote/'
    const sourceName = costSourceName()
    const key = `${storeFile}\u0000${snapshotFile}\u0000${prefix}\u0000${sourceName}`
    if (costStore === undefined || costStoreKey !== key) {
      const created = new RemoteCostStore({
        storeFile,
        snapshotFile,
        sourceName,
        sourcePrefix: prefix,
        log: (message: string) => { ctx.logger.debug(`dsh-remote-client: ${message}`) },
      })
      created.load()
      costStore = created
      costStoreKey = key
    }
    return costStore
  }

  /** How long a peer's `usage.read` capability answer is trusted. */
  const USAGE_OP_TTL_MS = 10 * 60_000
  let usageOpProbe: { at: number, supported: boolean } | undefined

  /**
   * Does the peer advertise `usage.read`?
   *
   * Probed through `sysinfo` once and cached, so an older peer neither logs an
   * "unknown op" every turn nor costs an extra round trip per prompt. A failed
   * probe is NOT cached: a tunnel that is down for a moment must not disable
   * reporting for the next ten minutes.
   */
  const usageOpSupported = async (): Promise<boolean> => {
    const cached = usageOpProbe
    if (cached !== undefined && Date.now() - cached.at < USAGE_OP_TTL_MS) return cached.supported
    try {
      const info = await link.request('sysinfo', {}, 30_000)
      const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
      const supported = ops.includes('usage.read')
      usageOpProbe = { at: Date.now(), supported }
      return supported
    } catch (error) {
      ctx.logger.debug(
        `dsh-remote-client: usage capability probe failed `
        + `(${error instanceof Error ? error.message : String(error)})`,
      )
      return false
    }
  }

  /**
   * Collect one remote session's new usage and refresh the snapshot.
   *
   * Fire-and-forget by contract: callers invoke it AFTER a tool/run has already
   * produced its result and never await it. It is synchronous up to the first
   * `await`, and the promise it starts is fully swallowed.
   *
   * Cursor rule (important): advance by the peer's `nextSeq`, falling back to
   * the last returned record's `seq`, and only then to the previous cursor.
   * `reply.seq` is the session's CURRENT seq and must not be used: when the
   * response is truncated by a limit, that would skip the calls in between.
   */
  const collectRemoteUsage = (sessionId: string): void => {
    if (text(sessionId) === undefined || read().costReporting !== true) return
    void (async () => {
      try {
        if (!(await usageOpSupported())) return
        const store = currentCostStore()
        const fromSeq = store.cursorOf(sessionId)
        const reply = await link.request(
          'usage.read',
          { sessionId, fromSeq },
          Math.max(read().timeoutMs ?? 120_000, 30_000),
        )
        // No live handle on the peer (e.g. it just restarted): nothing to report.
        if (reply.available === false) return
        const samples: RemoteUsageRecord[] = []
        let lastRecordSeq = 0
        for (const raw of Array.isArray(reply.records) ? reply.records : []) {
          const sample = sanitizeSample(raw, sessionId)
          if (sample !== null) samples.push(sample)
          const seq = Number((raw as { seq?: unknown } | null)?.seq)
          if (Number.isFinite(seq) && seq > lastRecordSeq) lastRecordSeq = seq
        }
        const nextSeq = Number(reply.nextSeq)
        const cursor = Number.isFinite(nextSeq) ? nextSeq : lastRecordSeq > 0 ? lastRecordSeq : fromSeq
        await store.record(sessionId, samples, cursor)
      } catch (error) {
        ctx.logger.debug(
          `dsh-remote-client: usage collection for ${sessionId} failed `
          + `(${error instanceof Error ? error.message : String(error)})`,
        )
      }
    })()
  }

  /**
   * Prompt calls currently awaiting a reply, keyed by the remote session they
   * drive, so a question or an interrupt relayed by the peer can reach the very
   * tool call that is waiting on that session.
   */
  const inFlight = new Map<string, {
    prompt: Promise<Record<string, unknown>>
    ask: (frame: Record<string, unknown>) => void
    interrupt: (frame: Record<string, unknown>) => void
  }>()

  /** Questions the peer relayed and this side has not answered yet. */
  const relayedQuestions = new Map<string, { sessionId: string, questions: unknown }>()

  /**
   * Interrupts the peer reported for sessions with no call parked on them.
   *
   * Held rather than dropped: a human on the controlled machine stopping a turn
   * is a real fact about that conversation, and the next prompt on the chat must
   * hand it to its agent instead of talking over the human.
   */
  const pendingInterrupts = new Map<string, Record<string, unknown>>()

  /** Things a human on the controlled machine said in a session we drive. */
  const pendingRemoteNotes = new Map<string, string[]>()

  /**
   * Committed assistant messages the peer transmitted one-by-one on the
   * optional super-agent-io channel, keyed by the remote session and bounded.
   *
   * They are merged into the final `replies` array only after the same call has
   * settled, so a frame can never invent a message the peer did not commit.
   */
  const streamedReplies = new Map<string, RemoteReply[]>()
  const STREAMED_REPLY_LIMIT = 64
  const clearStreamedReplies = (sessionId: string): void => { streamedReplies.delete(sessionId) }
  const addStreamedReply = (sessionId: string, reply: RemoteReply): void => {
    const current = streamedReplies.get(sessionId) ?? []
    if (current.some(item => item.sessionId === reply.sessionId && item.messageId === reply.messageId)) return
    current.push(reply)
    if (current.length > STREAMED_REPLY_LIMIT) current.splice(0, current.length - STREAMED_REPLY_LIMIT)
    streamedReplies.set(sessionId, current)
  }
  const takeStreamedReplies = (sessionId: string): RemoteReply[] => {
    const current = streamedReplies.get(sessionId) ?? []
    streamedReplies.delete(sessionId)
    return current
  }

  /**
   * Message ids already delivered by an RPC result. A late IO frame for one of
   * them must be dropped, not injected as a second inbound copy.
   */
  const rpcReplyIds = new Set<string>()
  /** Message ids already handed to the optional local IO ingress. */
  const inboundReplyIds = new Set<string>()
  /** Per local binding chain so multiple frames are admitted in arrival order. */
  const inboundChains = new Map<string, Promise<void>>()
  const DELIVERED_REPLY_LIMIT = 1024
  const deliveredKey = (sessionId: string, messageId: string): string => `${sessionId}\0${messageId}`
  const rememberBounded = (set: Set<string>, key: string): void => {
    if (set.has(key)) return
    set.add(key)
    while (set.size > DELIVERED_REPLY_LIMIT) {
      const oldest = set.values().next()
      if (oldest.done === true) break
      set.delete(oldest.value)
    }
  }
  const rememberRpcReplies = (replies: readonly RemoteReply[] | undefined): void => {
    for (const reply of replies ?? []) rememberBounded(rpcReplyIds, deliveredKey(reply.sessionId, reply.messageId))
  }
  const wasRpcReply = (sessionId: string, messageId: string): boolean => rpcReplyIds.has(deliveredKey(sessionId, messageId))
  const wasInboundReply = (sessionId: string, messageId: string): boolean => inboundReplyIds.has(deliveredKey(sessionId, messageId))
  const rememberInboundReply = (sessionId: string, messageId: string): void => rememberBounded(inboundReplyIds, deliveredKey(sessionId, messageId))
  const forgetInboundReply = (sessionId: string, messageId: string): void => { inboundReplyIds.delete(deliveredKey(sessionId, messageId)) }

  /**
   * Merge frames into one RPC result and record every message that result
   * delivered. The record is what keeps a late duplicate frame from being
   * injected into the local Session after the RPC already showed it.
   */
  const mergeStreamedReplyValue = (sessionId: string, value: Record<string, unknown>): Record<string, unknown> => {
    const frames = takeStreamedReplies(sessionId).filter(reply => !wasInboundReply(reply.sessionId, reply.messageId))
    const merged = frames.length > 0 ? mergeReplyFrames(value, frames) as Record<string, unknown> : value
    rememberRpcReplies(replyFields(merged).replies)
    return merged
  }

  /**
   * Which remote conversation each chat is using, remembered across restarts.
   * A cache: see `SessionMemory` for why every read and write is tolerant.
   */
  const memory = new SessionMemory(
    text(read().sessionMemoryFile) ?? dshHomePath('dsh-remote', 'client-sessions.json'),
  )
  memory.load()

  const inboundLog = (message: string, level: 'info' | 'warn' | 'debug' = 'info'): void => {
    try {
      if (level === 'warn') ctx.logger.warn(message)
      else if (level === 'debug') ctx.logger.debug(message)
      else log(message)
    } catch {
      // A hot-reload context may already be inactive.
    }
  }

  const inboundIo = createInboundIoAdapter(ctx, {
    enabled: () => read().superAgentIoInbound === true,
    log: inboundLog,
  })

  /**
   * Admit one asynchronous remote reply into the local conversation memory maps
   * to its remote Session.
   *
   * Foreground/background RPCs buffer these frames and return them in their own
   * `replies`; this path is only for a frame with no RPC parked on the session.
   * A message already delivered by an RPC is remembered and never injected
   * again. The IO binding is inbound-only (`sendEnabled:false`), so the local
   * agent's reaction cannot loop back to the peer.
   */
  const injectAsyncInboundReply = (remoteSessionId: string, reply: RemoteReply): void => {
    if (retired || read().superAgentIoInbound !== true) return
    if (inFlight.has(remoteSessionId)) return
    if (wasRpcReply(remoteSessionId, reply.messageId) || wasInboundReply(remoteSessionId, reply.messageId)) return
    const producer = operationPeer.getStore()
    if (producer === undefined) return
    const peer = producer.name
    const livePeer = peersNow()[peer]
    if (livePeer === undefined || authorityOf(livePeer) !== authorityOf(producer.profile)) return
    const localSession = memory.latestLocalSessionFor(remoteSessionId, sessionPrefixNow())
    if (localSession === undefined) {
      inboundLog(
        `dsh-remote-client: no local session is mapped to ${remoteSessionId}; `
        + `asynchronous remote reply ${reply.messageId} was not injected`,
        'debug',
      )
      return
    }
    rememberInboundReply(remoteSessionId, reply.messageId)
    const run = async (): Promise<void> => {
      try {
        const binding = await inboundIo.ensureBinding(peer, localSession, remoteSessionId)
        if (binding === undefined) {
          forgetInboundReply(remoteSessionId, reply.messageId)
          return
        }
        // The frame was already classified as asynchronous (no in-flight RPC)
        // when it arrived. A prompt that starts later is a new turn and cannot
        // contain this earlier committed message, so only an explicit RPC
        // delivery of the same message id may cancel the injection.
        if (wasRpcReply(remoteSessionId, reply.messageId)) {
          forgetInboundReply(remoteSessionId, reply.messageId)
          return
        }
        const outcome = await inboundIo.receive(binding, {
          externalMessageId: inboundExternalId(peer, remoteSessionId, reply.messageId),
          senderId: inboundSenderId(peer, reply),
          text: inboundText(reply),
          replySource: inboundReplySource(peer, reply),
        })
        if (outcome.kind === 'accepted') {
          inboundLog(
            `dsh-remote-client: remote reply ${reply.messageId} (${reply.provider}/${reply.model}) `
            + `from ${peer} admitted into local session ${localSession}`,
          )
          return
        }
        if (outcome.kind === 'unavailable') forgetInboundReply(remoteSessionId, reply.messageId)
        inboundLog(
          `dsh-remote-client: asynchronous remote reply ${reply.messageId} was not injected `
          + `(${outcome.kind}: ${outcome.reason})`,
          'debug',
        )
      } catch (error) {
        forgetInboundReply(remoteSessionId, reply.messageId)
        inboundLog(
          `dsh-remote-client: asynchronous remote reply ${reply.messageId} injection failed `
          + `(${error instanceof Error ? error.message : String(error)})`,
          'debug',
        )
      }
    }
    // Preserve frame order per local binding even when the first binding write
    // is slower than the next frame. No timer is introduced; this is one chain.
    const chainKey = `${peer}\0${localSession}`
    const previous = inboundChains.get(chainKey) ?? Promise.resolve()
    const next = previous.then(run, run)
    inboundChains.set(chainKey, next)
    const cleanup = (): void => {
      if (inboundChains.get(chainKey) === next) inboundChains.delete(chainKey)
    }
    void next.then(cleanup, cleanup)
  }

  /**
   * How far THIS chat has read the remote's trajectory journal.
   *
   * Incremental reading is what makes the journal cheap: with a cursor per chat,
   * "what happened over there" costs only what is new, instead of replaying every
   * command the machine ever ran. A cache like the one above —losing it costs one
   * bounded read, nothing more.
   */
  const journalMemory = new SessionMemory(dshHomePath('dsh-remote', 'client-journal.json'))
  journalMemory.load()

  /** The calling local session id, when the tool call carried one. */
  const localSessionOf = (exec: unknown): string | undefined => {
    const agent = (exec as { agent?: { session?: { id?: unknown } } } | undefined)?.agent
    const id = agent?.session?.id
    return typeof id === 'string' && id !== '' ? id : undefined
  }

  /** The reuse scope one call belongs to: the id family and the calling chat. */
  const scopeOf = (exec: unknown, prefix: string): SessionScope => {
    const localSession = localSessionOf(exec)
    return {
      prefix,
      ...(localSession === undefined ? {} : { localSession }),
    }
  }

  /** Flatten whichever shape the peer's session list arrived in. */
  const toCandidates = (raw: unknown): RemoteSession[] => {
    if (!Array.isArray(raw)) return []
    const out: RemoteSession[] = []
    for (const item of raw) {
      if (typeof item === 'string') {
        if (item !== '') out.push({ sessionId: item })
        continue
      }
      if (item === null || typeof item !== 'object') continue
      const row = item as Record<string, unknown>
      const sessionId = typeof row.sessionId === 'string' ? row.sessionId : ''
      if (sessionId === '') continue
      out.push({
        sessionId,
        ...(typeof row.cwd === 'string' && row.cwd !== '' ? { cwd: row.cwd } : {}),
        ...(typeof row.live === 'boolean' ? { live: row.live } : {}),
        ...(typeof row.seq === 'number' ? { seq: row.seq } : {}),
      })
    }
    return out
  }

  /**
   * Ask the peer which conversations already exist, newest first.
   *
   * A peer that advertises `agent.sessions` answers with its workspace-backed
   * sessions, including ones without a live handle. An older peer only lists
   * live session ids under `sysinfo`, oldest first, so those are reversed.
   */
  const discoverSessions = async (prefix: string): Promise<RemoteSession[]> => {
    const info = await link.request('sysinfo', {}, 30_000)
    const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
    if (ops.includes('agent.sessions')) {
      const listed = await link.request('agent.sessions', {
        ...(prefix === '' ? {} : { prefix }),
      }, 30_000)
      return toCandidates(listed.sessions)
    }
    return toCandidates(info.sessions).reverse()
  }

  /**
   * Choose the session a call with no explicit `session_id` continues.
   *
   * Strict by construction (see `reuse.ts`): a remembered choice wins, otherwise
   * the chat's own deterministic anchor —the same id on every call, so the peer
   * resumes that one conversation and nothing splits a chat in two. Adopting
   * some other existing conversation is opt-in, and never one that another chat
   * or a live call already drives.
   *
   * @param scope - the caller's reuse scope.
   * @returns the id to use, plus how it was chosen.
   */
  const resolveDefaultSession = async (
    scope: SessionScope,
  ): Promise<{ sessionId: string, origin: SessionOrigin }> => {
    const own = anchorSessionId(scope.prefix, scope.localSession)
    const remembered = memory.get(scopeKey(scope))
    if (remembered !== undefined && !inFlight.has(remembered)) {
      return { sessionId: remembered, origin: 'remembered' }
    }
    if (read().adoptExistingSessions !== true) {
      return { sessionId: own, origin: 'anchor' }
    }
    // Opt-in rescue for a chat that owns nothing yet: keep the chat's own id if
    // the peer already has it, otherwise continue one unclaimed conversation
    // instead of creating one more.
    try {
      const candidates = await discoverSessions(scope.prefix)
      if (candidates.some(candidate => candidate.sessionId === own)) {
        return { sessionId: own, origin: 'anchor' }
      }
      const picked = pickReusableSession(candidates, {
        prefix: scope.prefix,
        skip: new Set<string>([...inFlight.keys(), ...memory.inUse()]),
      })
      if (picked !== undefined) return { sessionId: picked.sessionId, origin: 'peer' }
    } catch (error) {
      ctx.logger.debug(
        `dsh-remote-client: session discovery failed (${error instanceof Error ? error.message : String(error)})`,
      )
    }
    return { sessionId: own, origin: 'anchor' }
  }

  // The peer pushes two things this side has to react to: a question its agent
  // asked (relayed here for review instead of being rendered on the peer's own
  // UI), and an interrupt —a human on the controlled machine stopping the turn.
  link.onEvent((frame) => {
    const kind = String(frame.kind ?? '')
    const sessionId = String(frame.sessionId ?? '')
    // The peer's tool registry changed: refetch the catalog and re-sync mirrors.
    // No session id is involved —this frame is about the peer's surface, not a
    // conversation.
    if (kind === 'caps.changed') {
      void refreshCapabilityCatalog(true)
      return
    }
    if (sessionId === '') return
    if (kind === 'assistant.reply') {
      // One frame = one real committed assistant message routed by the peer's
      // optional IO adapter. A parked RPC consumes it into its own `replies`;
      // with no RPC, the optional inbound adapter may put it into the local
      // conversation memory already maps to this remote Session.
      const reply = replyFrame(frame.reply, sessionId)
      if (reply !== undefined) {
        addStreamedReply(sessionId, reply)
        if (!inFlight.has(sessionId)) {
          try {
            injectAsyncInboundReply(sessionId, reply)
          } catch (error) {
            inboundLog(
              `dsh-remote-client: could not start asynchronous reply injection `
              + `(${error instanceof Error ? error.message : String(error)})`,
              'debug',
            )
          }
        }
      }
      return
    }
    if (kind === 'ask') {
      const qid = String(frame.qid ?? '')
      if (qid === '') return
      relayedQuestions.set(qid, { sessionId, questions: frame.questions })
      inFlight.get(sessionId)?.ask(frame)
      return
    }
    if (kind === 'interrupt') {
      // Our own `agent.interrupt` echoes back too; the server marks that one,
      // and only a genuinely remote stop is news here.
      if (String(frame.origin ?? '') === 'controller') return
      const parked = inFlight.get(sessionId)
      if (parked !== undefined) { parked.interrupt(frame); return }
      pendingInterrupts.set(sessionId, frame)
      return
    }
    if (kind === 'note') {
      const text = String(frame.text ?? '')
      if (text === '') return
      const notes = pendingRemoteNotes.get(sessionId) ?? []
      notes.push(text)
      pendingRemoteNotes.set(sessionId, notes)
    }
  })

  /**
   * Interrupt a remote turn, having been interrupted locally.
   *
   * The local user's stop must stop the work they were watching, and it must go
   * through the peer's own plugin surface (`agent.interrupt`) rather than by
   * dropping the socket: the peer's agent then closes its turn as a cancelled
   * turn, which is what its own UI and log expect. Best effort, short timeout —   * the local cancellation must not wait on a link that may already be gone.
   */
  const interruptRemote = (sessionId: string): Promise<void> => link
    .request('agent.interrupt', { sessionId }, 10_000)
    .then(() => { log(`dsh-remote-client: interrupted ${sessionId} on the peer`) })
    .catch((error: unknown) => {
      ctx.logger.debug(
        `dsh-remote-client: could not interrupt ${sessionId} on the peer `
        + `(${error instanceof Error ? error.message : String(error)})`,
      )
    })

  /**
   * Ask the peer to stop a command it is running for us.
   *
   * Best effort and never awaited by the cancellation path: the local call has
   * already settled, and a peer that predates `exec.cancel` answers "unknown op"
   * (the link retries once, then this swallows it). Nothing here may delay the
   * user's own stop.
   */
  const stopRemoteExec = (execId: string): Promise<void> => link
    .request('exec.cancel', { execId }, 10_000)
    .then((reply) => {
      if (reply.cancelled === true) log(`dsh-remote-client: stopped ${execId} on the peer`)
    })
    .catch((error: unknown) => {
      ctx.logger.debug(
        `dsh-remote-client: could not stop ${execId} on the peer `
        + `(${error instanceof Error ? error.message : String(error)})`,
      )
    })

  /**
   * Park one peer prompt so a relayed question, or an interrupt from the peer's
   * own user, can reach the very turn waiting on that session.
   *
   * Shared by the foreground prompt tool and background runs: both rely on the
   * same `inFlight` entry, which is what makes `remote_answer_question` work no
   * matter which entry point issued the prompt. The caller owns deleting the
   * entry when its call is over.
   *
   * @param sessionId - the remote conversation the prompt drives.
   * @param pending - the link request already on the wire.
   * @returns promises that resolve when the peer asks / is interrupted.
   */
  const parkPrompt = (
    sessionId: string,
    pending: Promise<Record<string, unknown>>,
  ): {
    asked: Promise<Record<string, unknown>>
    stopped: Promise<Record<string, unknown>>
  } => {
    let onAsk: (frame: Record<string, unknown>) => void = () => {}
    let onInterrupt: (frame: Record<string, unknown>) => void = () => {}
    const asked = new Promise<Record<string, unknown>>((resolve) => { onAsk = resolve })
    const stopped = new Promise<Record<string, unknown>>((resolve) => { onInterrupt = resolve })
    inFlight.set(sessionId, { prompt: pending, ask: onAsk, interrupt: onInterrupt })
    return { asked, stopped }
  }

  /**
   * The remote conversation a subagent run for this chat continues.
   *
   * Same rule as the tools, deliberately: one chat —one remote conversation, no
   * matter which entry point (a delegated task or a direct `remote_agent_prompt`)
   * asked for it.
   */
  const sessionForProvider = (parentSessionId: string): string => {
    const prefix = sessionPrefixNow()
    const scope: SessionScope = { prefix, localSession: parentSessionId }
    return memory.get(scopeKey(scope)) ?? anchorSessionId(prefix, parentSessionId)
  }

  /**
   * The peer-facing half of one subagent run.
   *
   * A sibling of the `remote_agent_prompt` path rather than a refactor of it: the
   * tool's call path is already verified, and a run differs where it counts —a
   * run has no model-facing question surface, so a question the peer asks
   * mid-run becomes the run's output (with the question registered, so
   * `remote_answer_question` can still answer it) instead of parking a tool call.
   */
  const promptForProvider = async (
    request: { sessionId: string, text: string, signal: AbortSignal },
  ): Promise<RemotePromptOutcome> => {
    clearStreamedReplies(request.sessionId)
    const pending = link.request('agent.prompt', {
      sessionId: request.sessionId,
      text: request.text,
      timeoutMs: 0,
    }, Math.max(read().timeoutMs ?? 120_000, 30_000))
    let onAsk: (frame: Record<string, unknown>) => void = () => {}
    let onInterrupt: (frame: Record<string, unknown>) => void = () => {}
    const asked = new Promise<Record<string, unknown>>((resolve) => { onAsk = resolve })
    const stopped = new Promise<Record<string, unknown>>((resolve) => { onInterrupt = resolve })
    inFlight.set(request.sessionId, { prompt: pending, ask: onAsk, interrupt: onInterrupt })
    try {
      const outcome = await Promise.race([
        pending.then(reply => ({ kind: 'reply' as const, reply })),
        asked.then(frame => ({ kind: 'ask' as const, frame })),
        stopped.then(frame => ({ kind: 'stop' as const, frame })),
      ])
      if (outcome.kind === 'stop') {
        inFlight.delete(request.sessionId)
        clearStreamedReplies(request.sessionId)
        // The turn is over either way; whatever it spent is real usage.
        collectRemoteUsage(request.sessionId)
        return { reply: '', interrupted: true, reason: 'aborted' }
      }
      if (outcome.kind === 'ask') {
        // Leave the in-flight entry and any IO frames alone on purpose: the
        // parked peer turn is still waiting, and remote_answer_question
        // finishes it through this very entry.
        const questions = Array.isArray(outcome.frame.questions)
          ? outcome.frame.questions as Array<{ id?: unknown, question?: unknown }>
          : []
        const lines = [
          '远端 agent 在等一个回答，所以这次委派先返回它的提问：',
          `qid: ${String(outcome.frame.qid ?? '')}`,
        ]
        for (const question of questions) {
          lines.push(`- [${String(question.id ?? '?')}] ${String(question.question ?? '')}`)
        }
        lines.push('用 remote_answer_question 作答；答案会回到对端那个还停着的轮次。')
        return { reply: lines.join('\n'), reason: 'completed' }
      }
      inFlight.delete(request.sessionId)
      collectRemoteUsage(request.sessionId)
      const reply = outcome.reply
      const merged = mergeStreamedReplyValue(request.sessionId, reply)
      return {
        reply: String(merged.reply ?? reply.reply ?? ''),
        ...replyFields(merged),
        ...(merged.interrupted === true ? { interrupted: true } : {}),
        ...(merged.created === true ? { created: true } : {}),
        reason: typeof merged.reason === 'string' ? merged.reason : null,
      }
    } catch (error) {
      inFlight.delete(request.sessionId)
      clearStreamedReplies(request.sessionId)
      throw error
    }
  }

  // ---------------------------------------------------------------------------
  // Background runs (see `remote-runs.ts` for the registry and the tools)
  //
  // A background run is the same peer prompt the foreground tool issues, but
  // the tool is answered before the turn ends. Everything below is the thin
  // transport half: session resolution, the parked `agent.prompt`, the
  // `agent.note` capability probe, and interruption. The bookkeeping, wording
  // and tool schemas live in `remote-runs.ts`, so that module unit-tests with
  // fake dependencies.
  // ---------------------------------------------------------------------------

  /** Largest delay a Node timer can hold; used when a turn has no deadline. */
  const LINK_FOREVER_MS = 2_147_000_000

  /**
   * The link-side deadline for one peer turn.
   *
   * `timeoutMs: 0` (the default for background runs) means "wait as long as the
   * turn takes" on the wire, so the link deadline cannot simply be the plugin
   * request timeout —that would cap the infinite case at two minutes. A finite
   * turn budget keeps the same headroom the foreground prompt tool gives it.
   */
  const linkDeadlineFor = (turnTimeoutMs: number): number => turnTimeoutMs > 0
    ? Math.max(read().timeoutMs ?? 120_000, turnTimeoutMs + 30_000)
    : LINK_FOREVER_MS

  /** How long a peer's `agent.note` capability answer is trusted. */
  const NOTE_OP_TTL_MS = 10 * 60_000
  const noteOpProbes = new Map<LinkClient, { at: number, supported: boolean, modes: boolean }>()

  /**
   * Does the peer advertise `agent.note`?
   *
   * A note is the only way to append an instruction without queueing yet another
   * `agent.prompt` and waiting on it, but it arrived in the r20 peer. Probed
   * through `sysinfo` once and cached; a failed probe is not cached (a tunnel
   * that is down for a moment must not downgrade the next message), and an
   * older peer simply keeps the queueing fallback.
   */
  const noteOpSupported = async (sessionId: string): Promise<{ supported: boolean, modes: boolean }> => {
    const binding = sessionBindings.get(sessionId)
    const target = binding === undefined ? operationPeer.getStore() ?? controlFor() : controlFor(binding.name)
    const cached = noteOpProbes.get(target.link)
    if (cached !== undefined && Date.now() - cached.at < NOTE_OP_TTL_MS) return cached
    try {
      const info = await operationPeer.run(target, () => link.request('sysinfo', {}, 30_000))
      const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
      const supported = ops.includes('agent.note')
      const features = info.features as { noteModes?: unknown } | undefined
      const noteModes = features?.noteModes
      const modes = Array.isArray(noteModes) && ['queue', 'steer', 'auto'].every(mode => noteModes.includes(mode))
      const found = { at: Date.now(), supported, modes }
      noteOpProbes.set(target.link, found)
      return found
    } catch (error) {
      ctx.logger.debug(
        `dsh-remote-client: note capability probe failed `
        + `(${error instanceof Error ? error.message : String(error)})`,
      )
      // A failed observation does not authorize a side-effecting fallback.
      throw error
    }
  }

  /** Only a pre-handler unknown-op refusal proves a note was not admitted. */
  const isUnknownPeerOp = (error: unknown): boolean => {
    const code = (error as { peerCode?: unknown } | null)?.peerCode
    if (code === 'FS_UNKNOWN_OP') return true
    const message = error instanceof Error ? error.message : String(error)
    return /^unknown op ["']agent\.note["']$/u.test(message)
  }

  /**
   * Queued prompts started by `remote_send_message` against an older peer.
   *
   * Held only so a rejection is always observed (the turn is intentionally not
   * awaited); each entry removes itself when it settles, so this set is bounded
   * by the number of unobservable notes actually in flight.
   */
  const orphanNotePrompts = new Set<Promise<unknown>>()

  /**
   * Append a user message to a remote conversation without waiting for the
   * peer's turn.
   *
   * Preferred path is the r20 `agent.note` op, which injects straight into the
   * session inbox. A peer without it gets one `agent.prompt` that is started and
   * deliberately not awaited: the message is still queued, only its completion
   * is unobservable from here —which the tool result says plainly.
   */
  const sendMessageToSession = async (request: {
    sessionId: string
    text: string
    mode?: RemoteInputMode
    signal?: AbortSignal
  }): Promise<{ accepted: boolean, method?: string, mode?: 'queue' | 'steer', processing?: string, note?: string }> => {
    if (request.signal?.aborted === true) {
      const cancelled = new Error('remote_send_message: cancelled locally')
      cancelled.name = 'AbortError'
      throw cancelled
    }
    const noteSupport = await noteOpSupported(request.sessionId)
    const supported = noteSupport.supported
    const mode = request.mode ?? 'auto'
    if (mode === 'steer' && (!supported || !noteSupport.modes)) {
      throw new Error('remote_send_message: peer does not advertise steering; upgrade it or explicitly choose queue')
    }
    if (supported) {
      try {
        const reply = await link.request('agent.note', {
          sessionId: request.sessionId,
          text: request.text,
          ...(noteSupport.modes ? { mode } : {}),
        }, 30_000)
        return { accepted: reply.accepted !== false, method: 'agent.note',
          ...(reply.mode === 'queue' || reply.mode === 'steer' ? { mode: reply.mode } : { mode: 'queue' as const }),
          ...(typeof reply.processing === 'string' ? { processing: reply.processing } : {}),
          ...(noteSupport.modes ? {} : { note: '旧peer仅支持followup排下一轮，不宣称next-step steering' }),
        }
      } catch (error) {
        if (!isUnknownPeerOp(error) || mode === 'steer') throw error
        ctx.logger.debug(
          `dsh-remote-client: agent.note unavailable, queueing through agent.prompt `
          + `(${error instanceof Error ? error.message : String(error)})`,
        )
      }
    }
    const queued = link.request('agent.prompt', {
      sessionId: request.sessionId,
      text: request.text,
      timeoutMs: 0,
    }, LINK_FOREVER_MS)
    orphanNotePrompts.add(queued)
    void queued.then(
      () => { orphanNotePrompts.delete(queued) },
      () => { orphanNotePrompts.delete(queued) },
    )
    return {
      accepted: true,
      method: 'agent.prompt',
      mode: 'queue',
      processing: 'next-turn',
      note: '对端旧版本；消息已排队，但完成时间不可观测',
    }
  }

  /**
   * Start one peer prompt for a background run and wire it into the same
   * `inFlight`/ask/interrupt plumbing a foreground call uses.
   *
   * Returns synchronously —the tool call is answered before the peer's turn
   * ends. The terminal outcome is reported through `onSettled`; a local Stop
   * only marks the run `cancelling`, because the peer's own turn still has to
   * report back (or be interrupted) before the run can honestly be called
   * settled. A question the peer asks mid-run is registered by the shared
   * `link.onEvent` handler, so `remote_answer_question` keeps working.
   *
   * @param request - the run, its text, deadline, and settlement callbacks.
   */
  const startRunPrompt = (request: RunPromptRequest): void => {
    if (request.signal?.aborted === true) {
      request.onSettled({
        status: 'aborted',
        interrupted: true,
        reason: 'aborted',
        diagnostic: '本机已中断，后台运行未启动',
      })
      return
    }
    clearStreamedReplies(request.sessionId)
    const pending = link.request('agent.prompt', {
      sessionId: request.sessionId,
      text: request.text,
      timeoutMs: request.timeoutMs,
    }, linkDeadlineFor(request.timeoutMs))
    // The ask resolver is intentionally unused: nothing is parked on a question
    // for a background run, but `remote_answer_question` resumes the same prompt
    // through this very `inFlight` entry.
    const parked = parkPrompt(request.sessionId, pending)

    let finished = false
    /** Drop this run's parking, but never another call's entry. */
    const cleanup = (): void => {
      if (finished) return
      finished = true
      request.signal?.removeEventListener('abort', onAbort)
      if (inFlight.get(request.sessionId)?.prompt === pending) inFlight.delete(request.sessionId)
    }
    /** Report the one terminal outcome; later races are ignored. */
    const settle = (outcome: RunSettlement): void => {
      if (finished) return
      cleanup()
      collectRemoteUsage(request.sessionId)
      request.onSettled(outcome)
    }
    /** Local Stop: stop the peer's work, but let the peer report the ending. */
    const onAbort = (): void => {
      request.onCancelling()
      void interruptRemote(request.sessionId)
    }
    request.signal?.addEventListener('abort', onAbort, { once: true })

    void (async () => {
      try {
        const outcome = await Promise.race([
          pending.then(reply => ({ kind: 'reply' as const, reply })),
          parked.stopped.then(frame => ({ kind: 'stop' as const, frame })),
        ])
        if (outcome.kind === 'stop') {
          clearStreamedReplies(request.sessionId)
          settle({
            status: 'aborted',
            interrupted: true,
            reason: String(outcome.frame.cause ?? 'user'),
          })
          return
        }
        const reply = outcome.reply
        const merged = mergeStreamedReplyValue(request.sessionId, reply)
        const reason = typeof merged.reason === 'string' ? merged.reason : null
        const body = typeof merged.reply === 'string' ? merged.reply : ''
        if (merged.interrupted === true) {
          settle({ status: 'aborted', interrupted: true, reply: body, ...replyFields(merged), reason: reason ?? 'aborted' })
          return
        }
        if (reason === 'error' || reason === 'blocked' || typeof merged.error === 'string') {
          settle({
            status: 'error',
            reply: body,
            ...replyFields(merged),
            reason,
            diagnostic: typeof merged.error === 'string' && merged.error !== ''
              ? merged.error
              : `dsh-remote-client: the peer's turn ended with reason "${String(reason)}"`,
          })
          return
        }
        settle({ status: 'completed', reply: body, ...replyFields(merged), reason })
      } catch (error) {
        clearStreamedReplies(request.sessionId)
        const message = error instanceof Error ? error.message : String(error)
        if (request.signal?.aborted === true) {
          settle({
            status: 'aborted',
            interrupted: true,
            reason: 'aborted',
            diagnostic: `本机中断：${message}`,
          })
          return
        }
        settle({ status: 'error', diagnostic: message })
      }
    })()
  }

  /** The thin client facade `remote-runs.ts` builds its tools over. */
  const runToolDeps: RunToolDeps = {
    async resolveSession(args, exec) {
      const prefix = sessionPrefixNow()
      const explicit = args.session_id
      if (explicit !== undefined) return { sessionId: explicit, origin: 'explicit' }
      const scope = scopeOf(exec, prefix)
      try {
        return await resolveDefaultSession(scope)
      } catch {
        return { sessionId: anchorSessionId(prefix, scope.localSession), origin: 'anchor' }
      }
    },
    startPrompt: startRunPrompt,
    sendMessage: sendMessageToSession,
    interrupt: interruptRemote,
    rememberScope(exec, sessionId) {
      memory.set(scopeKey(scopeOf(exec, sessionPrefixNow())), sessionId)
    },
    log,
    maxRuns: () => {
      const value = Number(read().maxBackgroundRuns ?? 8)
      return Number.isFinite(value) && value >= 1 ? Math.floor(value) : 8
    },
  }

  // Publish the declarations once. The peer filesystem provider mounts whatever
  // this registry holds, so a peer's address is written in exactly one place.
  // Read through `read()`, not `config` —the latter still holds the volatile
  // references, not the values behind them.
  const resolved = read()
  let peers: Record<string, PeerProfile> = peersNow()
  ctx.plugin(PeerRegistry, { peers, defaultPeer: text(resolved.defaultPeer) ?? '' })

  // ---------------------------------------------------------------------------
  // Multi-peer worker pool + Agent Teams board
  //
  // The single `link` above stays the control path for "this chat's one remote
  // conversation". A deployment that declares several peers gets one pooled
  // LinkClient per peer here, created lazily so a tool only dials the peers it
  // actually uses. The Team hooks are optional: without ctx.agentTeams the pool
  // tools still work and simply do not write the board.
  // ---------------------------------------------------------------------------
  const teamService = (): TeamFacade | undefined => {
    try {
      return ctx.get('agentTeams') as unknown as TeamFacade | undefined
    } catch {
      return undefined
    }
  }

  /** Current declarations, with the name the pool tools address them by. */
  const poolPeers = (): Record<string, PoolPeerProfile> =>
    Object.fromEntries(Object.entries(peersNow()).map(([name, profile]) => [name, { ...profile, name }]))

  const pooledLinks = new Map<string, LinkClient>()
  /** The pooled link for one peer, created on first use and reused afterwards. */
  const poolLinkFor = (peerName: string): LinkClient => {
    if (retired) throw new Error('Remote plugin disposed')
    const existing = pooledLinks.get(peerName)
    if (existing !== undefined) return existing
    const created = new LinkClient(() => {
      const profile = poolPeers()[peerName]
      return profile === undefined ? {} : {
        host: profile.host,
        port: profile.port,
        relayTarget: profile.relayTarget,
        privateKey: profile.privateKey,
        privateKeyFile: profile.privateKeyFile,
        autoGenerateKey: profile.autoGenerateKey,
        peerPublicKey: profile.peerPublicKey,
        peerPublicKeyFile: profile.peerPublicKeyFile,
        timeoutMs: profile.timeoutMs,
        allowLegacyHandshake: profile.allowLegacyHandshake,
        maxSessionMs: profile.maxSessionMs,
      }
    }, message => log(message), `dsh-remote:peer ${peerName}`, meshSocketFactory(ctx))
    const rawRequest = created.request.bind(created)
    created.request = async (op, args = {}, timeoutMs, options = {}) => {
      const profile = peersNow()[peerName]
      if (profile === undefined) throw new Error(`Unknown peer "${peerName}"`)
      assertPeerOperation(profile.maxPermission ?? 1, op, {
        peer: peerName, workspaceRoot: profile.workspaceRoot ?? '',
        ...(typeof args.path === 'string' ? { path: args.path } : {}),
      })
      return rawRequest(op, args, timeoutMs, options)
    }
    pooledLinks.set(peerName, created)
    return created
  }

  // Read-only catalog access for host-qualified references. The file-reference
  // provider and model-facing discovery tool share the same bounded operation.
  const referenceService = {
    names: () => Object.keys(peersNow()),
    async list(peer: string, args: Record<string, unknown>, signal?: AbortSignal) {
      if (!Object.hasOwn(peersNow(), peer)) throw new Error(`Unknown peer "${peer}"`)
      signal?.throwIfAborted()
      const pending = poolLinkFor(peer).request('references.list', args, 15_000)
      return signal === undefined ? pending : raceAbort(pending, signal)
    },
  }
  const provide = (ctx as unknown as { provide?: (name: string, value: unknown) => unknown }).provide
  if (typeof provide === 'function') provide.call(ctx, 'dshRemoteReferences', referenceService)
  ctx.on('agent/pre-step', async (payload, next) => mapRemoteReferences({
    peers: referenceService.names, list: referenceService.list,
  }, payload, await next()))

  const teamTaskHooks = createTeamTaskHooks({
    team: teamService,
    log: message => ctx.logger.debug(`dsh-remote-client: ${message}`),
  })

  const poolDeps: PoolDeps = {
    peers: poolPeers,
    prefix: () => text(read().sessionPrefix) ?? 'remote',
    localSessionOf,
    linkFor: poolLinkFor,
    log,
    teamTask: teamTaskHooks,
  }

  const tools = [
    defineTool({
      name: 'remote_ping',
      description: 'Check the link to the peer harness: version, build tag, hostname, live sessions, and this side\'s key fingerprint.',
      parameters: {},
      output: {
        schema: { type: 'json' },
        render: (_args, value) => renderText(JSON.stringify(value, null, 2)),
      },
      async execute(_args: Record<string, never>, exec?: { agent?: { session?: { id?: unknown } } }): Promise<JsonValue> {
        const info = await link.request('sysinfo', {}, 30_000)
        const localSession = localSessionOf(exec)
        return {
          clientVersion: CLIENT_VERSION,
          clientBuild: BUILD,
          connected: link.connected,
          // Which remote conversation THIS chat owns — the mapping the guidance
          // promises, made checkable without spending a prompt on it.
          remoteSessionForThisChat: localSession === undefined
            ? `${sessionPrefixNow()} (no calling session; shared)`
            : anchorSessionId(sessionPrefixNow(), localSession),
          // Whether remote usage is being forwarded to the local cost-meter, and
          // how much this plugin has recorded — readable without any network IO,
          // so "is the reporting loop working?" is one `remote_ping` away.
          remoteCost: (() => {
            const summary = currentCostStore().summary()
            return {
              enabled: read().costReporting === true,
              source: summary.source,
              records: summary.records,
              lastAt: summary.lastAt,
            }
          })(),
          ...info,
        } as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_exec',
      description:
        '在远端主机上执行 PowerShell（或 cmd）命令，返回 stdout / stderr / 退出码。'
        + '这是在对端机器上跑命令，不是本机。'
        + '本机被用户中断时，这条命令会通过对端的 `exec.cancel` 一起被停掉（对端版本过老则只能停掉本机这一侧）。',
      parameters: {
        command: { type: 'string', required: true, description: '要执行的命令。' },
        shell: { type: 'string', description: 'powershell（默认）或 cmd。' },
        timeout_ms: { type: 'number', description: '超时毫秒数，默认 120000。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            exit: number | null, timedOut: boolean, cancelled?: boolean,
            stdout: string, stderr: string, durationMs: number,
          }
          const parts = [
            `exit_code: ${v.exit === null ? '(none)' : v.exit}`
            + `${v.cancelled === true ? '  (STOPPED)' : v.timedOut ? '  (TIMED OUT)' : ''}`,
            `duration_ms: ${v.durationMs}`,
          ]
          if (v.stdout.trim() !== '') parts.push('--- stdout ---', v.stdout.trimEnd())
          if (v.stderr.trim() !== '') parts.push('--- stderr ---', v.stderr.trimEnd())
          if (v.stdout.trim() === '' && v.stderr.trim() === '') parts.push('(no output)')
          return renderText(parts.join('\n'))
        },
      },
      async execute(
        args: { command: string, shell?: string, timeout_ms?: number },
        exec?: { signal?: AbortSignal },
      ): Promise<JsonValue> {
        // The id is what lets a local Stop reach the PROCESS on the peer instead
        // of only settling the call waiting here; the ordering (settle, then ask)
        // lives in the helper, where it is tested.
        return await runCancellableExec({
          execId: `exec-${randomUUID()}`,
          args: {
            cmd: args.command,
            shell: args.shell ?? 'powershell',
            timeoutMs: args.timeout_ms ?? 120_000,
          },
          timeoutMs: Math.max(read().timeoutMs ?? 120_000, (args.timeout_ms ?? 0) + 30_000),
          ...(exec?.signal === undefined ? {} : { signal: exec.signal }),
          send: (requestArgs, timeout) => link.request('exec', requestArgs, timeout),
          cancelRemote: (execId) => { void stopRemoteExec(execId) },
        }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_agent_prompt',
      description:
        '把一段用户发言交给**远端 harness 的 agent**，等它跑完这一轮，取回回复。'
        + '输入在对端标记为 dsh-remote 来源（不是对端本地真人）；**把远端对话当作本机的一个 subagent / task**：'
        + '你派活、它交付，最后把结论带回本机上下文。\n'
        + '会话规则（严格）：**一个本机 chat 只对应一个远端对话**。省略 session_id 时，'
        + '本插件按本机会话推导出固定 id 并复用——对端已有就续接，没有才创建。'
        + '所以不要为了"隔离/换个话题"而改 session_id：那只会让对端多开一段对话。'
        + '只有用户明确要求另起一段时，才传 new_session=true（或显式给一个新 id）。\n'
        + '本机优先：能在本机上下文里做的事就在本机做；只有确实必须跑在对端机器上的动作'
        + '（对端的文件、对端的环境、对端已有的会话）才用 remote_*。'
        + '远端只做交付，别把它当成本机编排的执行器。\n'
        + '打断：本机被用户中断时，这一轮会同时中断远端；远端用户打断时，返回里会带 '
        + 'interrupted 标记——那时立刻停下、不要自动重试或继续，把决定权交回用户。',
      parameters: {
        text: { type: 'string', required: true, description: '交给对端 agent 的用户发言。' },
        session_id: { type: 'string', description: '对端会话 id。一般**不要传**：省略即复用本 chat 自己那一个对话。' },
        new_session: { type: 'boolean', description: 'true = 在对端另开一段对话。仅在用户明确要求另起一段时使用。' },
        preset_id: { type: 'string', description: '仅首次创建会话时生效的 preset id，如 cordis。' },
        workspace: { type: 'string', description: '对端会话的工作目录（仅首次创建时生效）。' },
        timeout_ms: { type: 'number', description: '等待这一轮结束的超时毫秒数；0 表示不限。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            sessionId: string, reply?: string, reason?: string | null,
            error?: string | null, origin?: SessionOrigin,
            seq?: number, created?: boolean, durationMs?: number,
            interrupted?: boolean, interruptedByRemote?: boolean,
            priorInterrupt?: { cause?: string, at?: number },
            remoteUserNotes?: string[],
            pendingQuestion?: {
              qid: string
              questions: Array<{
                id: string, question: string, header?: string, detail?: string,
                multiSelect?: boolean, options?: Array<{ label: string, description?: string }>,
              }>
            },
          }
          // Say plainly whether this turn continued a conversation or opened one.
          const tag = v.created === true
            ? '(created)'
            : v.origin === 'fresh' ? '(new)'
              : `(reused${v.origin === undefined || v.origin === 'explicit' ? '' : `: ${v.origin}`})`
          // The controlled side is waiting on its own user, so nothing here is a
          // reply: stop, and let the human decide what happens next.
          const stopLines: string[] = []
          if (v.priorInterrupt !== undefined) {
            stopLines.push(
              `⚠️ 上一轮在远端被用户打断了（cause: ${v.priorInterrupt.cause ?? 'unknown'}）；`
              + '这是那次打断的回报，不是新结果。',
            )
          }
          if (v.interrupted === true || v.interruptedByRemote === true) {
            stopLines.push(
              '⚠️ 这一轮在远端被用户打断，没有可用的回复。**立刻停止**：不要重试、不要自动继续、不要换 '
              + 'session_id 重发；把当前状态告诉用户，等用户给出新指示。',
            )
          }
          if ((v.remoteUserNotes?.length ?? 0) > 0) {
            stopLines.push('远端用户在这个对话里发了消息（不是本插件注入的）：')
            for (const note of v.remoteUserNotes ?? []) stopLines.push(`  · ${note}`)
            stopLines.push('以用户的新指示为准，重新规划；不要覆盖或忽略它。')
          }
          // The peer's agent asked something mid-turn: this call returns the
          // QUESTION instead of a reply, and the turn stays parked over there
          // until it is answered.
          if (v.pendingQuestion !== undefined) {
            const lines = [
              `session: ${v.sessionId} ${tag}`,
              ...stopLines,
              'reason : 对端 agent 正在等你回答（它调用了 ask_user_question）',
              `qid    : ${v.pendingQuestion.qid}`,
              '--- questions ---',
            ]
            for (const [index, question] of v.pendingQuestion.questions.entries()) {
              const header = question.header === undefined || question.header === '' ? '' : `[${question.header}] `
              lines.push(`${index + 1}. ${header}${question.question}`)
              // The id is what an answer must echo, so it has to be visible: without
              // it the caller cannot build a valid answers payload at all.
              lines.push(`   id: ${question.id}`)
              if (question.detail !== undefined && question.detail !== '') lines.push(`   ${question.detail}`)
              for (const [optionIndex, option] of (question.options ?? []).entries()) {
                lines.push(`   ${optionIndex + 1}) ${option.label}${option.description === undefined ? '' : ` — ${option.description}`}`)
              }
              if (question.multiSelect === true) lines.push('   (可多选)')
            }
            lines.push('')
            lines.push(`审查后作答：remote_answer_question(question_id="${v.pendingQuestion.qid}", answers={answers:[{id, selected:[...], custom?}]})`)
            lines.push('需要用户拍板时：先调本机 ask_user_question 问用户，再把它的返回转交给 remote_answer_question。')
            return renderText(lines.join('\n'))
          }
          const head = [
            `session: ${v.sessionId} ${tag}`,
            `reason : ${v.reason ?? '(none)'}   seq: ${v.seq ?? '?'}   ${v.durationMs ?? '?'} ms`,
            ...stopLines,
          ]
          if (v.error !== null && v.error !== undefined && v.error !== '') {
            head.push(`error  : ${v.error}`)
          }
          return renderText([...head, renderRemoteReplies(value)].join('\n'))
        },
      },
      async execute(args: {
        text: string, session_id?: string, new_session?: boolean, preset_id?: string,
        workspace?: string, timeout_ms?: number,
      }, exec?: {
        agent?: { session?: { id?: unknown } }
        signal?: AbortSignal
      }): Promise<JsonValue> {
        const prefix = sessionPrefixNow()
        const explicit = text(args.session_id)
        const workspace = text(args.workspace)
        const preset = text(args.preset_id)
        const scope = scopeOf(exec, prefix)
        const reuse = read().reuseSessions !== false && args.new_session !== true

        let sessionId: string
        let origin: SessionOrigin
        if (explicit !== undefined) {
          sessionId = explicit
          origin = 'explicit'
        } else if (!reuse) {
          sessionId = freshSessionId(prefix)
          origin = 'fresh'
        } else {
          // Advisory only: a failure here must still produce a usable id.
          try {
            ({ sessionId, origin } = await resolveDefaultSession(scope))
          } catch {
            sessionId = anchorSessionId(prefix, scope.localSession)
            origin = 'anchor'
          }
        }

        // News from the controlled machine that arrived between calls: its user
        // stopped the previous turn, or said something in this conversation.
        const priorInterrupt = pendingInterrupts.get(sessionId)
        if (priorInterrupt !== undefined) pendingInterrupts.delete(sessionId)
        const remoteUserNotes = pendingRemoteNotes.get(sessionId) ?? []
        if (remoteUserNotes.length > 0) pendingRemoteNotes.delete(sessionId)

        clearStreamedReplies(sessionId)
        const request = link.request('agent.prompt', {
          sessionId,
          text: args.text,
          timeoutMs: args.timeout_ms ?? 0,
          ...(preset === undefined ? {} : { presetId: args.preset_id }),
          ...(workspace === undefined ? {} : { workspace: args.workspace }),
        }, Math.max(read().timeoutMs ?? 120_000, (args.timeout_ms ?? 0) + 30_000))
        // Park this call so a question, or an interrupt from the peer's own user,
        // can reach the very turn waiting on that session. The underlying request
        // stays in flight either way: while the peer's agent is asking, its
        // `agent.prompt` handler is still parked on the far side, so answering the
        // question later resumes this very request.
        const parked = parkPrompt(sessionId, request)

        // The local user's stop has to stop the work they were watching. This is
        // a resolve-only promise so nothing can reject unobserved when another
        // branch wins the race.
        const signal = exec?.signal
        let onAbortLocal: () => void = () => {}
        const aborted = new Promise<{ kind: 'abort' }>((resolve) => {
          onAbortLocal = () => resolve({ kind: 'abort' })
        })
        const onAbort = (): void => {
          // Delete first: the peer's echo of OUR interrupt must not be read as
          // the remote user having stopped the turn.
          inFlight.delete(sessionId)
          void interruptRemote(sessionId)
          onAbortLocal()
        }
        if (signal !== undefined) {
          if (signal.aborted === true) onAbort()
          else signal.addEventListener('abort', onAbort, { once: true })
        }

        try {
          const outcome = await Promise.race([
            request.then(reply => ({ kind: 'reply' as const, reply })),
            parked.asked.then(frame => ({ kind: 'ask' as const, frame })),
            parked.stopped.then(frame => ({ kind: 'stop' as const, frame })),
            aborted,
          ])
          if (outcome.kind === 'abort') {
            // Propagate as a cancellation: the local turn is over, and the peer's
            // turn was cancelled above through its own plugin surface.
            const cancelled = new Error('remote_agent_prompt: interrupted locally; the peer turn was cancelled')
            cancelled.name = 'AbortError'
            throw cancelled
          }
          if (outcome.kind === 'stop') {
            // The controlled machine's user stopped the turn. Leave nothing parked
            // for a reply that this call is no longer waiting on.
            inFlight.delete(sessionId)
            clearStreamedReplies(sessionId)
            memory.set(scopeKey(scope), sessionId)
            collectRemoteUsage(sessionId)
            return {
              sessionId,
              origin,
              interrupted: true,
              interruptCause: String(outcome.frame.cause ?? 'user'),
              ...(remoteUserNotes.length > 0 ? { remoteUserNotes } : {}),
              ...(priorInterrupt === undefined ? {} : { priorInterrupt }),
              note:
                '远端用户打断这一轮：不要重试、不要自动继续；把情况告诉用户，'
                + '等用户（远端或本机）给出新指示。',
            } as unknown as JsonValue
          }
          if (outcome.kind === 'reply') {
            inFlight.delete(sessionId)
            // The turn landed, so this scope now continues THIS conversation —            // including one the caller named explicitly or forced with
            // `new_session`, which must not fall back to the previous pick.
            memory.set(scopeKey(scope), sessionId)
            collectRemoteUsage(sessionId)
            const merged = mergeStreamedReplyValue(sessionId, outcome.reply)
            return {
              ...merged,
              ...replyFields(merged),
              origin,
              sessionId,
              ...(remoteUserNotes.length > 0 ? { remoteUserNotes } : {}),
              ...(priorInterrupt === undefined ? {} : { priorInterrupt }),
            } as unknown as JsonValue
          }
          // Deliberately leave the in-flight entry alone: remote_answer_question
          // consumes it to finish this very turn.
          memory.set(scopeKey(scope), sessionId)
          return {
            sessionId,
            origin,
            ...(remoteUserNotes.length > 0 ? { remoteUserNotes } : {}),
            ...(priorInterrupt === undefined ? {} : { priorInterrupt }),
            pendingQuestion: {
              qid: String(outcome.frame.qid ?? ''),
              questions: outcome.frame.questions ?? [],
            },
            note:
              '对端 agent 正在等你回答这个提问。先审查：能自行判断就直接用 '
              + 'remote_answer_question 作答；需要用户拍板就用本机 ask_user_question 问用户，'
              + '再把它的返回交给 remote_answer_question。',
          } as unknown as JsonValue
        } catch (error) {
          inFlight.delete(sessionId)
          clearStreamedReplies(sessionId)
          throw error
        } finally {
          signal?.removeEventListener('abort', onAbort)
        }
      },
    }),

    defineTool({
      name: 'remote_answer_question',
      description:
        '把对端的提问答复回去（对端正在等），并继续等这一轮结束、取回最终回复。'
        + 'question_id 用 remote_agent_prompt 返回的 pendingQuestion.qid；'
        + 'answers 是 {answers:[{id, selected:[...], custom?}]} 形状，'
        + '也可以直接传本机 ask_user_question 的返回。',
      parameters: {
        question_id: { type: 'string', required: true, description: 'pendingQuestion.qid。' },
        answers: {
          type: 'json',
          required: true,
          description: '对每个问题的作答 {answers:[{id, selected:[...], custom?}]}；也可直接传本机 ask_user_question 的返回。',
        },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            sessionId: string, reply: string, reason: string | null,
            error?: string | null, seq: number, created: boolean, durationMs: number,
          }
          const head = [
            `session: ${v.sessionId}`,
            `reason : ${v.reason ?? '(none)'}   seq: ${v.seq}   ${v.durationMs} ms`,
          ]
          if (v.error !== null && v.error !== undefined && v.error !== '') {
            head.push(`error  : ${v.error}`)
          }
          return renderText([...head, renderRemoteReplies(value)].join('\n'))
        },
      },
      async execute(args: { question_id: string, answers: unknown }): Promise<JsonValue> {
        const qid = text(args.question_id)
        const pending = qid === undefined ? undefined : relayedQuestions.get(qid)
        if (qid === undefined || pending === undefined) {
          throw new Error(
            'remote_answer_question: no relayed question with that id '
            + '(already answered, expired, or never asked)',
          )
        }
        const entry = inFlight.get(pending.sessionId)
        if (entry === undefined) {
          throw new Error(`remote_answer_question: no prompt in flight for session ${pending.sessionId}`)
        }
        // The peer's `agent.prompt` is still parked, so ITS reply is the rest of
        // the turn: send the answer, then await the request already in flight
        // instead of issuing a new one.
        await link.notify({ kind: 'answer', qid, answer: args.answers })
        relayedQuestions.delete(qid)
        try {
          const reply = await entry.prompt
          const merged = mergeStreamedReplyValue(pending.sessionId, reply)
          return { ...merged, ...replyFields(merged) } as unknown as JsonValue
        } finally {
          inFlight.delete(pending.sessionId)
          clearStreamedReplies(pending.sessionId)
        }
      },
    }),

    defineTool({
      name: 'remote_agent_ensure',
      description:
        '在对端 harness 上创建或续接一个 agent 会话，但先不发言。'
        + '用于提前把会话建好（可指定 preset），之后用 remote_agent_prompt 复用同一个 session_id。',
      parameters: {
        session_id: { type: 'string', required: true, description: '对端会话 id。' },
        preset_id: { type: 'string', description: '仅首次创建时生效的 preset id。' },
        workspace: { type: 'string', description: '会话的工作目录（仅首次创建时生效）。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as { sessionId: string, created: boolean }
          return renderText(`session ${v.sessionId}: ${v.created ? 'created' : 'resumed'}`)
        },
      },
      async execute(args: { session_id: string, preset_id?: string, workspace?: string }, exec?: { agent?: { session?: { id?: unknown } } }): Promise<JsonValue> {
        const result = await link.request('agent.ensure', {
          sessionId: args.session_id,
          ...(text(args.preset_id) === undefined ? {} : { presetId: args.preset_id }),
          ...(text(args.workspace) === undefined ? {} : { workspace: args.workspace }),
        }) as unknown as JsonValue
        // Name the conversation here, and a later defaulted `remote_agent_prompt`
        // from this chat continues it instead of starting another.
        memory.set(scopeKey(scopeOf(exec, sessionPrefixNow())), args.session_id)
        return result
      },
    }),

    defineTool({
      name: 'remote_agent_events',
      description:
        '读取对端某个会话的事件流（只含必要字段：消息文本、工具调用、turn 结束原因）。'
        + '用于把对端上下文取回本机、压缩后再投递回去。'
        + '需要该会话在对端有活动句柄（先 remote_agent_prompt 或 remote_agent_ensure 过）。',
      parameters: {
        session_id: { type: 'string', required: true, description: '对端会话 id。' },
        from_seq: { type: 'number', description: '从该序号开始取，默认 0。' },
        limit: { type: 'number', description: '最多取多少条，默认 400。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            sessionId: string, seq: number,
            events: Array<Record<string, unknown>>,
          }
          const lines = [`session ${v.sessionId}  head_seq=${v.seq}  events=${v.events.length}`]
          for (const event of v.events) {
            const body = typeof event.text === 'string' && event.text !== ''
              ? event.text.replace(/\s+/g, ' ').slice(0, 160)
              : typeof event.name === 'string' ? `${event.name} ${String(event.arguments ?? '').slice(0, 120)}`
                : typeof event.reason === 'string' ? event.reason
                  : ''
            lines.push(`${String(event.seq).padStart(5)}  ${String(event.type).padEnd(18)} ${body}`)
          }
          return renderText(lines.join('\n'))
        },
      },
      async execute(args: { session_id: string, from_seq?: number, limit?: number }): Promise<JsonValue> {
        return await link.request('agent.events', {
          sessionId: args.session_id,
          fromSeq: args.from_seq ?? 0,
          limit: args.limit ?? 400,
        }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_journal',
      description:
        '读**远端的执行轨迹**：那台机器上被执行的指令、文件读写、被驱动的轮次、模型调用与用户打断，'
        + '由对端插件在操作发生时追加——**不消耗任何模型调用**。\n'
        + '默认只返回**你上次读之后的新条目**（本插件按 chat 记住游标），所以反复调用很便宜；'
        + '要看细节传 full=true，要从头看传 from_seq=0。',
      parameters: {
        from_seq: { type: 'number', description: '只读该序号之后的条目。省略 = 接着上次读到的位置；0 = 从头读。' },
        limit: { type: 'number', description: '最多返回多少条，默认 50（上限 500）。' },
        full: { type: 'boolean', description: 'true = 带上每条的操作细节（更占上下文）。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => renderText(formatJournal(value as unknown as JournalView).join('\n')),
      },
      async execute(
        args: { from_seq?: number, limit?: number, full?: boolean },
        exec?: { agent?: { session?: { id?: unknown } } },
      ): Promise<JsonValue> {
        const key = scopeKey(scopeOf(exec, sessionPrefixNow()))
        const remembered = journalMemory.get(key)
        // Explicit wins; otherwise continue where this chat stopped. Never read
        // means undefined —the peer answers with the tail, which is what a first
        // look actually wants.
        const from = typeof args.from_seq === 'number'
          ? args.from_seq
          : (remembered === undefined ? undefined : Number(remembered))
        let reply: Record<string, unknown>
        try {
          reply = await link.request('journal.read', {
            ...(from === undefined || !Number.isFinite(from) ? {} : { fromSeq: from }),
            limit: args.limit ?? 50,
            ...(args.full === true ? { full: true } : {}),
          }, 30_000)
        } catch (error) {
          // An older controlled half has no `journal.read` at all. Say that
          // plainly (with the alternative that does work) instead of handing the
          // model a raw protocol error it cannot act on.
          const message = error instanceof Error ? error.message : String(error)
          if (/unknown op/iu.test(message)) return { unsupported: true, error: message } as unknown as JsonValue
          throw error
        }
        const next = Number(reply.nextSeq)
        if (Number.isFinite(next)) journalMemory.set(key, String(next))
        return reply as unknown as JsonValue
      },
    }),
    defineTool({
      name: 'remote_agent_interrupt',
      description: '打断对端某个会话正在跑的 turn。',
      parameters: {
        session_id: { type: 'string', required: true, description: '对端会话 id。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as { interrupted: boolean, reason?: string }
          return renderText(v.interrupted ? 'interrupted' : `not interrupted: ${v.reason ?? 'unknown'}`)
        },
      },
      async execute(args: { session_id: string }): Promise<JsonValue> {
        return await link.request('agent.interrupt', { sessionId: args.session_id }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_preset_list',
      description: '列出对端 harness 可用的 agent preset（想知道"创造模式"的 id 就用它）。',
      parameters: {},
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            available: boolean, defaultId?: string,
            presets: Array<{ id: string, name: string, broken: string | null }>,
          }
          if (!v.available) return renderText('peer has no agentPresets service mounted')
          const lines = [`default: ${v.defaultId ?? '(none)'}`]
          for (const preset of v.presets) {
            lines.push(`- ${preset.id}${preset.name === '' ? '' : `（${preset.name}）`}${preset.broken === null ? '' : ` ⚠️ ${preset.broken}`}`)
          }
          return renderText(lines.join('\n'))
        },
      },
      async execute(): Promise<JsonValue> {
        return await link.request('preset.list', {}) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_fs_list',
      description: '列出远端目录内容。',
      parameters: {
        path: { type: 'string', required: true, description: '远端目录路径。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            path: string, count: number,
            entries: Array<{ name: string, isDir: boolean, size: number, mtimeMs: number }>,
          }
          const lines = [`${v.path}  (${v.count} entries)`]
          for (const entry of v.entries) {
            const when = entry.mtimeMs === 0 ? '' : new Date(entry.mtimeMs).toISOString().slice(0, 19).replace('T', ' ')
            lines.push(`${entry.isDir ? 'dir ' : 'file'}  ${(entry.isDir ? '' : fmtBytes(entry.size)).padStart(10)}  ${when}  ${entry.name}`)
          }
          return renderText(lines.join('\n'))
        },
      },
      async execute(args: { path: string }): Promise<JsonValue> {
        return await link.request('fs.list', { path: args.path }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_fs_write',
      description: '把文本写入远端文件（自动建父目录）。对端支持时，大内容走分块+压缩的快路径。',
      parameters: {
        path: { type: 'string', required: true, description: '远端文件路径。' },
        content: { type: 'string', required: true, description: '要写入的文本。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            written: number, size: number,
            fastPath?: boolean, durationMs?: number, rateMbps?: number,
          }
          const legacy = `wrote ${v.written} bytes (remote size now ${v.size})`
          if (v.fastPath !== true) return renderText(legacy)
          const duration = typeof v.durationMs === 'number' ? v.durationMs : 0
          const rate = typeof v.rateMbps === 'number' ? v.rateMbps.toFixed(2) : '0.00'
          return renderText(`${legacy}\n传输：分块快路径，耗时 ${duration} ms，速率 ${rate} Mbit/s`)
        },
      },
      async execute(
        args: { path: string, content: string },
        exec?: { signal?: AbortSignal },
      ): Promise<JsonValue> {
        const data = Buffer.from(args.content, 'utf8')
        const threshold = Number(read().transferFastPathBytes ?? 524_288)
        // Large text is where the single-frame op hurts; small writes stay on the
        // one-round-trip path even when the peer supports chunking.
        if (data.length >= threshold) {
          try {
            if (await fastTransferSupported()) {
              const result = await uploadBuffer(transferRequest, args.path, data, {
                ...transferOptions(exec?.signal),
              })
              return {
                written: result.bytes,
                size: result.bytes,
                sha256: result.sha256,
                fastPath: true,
                durationMs: result.durationMs,
                rateMbps: result.rateMbps,
                created: result.created,
                version: result.version,
              } as unknown as JsonValue
            }
          } catch (error) {
            // A failed `commit` has an UNKNOWN outcome: the peer may have renamed
            // the file while the reply died on the wire. Never silently rewrite
            // the target in that case —report it and let the caller verify first.
            if (commitOutcomeUnknown(error) && !isTransferAbortError(error)) {
              throw ambiguousCommitError(error)
            }
            // Only "the peer turns out not to know this op" (stale probe, older
            // build) may fall back to the legacy write. That case is idempotent:
            // neither `begin` nor a chunk writes the target, so replaying through
            // `fs.write` cannot double-apply anything.
            if (!isUnknownTransferOp(error)) throw error
            ctx.logger.debug(
              `dsh-remote-client: fast write unavailable, falling back to fs.write `
              + `(${error instanceof Error ? error.message : String(error)})`,
            )
          }
        }
        return await link.request('fs.write', {
          path: args.path,
          dataB64: data.toString('base64'),
        }) as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_put_file',
      description:
        '把**本机**文件流式上传到远端（分块 + 逐块 gzip + sha256 校验）。'
        + '适合大文件；小文本仍用 remote_fs_write 更省一次往返。'
        + '需要 r19+ 对端广告分块传输 op；旧对端会报 unknown op，此时改用 remote_exec 等方式。',
      parameters: {
        local_path: { type: 'string', required: true, description: '本机源文件路径。' },
        remote_path: { type: 'string', required: true, description: '远端目标文件路径。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            bytes: number, sha256: string, created?: boolean,
            durationMs: number, rateMbps?: number,
          }
          const rate = typeof v.rateMbps === 'number' ? `，速率 ${v.rateMbps.toFixed(2)} Mbit/s` : ''
          return renderText(
            `上传 ${fmtBytes(v.bytes)}（${v.bytes} 字节），耗时 ${v.durationMs} ms${rate}`
            + `${v.created === true ? '（新建）' : ''}\nsha256 ${v.sha256}`,
          )
        },
      },
      async execute(
        args: { local_path: string, remote_path: string },
        exec?: { signal?: AbortSignal },
      ): Promise<JsonValue> {
        throwIfAborted(exec?.signal)
        // An older peer has no chunked ops at all: fall back up front rather than
        // spending a round trip on `fs.put.begin` just to learn that.
        if (!(await fastTransferSupported())) {
          return await legacyUploadFile(args.local_path, args.remote_path, exec?.signal) as unknown as JsonValue
        }
        try {
          const result = await uploadFile(transferRequest, args.local_path, args.remote_path, {
            ...transferOptions(exec?.signal),
          })
          return {
            bytes: result.bytes,
            sha256: result.sha256,
            created: result.created,
            version: result.version,
            durationMs: result.durationMs,
            rateMbps: result.rateMbps,
          } as unknown as JsonValue
        } catch (error) {
          if (commitOutcomeUnknown(error) && !isTransferAbortError(error)) {
            throw ambiguousCommitError(error)
          }
          // A stale probe is the only case worth retrying through the legacy path;
          // a real error (missing local file, permission, checksum) must surface.
          if (!isUnknownTransferOp(error)) throw error
          ctx.logger.debug(
            `dsh-remote-client: chunked upload unavailable, falling back to fs.write `
            + `(${error instanceof Error ? error.message : String(error)})`,
          )
          return await legacyUploadFile(args.local_path, args.remote_path, exec?.signal) as unknown as JsonValue
        }
      },
    }),

    defineTool({
      name: 'remote_get_file',
      description:
        '把远端文件流式下载到**本机**（分块并行 + sha256 校验）。'
        + '先写临时文件、校验通过后再改名覆盖，中断不会留下半成品；适合大文件。'
        + '需要 r19+ 对端广告分块传输 op；旧对端会报 unknown op。',
      parameters: {
        remote_path: { type: 'string', required: true, description: '远端源文件路径。' },
        local_path: { type: 'string', required: true, description: '本机目标文件路径。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => {
          const v = value as unknown as {
            bytes: number, sha256: string, durationMs: number, rateMbps?: number,
          }
          const rate = typeof v.rateMbps === 'number' ? `，速率 ${v.rateMbps.toFixed(2)} Mbit/s` : ''
          return renderText(
            `下载 ${fmtBytes(v.bytes)}（${v.bytes} 字节），耗时 ${v.durationMs} ms${rate}`
            + `\nsha256 ${v.sha256}`,
          )
        },
      },
      async execute(
        args: { remote_path: string, local_path: string },
        exec?: { signal?: AbortSignal },
      ): Promise<JsonValue> {
        throwIfAborted(exec?.signal)
        if (!(await fastTransferSupported())) {
          return await legacyDownloadFile(args.remote_path, args.local_path, exec?.signal) as unknown as JsonValue
        }
        try {
          const result = await downloadToFile(transferRequest, args.remote_path, args.local_path, {
            ...transferOptions(exec?.signal),
          })
          return {
            bytes: result.bytes,
            sha256: result.sha256,
            durationMs: result.durationMs,
            rateMbps: result.rateMbps,
          } as unknown as JsonValue
        } catch (error) {
          if (!isUnknownTransferOp(error)) throw error
          ctx.logger.debug(
            `dsh-remote-client: chunked download unavailable, falling back to fs.read `
            + `(${error instanceof Error ? error.message : String(error)})`,
          )
          return await legacyDownloadFile(args.remote_path, args.local_path, exec?.signal) as unknown as JsonValue
        }
      },
    }),

    defineTool({
      name: 'remote_capabilities',
      description:
        '列出远端 harness 可直接 function call 的能力：远端某一 agent preset 的工具（含参数 schema）、插件清单、'
        + 'preset（即子智能体类型）、子智能体 provider，以及远端当前活跃会话（只读信息）。\n'
        + '远端独有工具已直接注册进各 agent 的作用域（同名时本机工具优先，来自本机/远端的同名者都不会互相覆盖）；'
        + '要按名字调用、或看某个工具的完整 schema，用 `remote_tool_call` / 本工具的 `tool` 参数。\n'
        + '注意：这不是"让远端开一段对话"，读目录只在远端挂起一个 preset scope，不创建/续接任何会话。',
      parameters: {
        peer: { type: 'string', description: '已配置的主机名；省略使用默认主机。' },
        preset_id: { type: 'string', description: '远端 preset id；省略 = 远端默认 preset（不影响已镜像工具）。' },
        refresh: { type: 'boolean', description: 'true = 立即重新拉取目录（默认用缓存，过期才重拉）。' },
        tool: { type: 'string', description: '只看这一个远端工具的完整参数 schema。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => renderText(String((value as unknown as { text?: unknown })?.text ?? '')),
      },
      async execute(
        args: { peer?: string, preset_id?: string, refresh?: boolean, tool?: string },
        exec?: { agent?: unknown },
      ): Promise<JsonValue> {
        if (read().remoteCapabilities === false) {
          return { available: false, text: '本机已关闭远端能力镜像（dsh-remote-client: remoteCapabilities=false）。' } as unknown as JsonValue
        }
        const requestedPreset = typeof args.preset_id === 'string' ? args.preset_id.trim() : ''
        if (requestedPreset !== '' || args.peer !== undefined) {
          const catalog = await readPeerCatalog(requestedPreset, args.peer)
          return {
            ...catalogSummary(catalog, exec?.agent),
            text: formatCatalog(catalog, args.tool === undefined ? {} : { tool: args.tool }),
          } as unknown as JsonValue
        }
        await refreshCapabilityCatalog(args.refresh === true)
        const catalog = capabilityCatalog
        if (catalog === undefined) {
          return { available: false, text: renderCapabilityCatalog(args.tool, exec?.agent) } as unknown as JsonValue
        }
        return {
          ...catalogSummary(catalog, exec?.agent),
          text: renderCapabilityCatalog(args.tool, exec?.agent),
        } as unknown as JsonValue
      },
    }),

    defineTool({
      name: 'remote_tool_call',
      description:
        '在远端 harness 上**按名字直接调用一个已注册工具**，返回它渲染好的结果。'
        + '用于：本机同名工具把远端工具遮挡、工具因远端拒绝策略没被镜像、或想显式指定远端 preset。\n'
        + '调用直接在对端执行工具本体：不新建/续接远端对话，不消耗远端模型轮次；'
        + '对端需要 session 的工具（如 subagent、todo_write）会明确报错而不是替你开会话。',
      parameters: {
        peer: { type: 'string', description: '已配置的主机名；省略使用默认主机。' },
        name: { type: 'string', required: true, description: '远端工具名（见 remote_capabilities）。' },
        arguments: { type: 'json', description: '传给该工具的参数对象。' },
        preset_id: { type: 'string', description: '远端 preset id；省略 = 本插件配置的/远端默认 preset。' },
        timeout_ms: { type: 'number', description: '本次调用的超时毫秒数（对端仍会按自己的上限再夹一次）。' },
      },
      output: {
        schema: { type: 'json' },
        render: (_args, value) => renderText(String((value as unknown as { text?: unknown })?.text ?? '')),
      },
      async execute(
        args: { peer?: string, name: string, arguments?: unknown, preset_id?: string, timeout_ms?: number },
        exec?: { signal?: AbortSignal },
      ): Promise<JsonValue> {
        if (read().remoteCapabilities === false) {
          throw new Error('本机已关闭远端能力镜像（dsh-remote-client: remoteCapabilities=false）')
        }
        const name = typeof args.name === 'string' ? args.name.trim() : ''
        if (name === '') throw new Error('remote_tool_call: `name` 不能为空')
        const presetId = typeof args.preset_id === 'string' && args.preset_id.trim() !== ''
          ? args.preset_id.trim()
          : undefined
        const result = await callPeerTool(
          name,
          (args.arguments ?? {}) as Record<string, unknown>,
          exec?.signal,
          {
            ...(presetId === undefined ? {} : { presetId }),
            ...(args.timeout_ms === undefined ? {} : { timeoutMs: args.timeout_ms }),
            ...(args.peer === undefined ? {} : { peer: args.peer }),
          },
        )
        return {
          content: result.content,
          ...(result.durationMs === undefined ? {} : { durationMs: result.durationMs }),
          text: proxyResultText(result),
        } as unknown as JsonValue
      },
    }),
  ]

  // Background-run control plane, appended as its own array so a later
  // registration (worker pools, team board) is one more spread instead of an
  // edit to the verified tool list above.
  const runTools = read().backgroundRuns === false ? [] : createRunTools(runToolDeps)
  const poolTools = createPoolTools(poolDeps)
  const referenceTool = createReferenceTool({
    peers: () => Object.keys(peersNow()),
    list: referenceService.list,
  })
  const allTools = [...tools, ...runTools, ...poolTools, referenceTool]

  // The settings service publishes this plugin's page from the `Config` schema
  // above; volatile edits land in the running references, so all that is left is
  // to drop a live session that was dialled with the previous endpoint/key, and
  // to follow the subagent switch in either direction.
  ctx.on('loader/volatile-update', () => {
    link.close()
    dropSubagentIfDisabled()
    ensureSubagent()
    // Publish complete fresh declarations, not the previous load-time snapshot.
    // Close every named socket so an endpoint/key edit cannot reuse old trust.
    for (const pooled of pooledLinks.values()) pooled.dispose()
    pooledLinks.clear()
    capabilityGeneration += 1
    capabilityInFlight = undefined
    capabilityCatalog = undefined
    capabilityCatalogAt = 0
    capabilityUnsupported = false
    capabilityCatalogFingerprint = ''
    try {
      const next = peersNow()
      validatePeerNames(Object.keys(next))
      const registry = ctx.get('dshRemotePeers') as PeerRegistry | undefined
      registry?.update({ peers: next, defaultPeer: text(read().defaultPeer) ?? '' })
      peers = next
    } catch (error) {
      // An invalid replacement must not leave the previous pins/permissions live.
      const registry = ctx.get('dshRemotePeers') as PeerRegistry | undefined
      registry?.update({ peers: {}, defaultPeer: '' })
      peers = {}
      ctx.logger.warn(`dsh-remote-client: invalid peer update; all mounts revoked (${String(error)})`)
    }
    // A preset/deny/timeout edit changes what should be mirrored. Withdraw first
    // when the feature just went off, then refetch in the background so the
    // registry follows the new configuration without a restart.
    if (read().remoteCapabilities === false) {
      void withdrawCapabilityMirrors()
    } else {
      void refreshCapabilityCatalog(true)
    }
  })

  const safeEffect = (fn: () => () => void, label: string): void => {
    // Best effort: a hot reload can hand apply() an already-inactive context,
    // where ctx.effect() throws and would abort the registration below.
    try {
      ctx.effect(fn, label)
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not register teardown (${String(error)})`)
    }
  }

  // The inbound IO adapter owns no transport or timer; release its binding
  // cache so a hot reload cannot keep using a disposed service.
  safeEffect(() => () => inboundIo.dispose(), 'dsh-remote-client: release inbound IO adapter')

  // Pooled links are per-peer and outlive any single tool call; close them with
  // the plugin rather than leaving idle sockets open.
  safeEffect(() => () => {
    for (const pooled of pooledLinks.values()) pooled.dispose()
  }, 'dsh-remote-client: close pooled peer links')

  // Present the peer as a DSH subagent provider when asked (default off).
  //
  // The kit is imported LAZILY and the whole block is quarantined: this plugin is
  // installed by profile link and only carries a node_modules junction for the
  // packages it statically imports, so a module-scope import of
  // `@deepseek-ai/dsh-subagent` would make the plugin unloadable on a machine
  // that has not linked it. A failure here degrades to "no subagent provider",
  // never to "no plugin".
  //
  // Registered through one ensure/drop pair rather than a bare `if`, because the
  // switch is a SETTING: toggling it in the GUI has to work, and only a volatile
  // update tells this half about it.
  let dropSubagent: (() => void) | undefined
  let subagentPending = false
  const ensureSubagent = (): void => {
    if (read().subagentProvider !== true || dropSubagent !== undefined || subagentPending) return
    subagentPending = true
    try {
      ctx.inject(['subagents'], (subagentsCtx: Context) => {
        void (async () => {
          try {
            const kit = await import('@deepseek-ai/dsh-subagent') as unknown as RemoteSubagentKit
            const provider = createRemoteProvider({
              kit,
              name: 'remote',
              sessionFor: sessionForProvider,
              prompt: request => operationPeer.run(operationPeer.getStore() ?? controlFor(), () => promptForProvider(request)),
              interrupt: interruptRemote,
              log,
            })
            const dropProvider = subagentsCtx.subagents.registerProvider(
              provider as unknown as Parameters<typeof subagentsCtx.subagents.registerProvider>[0],
            )
            // The delegation tool is registered here rather than by asking the
            // operator to add a `tool-subagent` row: one switch turns the feature
            // on, and the official row (which adds background runs) stays an
            // alternative rather than a prerequisite.
            let dropTool: (() => void) | undefined
            if (config.toolEnabled !== false) {
              ctx.inject(['tools'], (toolsCtx: Context) => {
                dropTool = toolsCtx.tools.register(createRemoteSubagentTool(
                  subagentsCtx.subagents as unknown as Parameters<typeof createRemoteSubagentTool>[0],
                  'remote',
                ))
                log(`dsh-remote-client: registered ${REMOTE_SUBAGENT_TOOL}`)
              })
            }
            dropSubagent = () => { dropTool?.(); dropProvider() }
            log('dsh-remote-client: registered subagent provider "remote"')
          } catch (error) {
            ctx.logger.warn(
              'dsh-remote-client: subagent provider NOT registered '
              + `(${error instanceof Error ? error.message : String(error)}); `
              + 'link `@deepseek-ai/dsh-subagent` into this plugin to enable it',
            )
          } finally {
            subagentPending = false
          }
        })()
      })
    } catch (error) {
      subagentPending = false
      ctx.logger.warn(`dsh-remote-client: could not register the subagent provider (${String(error)})`)
    }
  }
  /** Withdraw the provider and its tool when the switch is turned off. */
  const dropSubagentIfDisabled = (): void => {
    if (read().subagentProvider === true) return
    try {
      dropSubagent?.()
    } catch (error) {
      ctx.logger.warn(`dsh-remote-client: could not drop the subagent provider (${String(error)})`)
    }
    dropSubagent = undefined
  }
  ensureSubagent()

  // Refresh the external-usage snapshot once at boot. The snapshot a previous
  // process wrote is still the truth about past remote spend, but cost-meter
  // marks anything older than 24 hours as stale; re-stamping it keeps the
  // external totals (and balance reconciliation) live even when this process
  // drives no remote turn before the user looks. Only done when there is
  // something recorded: an empty store would otherwise publish a permanent
  // "$0 remote source" row to every cost-meter user who never used this link.
  // Purely local, so it is safe on the controlled machine too, where the client
  // half also loads with `toolEnabled: false`. Best effort and never awaited.
  try {
    const store = currentCostStore()
    if (read().costReporting === true && store.summary().records > 0) {
      void store.refreshSnapshot()
    }
  } catch (error) {
    ctx.logger.debug(
      `dsh-remote-client: cost snapshot refresh failed (${error instanceof Error ? error.message : String(error)})`,
    )
  }

  if (config.toolEnabled === false) {
    safeEffect(() => () => link.dispose(), 'dsh-remote-client: close link')
    return
  }

  // Lazy wait keeps the plugin loadable in a composition without a tools
  // registry; when `tools` appears the set lands in the global layer.
  ctx.inject(['tools'], (toolsCtx: Context) => {
    for (const tool of allTools) toolsCtx.tools.register(bindOperation(tool))
    log(
      `dsh-remote-client: registered ${allTools.length} tools `
      + `(peer ${text(read().host) ?? '?'}:${read().port ?? 0}, fingerprint ${fingerprintSafe(read)})`,
    )
    // Mirrors come after the static tools so a remote tool can never displace
    // one of this plugin's own names (the registry would reject the duplicate).
    attachCapabilityMirrors()
  })

  // Tell every local chat what this link is for, and —the load-bearing part —  // which remote conversation it owns. The text is a function, so the id is
  // derived from the session being assembled: the guidance and the code cannot
  // disagree, and the model is told the rule instead of having to discover it.
  if (read().promptGuidance !== false) {
    ctx.inject(['systemPrompt'], (promptCtx: Context) => {
      promptCtx.systemPrompt.section({
        name: 'dsh-remote:controller',
        // A free slot just before the first-party tool guidance (900 is taken by
        // file references, 1000 by the bash tool).
        order: 960,
        text: (context) => {
          const current = read()
          const peers = peersNow()
          // A deployment may declare only `peers` (no legacy host/port); the
          // guidance is about the link, so any declaration is enough.
          if (Object.keys(peers).length === 0) return ''
          const prefix = sessionPrefixNow()
          const session = (context as { agent?: { session?: { id?: unknown } } }).agent?.session?.id
          const own = typeof session === 'string' && session !== ''
            ? anchorSessionId(prefix, session)
            : undefined
          const endpoint = text(current.host) === undefined || (current.port ?? 0) <= 0
            ? `已声明 ${Object.keys(peers).length} 个 peer`
            : `对端 ${text(current.host)}:${current.port}`
          return [
            '## 远端 harness（dsh-remote 插件）',
            `本机可以驱动另一台机器上的 DSH 实例（${endpoint}）。`
            + '把每段远端对话当作**你自己的一个 subagent / task**：你派活、它交付，'
            + '结论与产物摘要必须带回本机上下文，不要把它当成本机编排的执行器。',
            '**一个 chat 只对应一个远端对话（严格要求）。**'
            + (own === undefined
              ? '本 chat 的远端会话按本机会话推导，省略 session_id 时会自动续接它。'
              : `本 chat 的远端会话固定是 \`${own}\`，省略 session_id 即续接它。`),
            '不要为了「隔离」或「换个话题」而传 session_id / new_session —— '
            + '那只会让对端多开一段对话。只有用户明确要求另起一段时，才用 new_session=true。',
            '**本机优先**：能在本机上下文里完成的事就在本机做；'
            + '只有确实必须跑在对端机器上的动作（对端的文件、对端的环境、对端已有的会话）才用 remote_* 工具。'
            + '非必要不新开对话，也不要为琐碎步骤反复往返。',
            ...(read().remoteCapabilities !== false
              ? ['**远端能力直连**：对端独有工具已注册进本 agent 的作用域（本机同名工具优先，无前缀）；'
                + '`remote_capabilities` 列对端能力（工具/插件/preset/provider），'
                + '`remote_tool_call(name, arguments)` 按名调用（本机遮挡时用它）。这些调用直接执行对端工具本体，'
                + '不新建/续接远端对话、不消耗远端模型轮次；需要会话的工具（subagent 等）会报错而不是替你开会话。']
              : []),
            ...(read().subagentProvider !== false
              ? ['整块子任务用 `subagent_remote(description, prompt)` 委派——它会作为 subagent 出现在本对话里；'
                + '零散的一轮发言或追问用 `remote_agent_prompt`。两者打的是同一段远端对话。']
              : []),
            ...(read().backgroundRuns !== false
              ? ['**长任务 / 不想阻塞本轮**用 `remote_run_start`：它立即返回 runId，后台继续跑；'
                + '之后用 `remote_run_status(run_id, wait_ms?)` 取交付（结果不会自动出现），'
                + '`remote_send_message(run_id=...)` 追加指示，`remote_run_cancel(run_id=...)` 打断。'
                + '要**交付进本对话**、值得等待的整块任务仍用 `subagent_remote`，不要两者混用同一个任务。']
              : []),
            ...(Object.keys(peers).length > 1
              ? ['**多个远端 worker**：`remote_workers` 列出已声明的 peer；'
                + '`remote_worker_prompt(peer, text)` 指定一台；'
                + '`remote_pool_dispatch(prompt, peers?)` 把同一任务并行派给多台并聚合结果（单台失败不影响其他台）。']
              : []),
            ...(teamService() === undefined
              ? []
              : ['在 **Agent Teams** 会话里，`remote_team_dispatch(description, prompt, peer?)` 会把这次远端工作登记到共享任务板'
                + '（建任务→认领→完成后写回摘要），返回的 taskId 可用 `team_task_get` 查；'
                + '远端 peer 本身不在 roster 里，看板上的 owner 是调用方。'
                + '只是并行刷多台、不要求看板时用 `remote_pool_dispatch`。']),
            '**打断高于一切**：用户在本机中断时，插件会同时中断对端那一轮；'
            + '若远端返回里出现 interrupted / 被打断的标记，立刻停下，不要重试、不要自动继续，'
            + '把当前状态和选择权交回用户。',
            '需要知道"对端到底做了什么"时用 `remote_journal` 读它的执行轨迹——'
            + '不消耗模型调用，且默认只返回**上次读过之后的新条目**，所以可以放心地反复查。',
          ].join('\n')
        },
      })
    })
  }

  safeEffect(() => () => link.dispose(), 'dsh-remote-client: close link')
}

/** Best-effort peer fingerprint for the boot log; never throws. */
function fingerprintSafe(read: () => ResolvedConfig): string {
  try {
    return fingerprint(resolvePeerPublicKey(read(), 'server.pub'))
  } catch {
    return '(peer key not configured)'
  }
}

export { LinkClient }
