/**
 * Live check of the reuse path against a real peer — no DSH, no cordis.
 *
 * It answers one question: when `remote_agent_prompt` gets no `session_id`,
 * which remote conversation does this client pick, and does the peer actually
 * continue it rather than create another? The steps mirror the plugin exactly
 * (`sysinfo` → `agent.sessions` when advertised, else the legacy live list →
 * `pickReusableSession`), so a pass here means the decision the tool makes is
 * the one you would observe in a conversation.
 *
 * Read-only unless `--prompt` is given; without it nothing is sent to an agent.
 *
 *   cd <deepseek-harness root>
 *   node --import tsx/esm E:/path/to/dsh-remote/test/live-reuse.ts \
 *     --host <peer host> --port <peer port> [--prefix remote] [--workspace E:\proj] [--prompt]
 *
 * Keys come from the same place the plugin reads them: `${DSH_HOME}/dsh-remote/`
 * (`client.key` + `server.pub`), overridable with `--private-key-file` /
 * `--peer-public-key-file`.
 */

import { LinkClient } from '../src/link.ts'
import { anchorSessionId, pickReusableSession, scopeKey } from '../src/reuse.ts'
import type { RemoteSession } from '../src/reuse.ts'
import { dshHomePath } from '../src/keys.ts'

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`)
  if (index === -1) return undefined
  const value = process.argv[index + 1]
  return value === undefined || value.startsWith('--') ? '' : value
}

const host = arg('host') ?? process.env.DSHR_HOST ?? ''
const port = Number(arg('port') ?? process.env.DSHR_PORT ?? 0)
const prefix = arg('prefix') ?? 'remote'
const workspace = arg('workspace')
const withPrompt = process.argv.includes('--prompt')

if (host === '' || port <= 0) {
  console.error('give --host and --port (the peer the plugin is configured against)')
  process.exitCode = 2
} else {
  const link = new LinkClient(() => ({
    host,
    port,
    privateKeyFile: arg('private-key-file') ?? dshHomePath('dsh-remote', 'client.key'),
    peerPublicKeyFile: arg('peer-public-key-file') ?? dshHomePath('dsh-remote', 'server.pub'),
    timeoutMs: 120_000,
  }), message => console.log(`   link: ${message}`), 'dsh-remote(live-check)')

  const toCandidates = (raw: unknown): RemoteSession[] => {
    if (!Array.isArray(raw)) return []
    return raw.flatMap((item) => {
      if (typeof item === 'string') return item === '' ? [] : [{ sessionId: item }]
      if (item === null || typeof item !== 'object') return []
      const row = item as Record<string, unknown>
      if (typeof row.sessionId !== 'string' || row.sessionId === '') return []
      return [{
        sessionId: row.sessionId,
        ...(typeof row.cwd === 'string' ? { cwd: row.cwd } : {}),
        ...(typeof row.live === 'boolean' ? { live: row.live } : {}),
        ...(typeof row.seq === 'number' ? { seq: row.seq } : {}),
      }]
    })
  }

  try {
    const info = await link.request('sysinfo', {}, 30_000)
    console.log(`peer: ${String(info.hostname)}  build=${String(info.build)}  platform=${String(info.platform)}`)
    const ops = Array.isArray(info.ops) ? info.ops.map(String) : []
    console.log(`advertised ops: ${ops.length === 0 ? '(none — pre-r11 peer)' : ops.join(', ')}`)

    let candidates: RemoteSession[]
    if (ops.includes('agent.sessions')) {
      const listed = await link.request('agent.sessions', {
        ...(prefix === '' ? {} : { prefix }),
        ...(workspace === undefined ? {} : { workspace }),
      }, 30_000)
      candidates = toCandidates(listed.sessions)
      console.log(`agent.sessions returned ${candidates.length} conversation(s)`)
    } else {
      candidates = toCandidates(info.sessions).reverse()
      console.log(`legacy sysinfo.sessions returned ${candidates.length} live id(s) (reversed to newest first)`)
    }
    for (const [index, candidate] of candidates.slice(0, 8).entries()) {
      console.log(
        `   ${index === 0 ? '->' : '  '} ${candidate.sessionId}`
        + `${candidate.cwd === undefined ? '' : `  cwd=${candidate.cwd}`}`
        + `${candidate.live === undefined ? '' : `  live=${String(candidate.live)}`}`
        + `${candidate.seq === undefined ? '' : `  seq=${candidate.seq}`}`,
      )
    }

    const picked = pickReusableSession(candidates, {
      prefix,
      ...(workspace === undefined ? {} : { workspace }),
    })
    // The rule under test: the id is a pure function of the calling chat, and the
    // peer continues it when it already exists.
    const chat = arg('session') ?? 'session-live-check-0001'
    const chosen = anchorSessionId(prefix, chat)
    const exists = candidates.some(candidate => candidate.sessionId === chosen)
    console.log(`\nlocal chat     : ${chat}`)
    console.log(`chosen session : ${chosen}   (${exists ? 'already on the peer -> REUSE' : 'not on the peer yet -> will be created once'})`)
    console.log(`stable         : ${anchorSessionId(prefix, chat) === chosen}`)
    console.log(`other chat     : ${anchorSessionId(prefix, 'session-live-check-0002')}`)
    console.log(
      `adoption would : ${picked === undefined ? '(nothing to adopt)' : picked.sessionId}`
      + '   — only used when adoptExistingSessions is on',
    )
    console.log(`scope key      : ${scopeKey({ prefix, localSession: chat })}`)

    if (withPrompt) {
      const reply = await link.request('agent.prompt', {
        sessionId: chosen,
        text: '只回复 OK，不要做别的事。',
        timeoutMs: 180_000,
      }, 240_000)
      console.log(`\nprompt -> session: ${String(reply.sessionId)}  created=${String(reply.created)}`)
      console.log(`reply           : ${String(reply.reply ?? '(empty)')}`)
      console.log(reply.created === false
        ? 'PASS: the peer continued this chat\'s existing conversation (created=false)'
        : 'NOTE: the peer created this chat\'s conversation (first use)')
    }
  } catch (error) {
    console.error(`live check failed: ${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  } finally {
    link.close()
  }
}
