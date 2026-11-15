/**
 * Self-test for the `rmt:` remote-path feature:
 *
 *  1. the shared scheme parser both halves use;
 *  2. the completion query splitter;
 *  3. the file-reference provider end to end against a REAL cordis context with
 *     a fake `fs` backend advertising `supportsRemotePaths` — proving `@rmt:`
 *     candidates come from the peer backend and local queries still fall back
 *     to the shipped local provider.
 *
 * Run from the harness checkout so `tsx` resolves:
 *   node --import tsx/esm E:/path/to/dsh-remote/test/remote-paths.test.ts
 */

import { Context, Service } from '@deepseek-ai/cordis'
import { formatFileMention } from '@deepseek-ai/dsh-file-reference'
import LocalFileReferenceService from '@deepseek-ai/dsh-file-reference-local'

import {
  isRemotePath,
  parseMountPath,
  parseMountReferenceQuery,
  parseRemotePath,
  parseRemoteReferenceQuery,
  parseScpPath,
  parseScpReferenceQuery,
} from '../src/remote-path.ts'
import RemoteFileReferenceService from '../src/file-reference.ts'

let failures = 0
function check(label: string, ok: boolean, detail?: string): void {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

// ---------------------------------------------------------------------------
// 1. the scheme parser
// ---------------------------------------------------------------------------

console.log('\n== 1. rmt: path parsing ==')
{
  const forward = parseRemotePath('rmt:/E:/data/archives/')
  check('forward-slash spelling', forward?.remote === 'E:/data/archives/' && forward?.separator === '/', JSON.stringify(forward))
  const back = parseRemotePath('rmt:\\E:\\data\\archives\\')
  check('backslash spelling', back?.remote === 'E:\\data\\archives\\' && back?.separator === '\\', JSON.stringify(back))
  const posix = parseRemotePath('rmt://home/u/x')
  check('double slash keeps an absolute POSIX path', posix?.remote === '/home/u/x', JSON.stringify(posix))
  check('a plain local path is not remote', parseRemotePath('E:/x') === undefined)
  check('isRemotePath agrees', isRemotePath('RMT:/x') && !isRemotePath('E:/x'))
}

console.log('\n== 2. completion query split ==')
{
  const deep = parseRemoteReferenceQuery('rmt:/E:/data/ar')
  check('prefix/partial/rest split', deep?.prefix === 'rmt:/E:/data/' && deep?.partial === 'ar' && deep?.rest === 'E:/data/ar',
    JSON.stringify(deep))
  const back = parseRemoteReferenceQuery('rmt:\\E:\\data\\')
  check('backslash style is preserved in the prefix',
    back?.separator === '\\' && back.prefix.endsWith('\\') && back.partial === '' && back.rest === 'E:/data/',
    JSON.stringify(back))
  const root = parseRemoteReferenceQuery('rmt:')
  check('root query', root?.partial === '' && root?.rest === '', JSON.stringify(root))
  check('bare rmt is not a remote query here', parseRemoteReferenceQuery('rmt') === undefined)
  check('local query is not a remote query', parseRemoteReferenceQuery('src/app') === undefined)
}

console.log('\n== 2b. scp/rsync-style peer spelling ==')
{
  const isPeer = (name: string): boolean => name === 'home-pc' || name === 'laptop'
  const forward = parseScpPath('home-pc:/E:/data/archives/', isPeer)
  check('peer:/ spelling', forward?.peer === 'home-pc' && forward?.remote === 'E:/data/archives/',
    JSON.stringify(forward))
  const back = parseScpPath('home-pc:\\E:\\data\\', isPeer)
  check('peer:\\ spelling normalizes the remote side',
    back?.peer === 'home-pc' && back?.remote === 'E:/data/' && back?.separator === '\\',
    JSON.stringify(back))
  check('a drive letter is not a peer', parseScpPath('E:/data/x', isPeer) === undefined)
  check('an undeclared token is not a peer', parseScpPath('nobody:/E:/x', isPeer) === undefined)
  check('a local path is not a peer path', parseScpPath('src/app.ts', isPeer) === undefined)

  const q = parseScpReferenceQuery('home-pc:/E:/data/ar', ['laptop', 'home-pc'])
  check('completion split uses the typed prefix',
    q !== undefined && !('peerHint' in q) && q.peer === 'home-pc' && q.prefix === 'home-pc:/E:/data/'
    && q.partial === 'ar' && q.rest === 'E:/data/ar', JSON.stringify(q))
  const hint = parseScpReferenceQuery('hom', ['laptop', 'home-pc'])
  check('a peer-name prefix yields a hint', hint !== undefined && 'peerHint' in hint && hint.peerHint === 'home-pc',
    JSON.stringify(hint))
  check('an unknown token with a colon yields nothing', parseScpReferenceQuery('nobody:/E:/x', ['home-pc']) === undefined)
}

console.log('\n== 2c. mount spelling /rmt/… (the only one Markdown can render) ==')
{
  const isPeer = (name: string): boolean => name === 'home-pc' || name === 'laptop'
  const def = parseMountPath('/rmt/E:/data/a.jpg', isPeer)
  check('default peer path', def?.peer === undefined && def?.remote === 'E:/data/a.jpg' && def.isDefaultPeer,
    JSON.stringify(def))
  const named = parseMountPath('/rmt/home-pc/E:/data/a.jpg', isPeer)
  check('named peer path', named?.peer === 'home-pc' && named?.remote === 'E:/data/a.jpg', JSON.stringify(named))
  const posix = parseMountPath('/rmt//home/u/a.jpg', isPeer)
  check('POSIX absolute peer path', posix?.remote === '/home/u/a.jpg', JSON.stringify(posix))
  check('an undriven /rmt first segment is default peer',
    parseMountPath('/rmt/somefile.jpg', isPeer)?.remote === 'somefile.jpg')
  check('non-mount path is not a mount path', parseMountPath('rmt:/E:/x', isPeer) === undefined)

  const root = parseMountReferenceQuery('/rmt/', ['home-pc', 'laptop'], 'home-pc')
  check('mount root', root?.root === true, JSON.stringify(root))
  const hint = parseMountReferenceQuery('/rmt/hom', ['home-pc', 'laptop'], 'home-pc')
  check('mount peer-name hint', hint?.peerHint === 'home-pc', JSON.stringify(hint))
  const namedQuery = parseMountReferenceQuery('/rmt/laptop/E:/data/ar', ['home-pc', 'laptop'], 'home-pc')
  check('named mount query split',
    namedQuery !== undefined && namedQuery.peer === 'laptop' && namedQuery.rest === 'E:/data/ar'
    && namedQuery.partial === 'ar', JSON.stringify(namedQuery))
}

// ---------------------------------------------------------------------------
// 3. the file-reference provider against a real cordis context
// ---------------------------------------------------------------------------

/** Minimal agents service: the provider only lists agents. */
class FakeAgents extends Service {
  constructor(ctx: Context) {
    super(ctx, 'agents')
  }

  list(): never[] {
    return []
  }

  get(): undefined {
    return undefined
  }
}

/** Fake federated filesystem: one directory with a dir and a file. */
class FakeFs extends Service {
  static inject: string[] = []
  supportsRemotePaths = true
  readonly calls: string[] = []

  constructor(ctx: Context) {
    super(ctx, 'fs')
  }

  /** The default peer is first, as the real backend orders it. */
  remotePeerNames(): string[] {
    return ['home-pc', 'laptop']
  }

  remoteDefaultPeerName(): string {
    return 'home-pc'
  }

  async resolve(path: string): Promise<{ targetKey: string, displayPath: string }> {
    this.calls.push(`resolve:${path}`)
    const remote = path.replace(/^(?:rmt:|home-pc:|laptop:)[\\/]?/u, '')
    return { targetKey: `peer:home-pc:${remote}` as never, displayPath: path }
  }

  async listDir(target: { targetKey: string }): Promise<Array<{ name: string, type: string, target: unknown }>> {
    this.calls.push(`list:${target.targetKey}`)
    return [
      { name: 'archives', type: 'directory', target: {} },
      { name: 'alpha.txt', type: 'file', target: {} },
      { name: 'beta.txt', type: 'file', target: {} },
    ]
  }

  async stat(target: { targetKey: string }): Promise<{ version: string, type: string, size: number }> {
    this.calls.push(`stat:${target.targetKey}`)
    return { version: 'v1' as never, type: 'directory', size: 0 }
  }
}

/** A backend that is NOT federated: remote completion must be silent. */
class LocalOnlyFs extends FakeFs {
  override supportsRemotePaths = false
}

async function makeContext(fsPlugin: typeof FakeFs): Promise<{ ctx: Context, fs: FakeFs }> {
  const ctx = new Context()
  await ctx.plugin(FakeAgents)
  await ctx.plugin(fsPlugin)
  await ctx.plugin(RemoteFileReferenceService, {})
  return { ctx, fs: ctx.get('fs') as unknown as FakeFs }
}

const agent = {
  session: { header: { cwd: process.cwd() } },
  ctx: {},
} as never

console.log('\n== 3. @rmt: completion emits explicit host:/ candidates ==')
{
  const { ctx, fs } = await makeContext(FakeFs)
  const signal = new AbortController().signal
  const listed = await ctx.get('fileReferences')!.list(agent as never, 'rmt:/E:/data/', signal)
  check('lists the peer directory', listed.length === 3, JSON.stringify(listed))
  check('directory candidates name their host',
    listed[0]?.path === 'home-pc:/E:/data/archives' && listed[0]?.kind === 'directory',
    JSON.stringify(listed[0]))
  check('the mention formatter renders one trailing slash',
    formatFileMention(listed[0]!, false) === '@home-pc:/E:/data/archives/',
    String(formatFileMention(listed[0]!, false)))
  check('files come after directories', listed[1]?.path === 'home-pc:/E:/data/alpha.txt' && listed[1]?.kind === 'file',
    JSON.stringify(listed[1]))
  check('the listed directory was resolved through the same alias', fs.calls.includes('resolve:home-pc:/E:/data/'), fs.calls.join(','))

  fs.calls.length = 0
  const filtered = await ctx.get('fileReferences')!.list(agent as never, 'rmt:/E:/data/al', signal)
  check('the partial segment filters entries', filtered.length === 1 && filtered[0]?.path === 'home-pc:/E:/data/alpha.txt',
    JSON.stringify(filtered))

  fs.calls.length = 0
  const back = await ctx.get('fileReferences')!.list(agent as never, 'rmt:\\E:\\data\\be', signal)
  check('backslash typing still resolves, candidates use /',
    back.length === 1 && back[0]?.path === 'home-pc:/E:/data/beta.txt', JSON.stringify(back))

  fs.calls.length = 0
  const root = await ctx.get('fileReferences')!.list(agent as never, 'rmt:/', signal)
  check('root completion lists drives without a trailing slash',
    root.length > 0 && root.every(row => /^home-pc:\/[A-Z]:$/u.test(row.path)), JSON.stringify(root.slice(0, 3)))
  check('a selected drive renders as @home-pc:/C:/',
    formatFileMention(root[0]!, false) === '@home-pc:/C:/', String(formatFileMention(root[0]!, false)))
  await ctx.fiber.dispose()
}

console.log('\n== 3b. peer spellings complete to the explicit host:/ form ==')
{
  const { ctx, fs } = await makeContext(FakeFs)
  const signal = new AbortController().signal

  // A named peer, even the default one, keeps its name in the mention.
  const listed = await ctx.get('fileReferences')!.list(agent as never, 'home-pc:/E:/data/', signal)
  check('a default-peer alias completes to host:/…',
    listed.length === 3 && listed[0]?.path === 'home-pc:/E:/data/archives', JSON.stringify(listed.slice(0, 2)))
  check('its formatter output names the host',
    formatFileMention(listed[0]!, false) === '@home-pc:/E:/data/archives/',
    String(formatFileMention(listed[0]!, false)))
  check('the backend was asked through the same alias',
    fs.calls.includes('resolve:home-pc:/E:/data/'), fs.calls.join(','))

  const named = await ctx.get('fileReferences')!.list(agent as never, 'laptop:/E:/data/', signal)
  check('a non-default peer keeps its name',
    named.length === 3 && named[0]?.path === 'laptop:/E:/data/archives', JSON.stringify(named.slice(0, 2)))

  // Mount-root completion offers peer directories.
  const mountRoot = await ctx.get('fileReferences')!.list(agent as never, '/rmt/', signal)
  check('mount root offers peer directories',
    mountRoot.length === 2 && mountRoot[0]?.path === 'home-pc:' && mountRoot[1]?.path === 'laptop:',
    JSON.stringify(mountRoot))
  check('a peer directory renders as @home-pc:/',
    formatFileMention(mountRoot[0]!, false) === '@home-pc:/',
    String(formatFileMention(mountRoot[0]!, false)))

  // A peer-name prefix under the mount.
  const hint = await ctx.get('fileReferences')!.list(agent as never, '/rmt/hom', signal)
  check('a mount peer-name prefix offers the peer', hint.some(row => row.path === 'home-pc:'), JSON.stringify(hint))

  // Default-peer path typed directly in mount spelling.
  const defaultMount = await ctx.get('fileReferences')!.list(agent as never, '/rmt/E:/data/', signal)
  check('a mount-spelling default path lists entries',
    defaultMount.length === 3 && defaultMount[0]?.path === 'home-pc:/E:/data/archives', JSON.stringify(defaultMount.slice(0, 2)))

  // Drive root in mount spelling for a named peer.
  const drives = await ctx.get('fileReferences')!.list(agent as never, '/rmt/laptop/', signal)
  check('a named peer mount lists drives',
    drives.length > 0 && drives.every(row => /^laptop:\/[A-Z]:$/u.test(row.path)), JSON.stringify(drives.slice(0, 3)))

  const scpAlias = await ctx.get('fileReferences')!.list(agent as never, 'laptop:/', signal)
  check('the scp alias completes to host:/ paths too',
    scpAlias.length > 0 && scpAlias.every(row => row.path.startsWith('laptop:/')), JSON.stringify(scpAlias.slice(0, 2)))
  await ctx.fiber.dispose()
}

console.log('\n== 4. local queries still use the shipped provider ==')
{
  const { ctx } = await makeContext(FakeFs)
  const signal = new AbortController().signal
  const provider = ctx.get('fileReferences')!
  const local = await provider.list(agent as never, 'src/app', signal)
  const expected = await LocalFileReferenceService.prototype.list.call(provider, agent as never, 'src/app', signal)
  check('a local query returns exactly the shipped provider candidates', JSON.stringify(local) === JSON.stringify(expected),
    JSON.stringify(local))

  const bare = await ctx.get('fileReferences')!.list(agent as never, 'rmt', signal)
  check('bare rmt offers the default host', bare.some(row => row.path === 'home-pc:'), JSON.stringify(bare))
  await ctx.fiber.dispose()
}

console.log('\n== 5. without the federated backend, remote completion stays silent ==')
{
  const { ctx } = await makeContext(LocalOnlyFs)
  const listed = await ctx.get('fileReferences')!.list(agent as never, '/rmt/E:/data/', new AbortController().signal)
  check('no mount candidates when fs does not support remote paths', listed.length === 0, JSON.stringify(listed))
  const alias = await ctx.get('fileReferences')!.list(agent as never, 'rmt:/E:/data/', new AbortController().signal)
  check('no alias candidates either', alias.length === 0, JSON.stringify(alias))
  await ctx.fiber.dispose()
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
// The local provider keeps a timer-less cache but the cordis root fiber can hold
// a pending effect; exit explicitly like the other lifecycle tests.
process.exit(failures === 0 ? 0 : 1)
