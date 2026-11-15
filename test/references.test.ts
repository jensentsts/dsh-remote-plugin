import assert from 'node:assert/strict'
import { Context, Service } from '@deepseek-ai/cordis'
import { listReferenceCatalog } from '../src/reference-catalog.ts'
import { parseHostReference, parseReferenceCatalog, matchingWorkspaces, workspaceChildPath, referenceTokens } from '../src/reference-query.ts'
import { resolveCatalogReference, createReferenceTool } from '../src/reference-tool.ts'
import { configuredPeers, configuredDefaultPeer, defaultEndpoint } from '../src/peer-configuration.ts'
import { RemoteFileReferenceService } from '../src/file-reference.ts'

const names = ['studio', 'laptop']
assert.deepEqual(parseHostReference('studio:/C:/data/report.txt', names), { peer: 'studio', kind: 'path', path: 'C:/data/report.txt' })
assert.deepEqual(parseHostReference('studio:产品/docs/a.txt', names), { peer: 'studio', kind: 'search', query: '产品', relative: 'docs/a.txt' })
assert.deepEqual(parseHostReference('studio:workspace:ws-01/src/', names), { peer: 'studio', kind: 'workspace', query: 'ws-01', relative: 'src/' })
assert.equal(parseHostReference('C:/data', names), undefined)
assert.equal(parseHostReference('unknown:/C:/data', names), undefined)
assert.deepEqual(parseHostReference('studio:plugin:@example/clock', names), { peer: 'studio', kind: 'plugin', query: '@example/clock', relative: '' })
assert.equal(workspaceChildPath('C:/projects/产品', 'docs/a.txt'), 'C:/projects/产品/docs/a.txt')
assert.equal(workspaceChildPath('/', 'docs/a.txt'), '/docs/a.txt')
for (const bad of ['../secret', '/etc/passwd', 'C:/secret', 'x/../../y', 'x\\..\\secret']) assert.throws(() => workspaceChildPath('C:/root', bad))
assert.deepEqual(referenceTokens('mail a@studio:thing `@studio:ignored` @studio:产品\n```ts\n@studio:hidden\n```\n@"studio:设计 笔记/docs/a.txt"'), ['studio:产品', 'studio:设计 笔记/docs/a.txt'])

const workspaces = [
  { id: 'ws-01', title: '产品', path: 'C:/projects/product' },
  { id: 'ws-02', title: 'Notes', path: 'D:/notes/one' },
  { id: 'ws-03', title: 'Notes', path: 'D:/notes/two' },
]
assert.equal(matchingWorkspaces(workspaces, 'Notes').length, 2)
assert.equal(matchingWorkspaces(workspaces, 'ws-02')[0]?.path, 'D:/notes/one')
const plugin = { id: 'clock', name: '@example/clock', enabled: true }
const catalog = parseReferenceCatalog({ workspaces, plugins: [plugin], available: true })
assert.equal(resolveCatalogReference(parseHostReference('studio:产品/docs/a.txt', names)!, catalog).path, '/rmt/studio/C:/projects/product/docs/a.txt')
assert.equal(resolveCatalogReference(parseHostReference('studio:Notes', names)!, catalog).status, 'ambiguous')
assert.equal(resolveCatalogReference(parseHostReference('studio:clock', names)!, catalog).kind, 'plugin')
const clash = { ...catalog, workspaces: [{ id: 'ws-04', title: 'clock', path: 'C:/clock' }] }
assert.equal(resolveCatalogReference(parseHostReference('studio:clock', names)!, clash).status, 'ambiguous')
assert.equal(resolveCatalogReference(parseHostReference('studio:plugin:clock', names)!, clash).status, 'resolved')

let agentsCreated = 0
const services = {
  workspaceRegistry: { list: () => workspaces },
  pluginManager: { listPlugins: async () => [{ entryId: 'host-clock', moduleName: '@example/clock', enabled: true, config: { privateKey: 'never-export' } }] },
  agentPresets: { compositionInventory: async () => [{ id: 'standard', rows: [{ entryId: 'scoped-clock', moduleName: '@example/clock', enabled: true }] }] },
  agents: { create: () => { agentsCreated += 1 } },
}
const ctx = { get: (name: string) => services[name as keyof typeof services] } as unknown as Context
const reply = await listReferenceCatalog(ctx, { limit: 1 })
assert.equal(reply.truncated, true)
assert.equal(JSON.stringify(reply).includes('never-export'), false)
assert.equal(agentsCreated, 0)
assert.equal((await listReferenceCatalog(ctx, { query: '产品', kind: 'workspace' })).plugins instanceof Array, true)
const controller = new AbortController(); controller.abort()
await assert.rejects(listReferenceCatalog(ctx, {}, controller.signal))

const config = { host: 'legacy.example', port: 50000, peerName: 'legacy', peers: { studio: { host: 'studio.example', port: 50001, maxPermission: 1 } }, defaultPeer: 'studio' }
assert.equal(configuredDefaultPeer(config), 'studio')
assert.equal(defaultEndpoint(config).host, 'studio.example')
assert.equal(configuredPeers(config).legacy?.maxPermission, 3)
assert.throws(() => configuredDefaultPeer({ ...config, defaultPeer: 'missing' }))
assert.equal(defaultEndpoint({ peers: { studio: { port: 5 } } }).port, 5)
const tool = createReferenceTool({ peers: () => names, list: async () => ({ workspaces, plugins: [plugin] }) })
assert.equal(tool.name, 'remote_references')

// Real Cordis registrations: peer resources coexist with the original file and
// optional local workspace providers; selected paths are canonical and pinned.
class Agents extends Service { constructor(c: Context) { super(c, 'agents') } list() { return [] } get() { return undefined } }
class WorkingDirectory extends Service { constructor(c: Context) { super(c, 'workingDirectory') } async ensure() { return process.cwd() } }
class Fs extends Service {
  readonly supportsRemotePaths = true
  constructor(c: Context) { super(c, 'fs') }
  remotePeerNames() { return names }
  remoteDefaultPeerName() { return 'studio' }
  async resolve(path: string) { return { targetKey: path, displayPath: path } }
  async listDir() { return [{ name: 'a.txt', type: 'file' }] }
  async stat() { return { type: 'directory' } }
}
const root = new Context()
await root.plugin(Agents); await root.plugin(WorkingDirectory); await root.plugin(Fs)
root.provide('dshRemoteReferences', { list: async (_peer: string, args: Record<string, unknown>) => args.resolve === true
  ? { available: true, status: 'resolved', path: workspaceChildPath('C:/projects/product', String(args.relative ?? '')), kind: 'directory' }
  : { available: true, workspaces, plugins: [plugin] } })
root.provide('workspaceReferences', { match: () => 'hint', list: async () => [{ path: 'C:/local/project', kind: 'directory' }] })
await root.plugin(RemoteFileReferenceService, {})
const provider = root.get('fileReferences')!
const signal = new AbortController().signal
const agent = { ctx: {}, session: { header: { cwd: process.cwd() } } } as never
const hints = await provider.list(agent, 'studio:产', signal)
assert(hints.some(row => row.path === 'studio:/C:/projects/product'))
assert(hints.some(row => row.path === 'studio:plugin:@example/clock'))
const children = await provider.list(agent, 'studio:产品/docs/', signal)
assert.equal(children[0]?.path, 'studio:/C:/projects/product/docs/a.txt')
assert((await provider.list(agent, 'unmatched-local', signal)).some(row => row.path === 'C:/local/project'))
await root.fiber.dispose()
console.log('ALL PASS: host references, named workspaces, ambiguity, traversal, bounded discovery, no sessions and live peer configuration')
