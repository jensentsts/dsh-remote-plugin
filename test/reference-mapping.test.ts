import assert from 'node:assert/strict'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { mapRemoteReferences } from '../src/reference-mapping.ts'
import { createReferenceTool, resolveRemoteReference } from '../src/reference-tool.ts'
import { listReferenceCatalog } from '../src/reference-catalog.ts'
import { parseHostReference } from '../src/reference-query.ts'
import type { ReferenceDeps } from '../src/reference-tool.ts'
import type { UserMessage } from '@deepseek-ai/dsh-llm'
import type { Context } from '@deepseek-ai/cordis'

const signal = new AbortController().signal
const workspace = { id: 'ws-one', title: 'Research', path: 'C:/projects/research' }
let requests: Record<string, unknown>[] = []
const deps: ReferenceDeps = {
  peers: () => ['studio'],
  async list(_peer, args) {
    requests.push(args)
    if (args.resolve === true) {
      if (String(args.relative).includes('escape')) throw new Error('Workspace reference escapes its registered directory')
      return { available: true, status: 'resolved', path: `C:/projects/research${args.relative ? `/${String(args.relative)}` : ''}`, kind: 'directory' }
    }
    return { available: true, workspaces: [workspace], plugins: [{ id: 'clock', name: '@example/clock', enabled: true }] }
  },
}
const message = (text: string): UserMessage => createUserMessage({ source: { kind: 'user' }, content: [{ type: 'text', text }] })
const original = message('@studio:Research/docs/')
const decision = { kind: 'enter' as const, startsRequestSeries: true as const, messages: [{ ...original, content: [...original.content, { type: 'text' as const, text: '@studio:injected' }] }] }
const mapped = await mapRemoteReferences(deps, { messages: [original], signal }, decision)
assert.equal(mapped.kind, 'enter')
if (mapped.kind !== 'enter') throw new Error('unexpected reject')
assert.equal(mapped.startsRequestSeries, true)
assert.equal(mapped.messages[0]?.content.length, 3)
assert.equal(requests.some(row => row.query === 'injected'), false)
assert.equal(requests.some(row => row.resolve === true), true)
assert.equal(mapped.messages[0]?.id, original.id)

requests = []
const relay = { ...message('@studio:Research'), source: { kind: 'qq' } } as unknown as UserMessage
assert.equal(await mapRemoteReferences(deps, { messages: [relay], signal }, { kind: 'enter', messages: [relay] }).then(row => row.kind === 'enter' ? row.messages[0]?.content.length : 0), 1)
assert.equal(requests.length, 0)
const empty = { ...message(''), content: [{ type: 'text' as const, text: '' }, { type: 'text' as const, text: '@studio:Research' }] }
await mapRemoteReferences(deps, { messages: [empty], signal }, { kind: 'enter', messages: [empty] })
const large = message('@studio:Research/escape')
const refused = await mapRemoteReferences(deps, { messages: [large], signal }, { kind: 'enter', messages: [large] })
assert.equal(JSON.stringify(refused).includes('"status":"resolved"'), false)
assert.equal(JSON.stringify(refused).includes('unavailable'), true)
requests = []
const many = { ...message(''), content: Array.from({ length: 50 }, (_, n) => ({ type: 'text' as const, text: `@studio:plugin:item${n}` })) }
await mapRemoteReferences(deps, { messages: [many], signal }, { kind: 'enter', messages: [many] })
assert.equal(requests.length, 20)
const cut = message(`@studio:${'x'.repeat(100_000)}`)
requests = []
assert.equal(await mapRemoteReferences(deps, { messages: [cut], signal }, { kind: 'enter', messages: [cut] }).then(row => row.kind === 'enter' ? row.messages[0]?.content.length : 0), 1)
assert.equal(requests.length, 0)

const tool = createReferenceTool(deps)
const scoped = await tool.execute({ query: '@example/clock', peer: 'studio' }, {} as never) as unknown as { status: string; kind: string }
assert.equal(scoped.kind, 'plugin'); assert.equal(scoped.status, 'resolved')
assert.equal((await tool.execute({ query: 'studio:plugin:clock', peer: 'studio' }, {} as never) as unknown as { status: string }).status, 'resolved')
await assert.rejects(Promise.resolve().then(() => tool.execute({ query: 'studio:clock', peer: 'laptop' }, {} as never)))

// Half-typed mentions name nothing: they must not be resolved or injected.
for (const partial of ['@studio:/', '@studio:', '@studio:workspace:', '@studio:plugin:', '@studio:/   ']) {
  requests = []
  const typed = message(`写到一半 ${partial}`)
  const kept = await mapRemoteReferences(deps, { messages: [typed], signal }, { kind: 'enter', messages: [typed] })
  assert.equal(kept.kind === 'enter' ? kept.messages[0]?.content.length : -1, 1, `metadata injected for ${partial}`)
  assert.equal(requests.length, 0, `resolved a half-typed mention ${partial}`)
}
// A path mention already carries its host and path: no metadata is pasted into
// the user's message, and nothing is resolved over the wire for it.
requests = []
const plainPath = message('看看 @studio:/C:/projects/research/docs')
const keptPath = await mapRemoteReferences(deps, { messages: [plainPath], signal }, { kind: 'enter', messages: [plainPath] })
assert.equal(keptPath.kind === 'enter' ? keptPath.messages[0]?.content.length : -1, 1)
assert.equal(requests.length, 0)
// A name-based reference still announces where it resolved to.
requests = []
const named = message('@studio:Research/docs/')
const keptNamed = await mapRemoteReferences(deps, { messages: [named], signal }, { kind: 'enter', messages: [named] })
assert.equal(keptNamed.kind === 'enter' ? keptNamed.messages[0]?.content.length : 0, 2)
assert.equal(requests.length > 0, true)

// The owning filesystem, not a concatenation, decides symlink containment.
const services: Record<string, unknown> = {
  workspaceRegistry: { list: () => [workspace] },
  fs: {
    async resolve(path: string) { return { targetKey: path.includes('/escape') ? 'C:/private/outside' : path, displayPath: path } },
    contains(root: { targetKey: string }, target: { targetKey: string }) { return target.targetKey === root.targetKey || target.targetKey.startsWith(`${root.targetKey}/`) },
    async stat() { return { type: 'directory' } },
  },
}
const ctx = { get: (name: string) => services[name] } as unknown as Context
await assert.rejects(listReferenceCatalog(ctx, { kind: 'workspace', query: 'ws-one', relative: 'escape/secret.txt', resolve: true }, signal), /escapes/)
const verified = await resolveRemoteReference({ peers: () => ['studio'], list: (_peer, args, abort) => listReferenceCatalog(ctx, args, abort) }, parseHostReference('studio:Research/docs', ['studio'])!, signal)
assert.equal(verified.status, 'resolved')
assert.equal(verified.path, '/rmt/studio/C:/projects/research/docs')
console.log('ALL PASS: reference admission, shared budgets, scoped plugin syntax and host-side canonical containment')
