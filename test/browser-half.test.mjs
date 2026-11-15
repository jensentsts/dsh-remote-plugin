/**
 * Self-test for the BROWSER half (`client.js`), which otherwise has no coverage.
 *
 * The half is plain JavaScript served as-is, so a mistake in it shows up only as
 * a broken Plugins page. This harness loads it the way the web runtime does
 * (`window.__ModuleLoader__.load({ id, factory })`), calls `factory(require)`
 * with a minimal React, and then actually RENDERS the registered components
 * against fake forms — including the secret "set / not set" path that depends on
 * the settings describe mirror rather than on the form snapshot.
 *
 * Run with node (no tsx needed):
 *   node E:/path/to/dsh-remote/test/browser-half.test.mjs
 */


let failures = 0
function check(label, ok, detail) {
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${ok || detail === undefined ? '' : `  <- ${detail}`}`)
}

// ── the runtime stubs the half expects to exist before it is loaded ────────
let captured
globalThis.window = { __ModuleLoader__: { load: (definition) => { captured = definition } } }
globalThis.document = {
  head: { appendChild() {} },
  getElementById: () => null,
  createElement: () => ({ id: '', textContent: '' }),
}

/** Hook state is retained only in interaction tests; this is not a visual renderer. */
let hookRuntime
const React = {
  createElement: (type, props, ...children) => ({ type, props: { ...(props ?? {}), children } }),
  useState(initial) {
    if (!hookRuntime) return [typeof initial === 'function' ? initial() : initial, () => {}]
    const runtime = hookRuntime
    const index = runtime.cursor++
    if (!Object.hasOwn(runtime.values, index)) runtime.values[index] = typeof initial === 'function' ? initial() : initial
    return [runtime.values[index], (update) => {
      const next = typeof update === 'function' ? update(runtime.values[index]) : update
      if (!Object.is(next, runtime.values[index])) { runtime.values[index] = next; runtime.dirty = true }
    }]
  },
  useEffect(effect, dependencies) {
    if (!hookRuntime) { effect(); return }
    const runtime = hookRuntime
    const index = runtime.cursor++
    const previous = runtime.effects[index]
    if (previous && dependencies?.every((part, position) => Object.is(part, previous.dependencies?.[position]))) return
    runtime.pendingEffects.push(() => {
      previous?.cleanup?.()
      runtime.effects[index] = { dependencies, cleanup: effect() }
    })
  },
  useCallback: (callback) => callback,
}
const requireStub = (id) => {
  if (id === 'react') return React
  throw new Error(`unexpected require("${id}")`)
}

await import(new URL('../client.js', import.meta.url).href)

console.log('\n== 1. module registration ==')
check('the half registers itself under its package id', captured?.id === 'dsh-remote', String(captured?.id))
check('it exposes a factory', typeof captured?.factory === 'function')

const plugin = captured.factory(requireStub)
check('inject stays soft (no hard configForms dependency)', Array.isArray(plugin.inject)
  && plugin.inject.includes('slots') && plugin.inject.includes('locale')
  && !plugin.inject.includes('configForms'), JSON.stringify(plugin.inject))

/** Apply the half against a fake context and return what it registered. */
function applyWith({ describe, describeThrows }) {
  const registrations = new Map()
  const ctx = {
    effect: (fn) => { const stop = fn(); return typeof stop === 'function' ? stop : () => {} },
    locale: { register: () => () => {}, bind: () => () => undefined, getSnapshot: () => ({ active: 'zh' }) },
    slots: {
      inject: (_name, run) => run(),
      register: (options, component) => { registrations.set(options.key, { options, component }) },
    },
    configForms: describeThrows === true
      ? { describe: () => { throw new Error('no describe face') } }
      : (describe === undefined ? undefined : { describe: () => describe }),
  }
  plugin.apply(ctx)
  return registrations
}

const lookups = { lookup: () => undefined, locale: 'zh' }

/**
 * Expand an element the way React would: call function components until host
 * elements remain. The registered entry is a dispatcher, so the real page or
 * summary body lives one level deeper than its return value.
 */
function renderDeep(element, depth = 0) {
  if (element === null || element === undefined || typeof element !== 'object') return element
  if (depth > 12) return element
  if (Array.isArray(element)) return element.map(child => renderDeep(child, depth))
  if (typeof element.type === 'function') return renderDeep(element.type(element.props), depth + 1)
  const children = element.props?.children ?? []
  return { ...element, props: { ...element.props, children: children.map(child => renderDeep(child, depth + 1)) } }
}

/** Every text node in a rendered tree, joined. */
function textOf(element) {
  if (element === null || element === undefined) return ''
  if (typeof element === 'string' || typeof element === 'number') return String(element)
  if (Array.isArray(element)) return element.map(textOf).join(' ')
  return textOf(element.props?.children ?? [])
}

/** Render one registered entry and return both the tree and its text. */
function render(entry, view, form) {
  const tree = renderDeep(entry.component({ view, form, ...lookups }))
  return { tree, text: textOf(tree) }
}

const readyForm = {
  state: {
    status: 'ready', value: { host: 'peer.example', port: 50000 }, user: {},
    revision: 1, writable: true, mode: 'host',
  },
  mutate: async () => true,
}
/** A describe face reporting one namespace's secret paths. */
const faceWith = (ns, paths) => ({
  getSnapshot: () => ({ view: { namespaces: [{ ns, secrets: paths.map(path => ({ path: Array.isArray(path) ? path : [path], set: true })) }] } }),
  subscribe: () => () => {},
  ensure: async () => {},
})

console.log('\n== 2. direct and mesh pages register under their bundle row keys ==')
{
  const registrations = applyWith({})
  check('client row key', registrations.has('dsh-remote#dsh-remote-client'))
  check('server row key', registrations.has('dsh-remote#dsh-remote-server'))
  check('mesh row key', registrations.has('dsh-remote#dsh-remote-mesh'))
  check('the row id is the settings namespace the page will be served',
    registrations.get('dsh-remote#dsh-remote-client')?.options?.key === 'dsh-remote#dsh-remote-client')
  check('locale namespace declared', registrations.get('dsh-remote#dsh-remote-client')?.options?.locale === 'dshRemoteSettings')
}

console.log('\n== 2b. the CONTROLLED half\'s page renders too ==')
{
  // The driven machine mounts the server row; its page must work without any
  // client-side fields and with its own settings namespace.
  const registrations = applyWith({
    describe: faceWith('dsh-remote-server', ['privateKey']),
  })
  const entry = registrations.get('dsh-remote#dsh-remote-server')
  const serverForm = {
    state: {
      status: 'ready',
      value: { host: '127.0.0.1', port: 11325, maxPermission: 3, audit: true, promptGuidance: true },
      user: {}, revision: 1, writable: true, mode: 'host',
    },
    mutate: async () => true,
  }
  const page = render(entry, 'page', serverForm)
  check('server page renders', page.tree?.type === 'div', String(page.tree?.type))
  check('server page lists its own fields', page.text.includes('监听地址') && page.text.includes('允许主控做的上限'), page.text.slice(0, 90))
  check('server page includes the guidance switch', page.text.includes('被驱动会话'), '')
  {
    const nodes = []
    const walk = (element) => {
      if (element === null || element === undefined || typeof element !== 'object') return
      if (Array.isArray(element)) { for (const child of element) walk(child); return }
      nodes.push(element)
      walk(element.props?.children)
    }
    walk(page.tree)
    const inputs = nodes.filter(node => node.type === 'input')
    const ids = new Set(nodes.map(node => node.props?.id).filter(Boolean))
    check('server controls are labelled and described too',
      inputs.length > 0
      && inputs.every(input => typeof input.props['aria-label'] === 'string' && input.props['aria-label'] !== '')
      && inputs.filter(input => typeof input.props['aria-describedby'] === 'string')
        .every(input => ids.has(input.props['aria-describedby'])),
      String(inputs.length))
  }
  const summary = render(entry, 'summary', serverForm)
  check('server summary shows the bind endpoint', summary.text.includes('127.0.0.1:11325'), summary.text)
  check('server secret flag comes from its own namespace', summary.text.includes('已设置'), summary.text)
}

console.log('\n== 3. rendering ==')
{
  const registrations = applyWith({})
  const entry = registrations.get('dsh-remote#dsh-remote-client')
  const page = render(entry, 'page', readyForm)
  check('page renders for a ready form', page.tree?.type === 'div', String(page.tree?.type))
  check('page lists the configured fields', page.text.includes('对端地址') && page.text.includes('会话 id 前缀'), page.text.slice(0, 80))
  check('page renders without a form', render(entry, 'page', undefined).text.includes('没有拿到配置表单'))
  check('page renders while loading', render(entry, 'page', { state: { status: 'loading' } }).text.includes('正在读取'))
  check('page renders when the namespace is unavailable', render(entry, 'page', { state: { status: 'unavailable' } }).text.includes('没有暴露'))
  check('summary renders', render(entry, 'summary', readyForm).tree !== null)
  check('summary shows the endpoint', render(entry, 'summary', readyForm).text.includes('peer.example:50000'),
    render(entry, 'summary', readyForm).text)
}

console.log('\n== 3b. the form describes itself the way DSH settings do ==')
{
  const registrations = applyWith({})
  const entry = registrations.get('dsh-remote#dsh-remote-client')
  const page = render(entry, 'page', readyForm)

  // Every element in the tree, flattened.
  const nodes = []
  const walk = (element) => {
    if (element === null || element === undefined || typeof element !== 'object') return
    if (Array.isArray(element)) { for (const child of element) walk(child); return }
    nodes.push(element)
    walk(element.props?.children)
  }
  walk(page.tree)

  const inputs = nodes.filter(node => node.type === 'input')
  check('the form has inputs', inputs.length > 0, String(inputs.length))
  check('every input is labelled', inputs.every(input => typeof input.props['aria-label'] === 'string' && input.props['aria-label'] !== ''))

  const described = inputs.filter(input => typeof input.props['aria-describedby'] === 'string')
  check('hinted fields point at their hint', described.length > 0, String(described.length))
  const ids = new Set(nodes.map(node => node.props?.id).filter(Boolean))
  check('every aria-describedby resolves to a rendered element',
    described.every(input => ids.has(input.props['aria-describedby'])),
    described.map(input => input.props['aria-describedby']).join(','))
  const hints = nodes.filter(node => node.props?.id !== undefined && String(node.props.id).startsWith('fsf-hint-'))
  check('the hint text is real content, not only a placeholder',
    hints.length > 0 && hints.every(node => String(textOf(node)).trim() !== ''), String(hints.length))
  check('and it is no longer duplicated into the placeholder',
    inputs.every(input => input.props.placeholder === undefined || String(input.props.placeholder).length === 0
      || input.props.type === 'password'),
    inputs.map(input => String(input.props.placeholder)).filter(Boolean).join('|'))

  check('the form exposes a busy state', 'aria-busy' in (page.tree.props ?? {}))
  const buttons = nodes.filter(node => node.type === 'button')
  check('the page owns a save control', buttons.length > 0 && buttons.some(button => String(textOf(button)).includes('保存')),
    buttons.map(button => textOf(button)).join('|'))
}

console.log('\n== 3c. an error is announced, a hint is not an error ==')
{
  const registrations = applyWith({})
  const entry = registrations.get('dsh-remote#dsh-remote-client')
  const nodes = []
  const walk = (element) => {
    if (element === null || element === undefined || typeof element !== 'object') return
    if (Array.isArray(element)) { for (const child of element) walk(child); return }
    nodes.push(element)
    walk(element.props?.children)
  }
  walk(render(entry, 'page', readyForm).tree)
  check('no element claims an alert while nothing failed', !nodes.some(node => node.props?.role === 'alert'))
}

console.log('\n== 4. the secret "set" flag comes from the describe mirror ==')
{
  // The form snapshot deliberately carries NO secrets, which is the shipped
  // behaviour that made this control dead.
  const form = { state: { ...readyForm.state, secrets: undefined }, mutate: async () => true }

  // Each apply replaces the module-level describe face, so render each case
  // while its own face is the active one.
  const withFace = applyWith({ describe: faceWith('dsh-remote-client', ['privateKey']) })
  const set = render(withFace.get('dsh-remote#dsh-remote-client'), 'summary', form)
  check('reports 已设置 when the mirror says the key is set', set.text.includes('已设置'), set.text)
  const pageSet = render(withFace.get('dsh-remote#dsh-remote-client'), 'page', form)
  check('the page offers Clear once the key is known to be set', pageSet.text.includes('清除'),
    `已设置=${pageSet.text.includes('已设置')} 清除=${pageSet.text.includes('清除')}`)

  const withoutFace = applyWith({})
  const unset = render(withoutFace.get('dsh-remote#dsh-remote-client'), 'summary', form)
  check('reports 未设置 when nothing says it is set', unset.text.includes('未设置'), unset.text)
  const pageUnset = render(withoutFace.get('dsh-remote#dsh-remote-client'), 'page', form)
  check('and offers no Clear when it is not set', !pageUnset.text.includes('清除'))

  const otherNs = applyWith({ describe: faceWith('someone-else', ['privateKey']) })
  const ignored = render(otherNs.get('dsh-remote#dsh-remote-client'), 'summary', form)
  check('a flag from another namespace is ignored', ignored.text.includes('未设置'), ignored.text)
}

console.log('\n== 5. a broken / absent describe face must not break the page ==')
{
  const throwing = applyWith({ describeThrows: true })
  check('apply still registers all three keys when describe() throws', throwing.size === 3, String(throwing.size))
  const entry = throwing.get('dsh-remote#dsh-remote-client')
  check('and the page still renders', render(entry, 'page', readyForm).tree !== null)

  const weird = applyWith({ describe: () => ({ getSnapshot: () => ({ view: { namespaces: 'nope' } }) }) })
  const entry2 = weird.get('dsh-remote#dsh-remote-client')
  check('a reshaped snapshot is tolerated', render(entry2, 'page', readyForm).tree !== null)
}

/** Flatten the element contract without requiring a browser or producing a preview. */
function nodesOf(tree) {
  if (!tree || typeof tree !== 'object') return []
  if (Array.isArray(tree)) return tree.flatMap(nodesOf)
  return [tree, ...nodesOf(tree.props?.children)]
}

function mount(entry, form, locale = 'zh') {
  const runtime = { values: [], effects: [], cursor: 0, dirty: false, pendingEffects: [] }
  let result
  function rerender() {
    for (let pass = 0; pass < 12; pass += 1) {
      runtime.cursor = 0; runtime.dirty = false; runtime.pendingEffects = []
      hookRuntime = runtime
      try {
        const tree = renderDeep(entry.component({ view: 'page', form, ...lookups, locale }))
        result = { tree, text: textOf(tree) }
        for (const run of runtime.pendingEffects) run()
      } finally { hookRuntime = undefined }
      if (!runtime.dirty) return result
    }
    throw new Error('settings hooks failed to settle')
  }
  const byPath = path => nodesOf(result.tree).find(node => node.props?.['data-path'] === JSON.stringify(path))
  return {
    rerender,
    get tree() { return result.tree },
    get text() { return result.text },
    nodes: () => nodesOf(result.tree),
    control(path) { return nodesOf(byPath(path)).find(node => ['input', 'select', 'textarea'].includes(node.type)) },
    named(label) { return nodesOf(result.tree).find(node => node.props?.['aria-label'] === label) },
    button(label) { return nodesOf(result.tree).find(node => node.type === 'button' && textOf(node) === label) },
    rowButton(path, label) { return nodesOf(byPath(path)).find(node => node.type === 'button' && textOf(node) === label) },
    change(node, value) {
      if (!node) throw new Error('missing control')
      node.props.onChange({ target: { value, checked: value } }); rerender()
    },
    async click(node) {
      if (!node || node.props.disabled) throw new Error(`missing or disabled button: ${textOf(node)}`)
      const task = node.props.onClick(); rerender(); await task; rerender()
    },
    dispose() { for (const effect of runtime.effects) effect?.cleanup?.() },
  }
}

function recordingForm(value, extra = {}) {
  const writes = []
  const form = {
    state: { ...readyForm.state, value, user: {}, ...extra },
    mutate: async (ops, revision) => { writes.push({ ops: structuredClone(ops), revision }); return true },
  }
  return { form, writes }
}
const clientEntry = (describe) => applyWith({ describe }).get('dsh-remote#dsh-remote-client')
const serverEntry = () => applyWith({}).get('dsh-remote#dsh-remote-server')
const meshEntry = (describe) => applyWith({ describe }).get('dsh-remote#dsh-remote-mesh')
const samplePeers = () => ({
  host: 'legacy.example.invalid', port: 46001, peerName: 'legacy', defaultPeer: 'build.eu',
  peers: {
    'build.eu': { host: 'build.example.invalid', port: 46002, maxPermission: 1, unknownFuture: { mode: 'keep' } },
    review: { host: 'review.example.invalid', port: 46003, maxPermission: 2, workspaceRoot: '/srv/example' },
  },
})

console.log('\n== 6. basic fields stay visible and advanced fields are folded ==')
{
  const { form } = recordingForm(samplePeers())
  const page = mount(clientEntry(), form); page.rerender()
  const details = page.nodes().filter(node => node.type === 'details')
  check('capabilities and advanced use native, initially closed details',
    details.some(node => textOf(node).includes('能力开关')) && details.some(node => textOf(node).includes('高级设置'))
      && details.every(node => node.props.open !== true))
  const visiblePaths = []
  function visit(node, folded = false) {
    if (!node || typeof node !== 'object') return
    if (Array.isArray(node)) { for (const child of node) visit(child, folded); return }
    const hidden = folded || (node.type === 'details' && !node.props.open)
    if (!hidden && node.props?.['data-path']) visiblePaths.push(JSON.parse(node.props['data-path']))
    visit(node.props?.children, hidden)
  }
  visit(page.tree)
  check('basic single-host address, port and keys are not behind a long advanced section',
    ['host', 'port', 'peerPublicKey', 'privateKey'].every(name => visiblePaths.some(path => path.length === 1 && path[0] === name)))
  check('advanced session and transfer parameters are not initially expanded',
    !visiblePaths.some(path => ['sessionPrefix', 'transferChunkBytes', 'capabilityTimeoutMs'].includes(path[0])))
  check('bidirectional and legacy precedence explanations are present', page.text.includes('两端分别启用 client 和 server') && page.text.includes('同名 peers 条目优先'))
  check('only requested reference spellings are advertised', page.text.includes('@主机:工作区/路径') && page.text.includes('@主机:插件') && page.text.includes('@主机:/C:/路径') && !page.text.includes('~'))
  check('rendering the page performs no mutation or network probe', !page.nodes().some(node => node.type === 'button' && /连接|探测/.test(textOf(node))))
  const controls = page.nodes().filter(node => ['input', 'select', 'textarea'].includes(node.type))
  const ids = new Set(page.nodes().map(node => node.props?.id).filter(Boolean))
  check('all controls have localized labels and valid description targets', controls.every(node => node.props['aria-label'])
    && controls.every(node => !node.props['aria-describedby'] || node.props['aria-describedby'].split(' ').every(id => ids.has(id))))
  page.dispose()
}

console.log('\n== 7. nested edits preserve unknown fields and redacted keys ==')
{
  const value = samplePeers()
  const { form, writes } = recordingForm(value)
  const page = mount(clientEntry(faceWith('dsh-remote-client', [['peers', 'build.eu', 'privateKey']])), form); page.rerender()
  page.change(page.named('编辑主机'), 'build.eu')
  check('the selected named host exposes its connection, pin, permission, root and timeout',
    ['host', 'port', 'peerPublicKey', 'privateKey', 'maxPermission', 'workspaceRoot', 'timeoutMs', 'privateKeyFile'].every(name => page.control(['peers', 'build.eu', name])))
  check('nested private key set flag is resolved without splitting dotted names',
    page.rowButton(['peers', 'build.eu', 'privateKey'], '清除') !== undefined)
  check('redacted private key starts blank', page.control(['peers', 'build.eu', 'privateKey']).props.value === '')
  page.change(page.control(['peers', 'build.eu', 'host']), 'updated.example.invalid')
  page.change(page.control(['peers', 'build.eu', 'privateKey']), '')
  await page.click(page.button('保存'))
  check('writes only the requested nested field with one revision fence', JSON.stringify(writes) === JSON.stringify([{
    ops: [{ op: 'set', path: ['peers', 'build.eu', 'host'], value: 'updated.example.invalid' }], revision: 1,
  }]), JSON.stringify(writes))
  check('redacted/unknown data were not restated or edited', value.peers['build.eu'].unknownFuture.mode === 'keep'
    && !writes[0].ops.some(op => op.path.includes('privateKey') || op.path.length < 3))
  page.dispose()
}

console.log('\n== 8. secret drafts are isolated, cleared explicitly, and revision-scoped ==')
{
  const { form, writes } = recordingForm(samplePeers())
  const describe = faceWith('dsh-remote-client', ['privateKey', ['peers', 'build.eu', 'privateKey']])
  const page = mount(clientEntry(describe), form); page.rerender()
  page.change(page.control(['privateKey']), 'fixture-legacy-secret')
  page.change(page.named('编辑主机'), 'build.eu')
  check('switching host does not copy another password draft', page.control(['peers', 'build.eu', 'privateKey']).props.value === '')
  page.change(page.control(['peers', 'build.eu', 'privateKey']), 'fixture-build-secret')
  page.change(page.named('编辑主机'), 'review')
  check('a second named host has its own empty secret input', page.control(['peers', 'review', 'privateKey']).props.value === '')
  page.change(page.named('编辑主机'), 'build.eu')
  check('returning to a host keeps only its own draft', page.control(['peers', 'build.eu', 'privateKey']).props.value === 'fixture-build-secret')
  await page.click(page.button('保存'))
  check('both explicit secrets go to their exact paths', writes[0].ops.length === 2
    && writes[0].ops.some(op => JSON.stringify(op.path) === JSON.stringify(['privateKey']) && op.value === 'fixture-legacy-secret')
    && writes[0].ops.some(op => JSON.stringify(op.path) === JSON.stringify(['peers', 'build.eu', 'privateKey']) && op.value === 'fixture-build-secret'))
  check('accepted save clears all password drafts', page.control(['peers', 'build.eu', 'privateKey']).props.value === '')
  await page.click(page.rowButton(['peers', 'build.eu', 'privateKey'], '清除'))
  await page.click(page.button('保存'))
  check('explicit clear masks an inherited inline key, not unset-to-inherit', JSON.stringify(writes[1].ops) === JSON.stringify([
    { op: 'set', path: ['peers', 'build.eu', 'privateKey'], value: '' },
  ]))
  page.change(page.control(['peers', 'build.eu', 'privateKey']), 'fixture-stale-secret')
  form.state = { ...form.state, revision: 2 }
  page.rerender()
  check('new Host revision erases stale secrets and disables Save', page.control(['peers', 'build.eu', 'privateKey']).props.value === '' && page.button('保存').props.disabled)
  page.dispose()
}

console.log('\n== 9. add, remove and default selection never replace a record ==')
{
  const { form, writes } = recordingForm(samplePeers())
  const page = mount(clientEntry(), form); page.rerender()
  for (const invalid of ['x', 'rmt', '.', '..', 'C:', 'bad/name', 'bad name', '中文', '__proto__', 'constructor', 'prototype', 'Build.EU']) {
    page.change(page.named('新主机名称'), invalid)
    await page.click(page.button('添加主机'))
    check(`rejects invalid, reserved or duplicate host name ${invalid}`, page.nodes().some(node => node.props.role === 'alert') && writes.length === 0)
  }
  page.change(page.named('新主机名称'), 'staging')
  await page.click(page.button('添加主机'))
  check('new host opens with the safe read-only ceiling', page.control(['peers', 'staging', 'maxPermission']).props.value === '1')
  check('new host key-generation control reflects its schema default before first Save', page.control(['peers', 'staging', 'autoGenerateKey']).props.checked === true)
  page.change(page.control(['peers', 'staging', 'host']), 'staging.example.invalid')
  page.change(page.control(['peers', 'staging', 'port']), '46004')
  page.change(page.named('默认主机'), 'staging')
  await page.click(page.button('保存'))
  check('add/default mutate only leaf paths and preserve legacy configuration', writes[0].ops.every(op => op.path[0] === 'defaultPeer' || op.path[0] === 'peers' && op.path[1] === 'staging' && op.path.length === 3)
    && writes[0].ops.some(op => op.path[0] === 'defaultPeer' && op.value === 'staging'), JSON.stringify(writes))
  page.dispose()
}
{
  const { form, writes } = recordingForm(samplePeers())
  const page = mount(clientEntry(), form); page.rerender(); page.change(page.named('编辑主机'), 'build.eu')
  await page.click(page.button('移除主机'))
  check('removal requires an explicit second confirmation', !page.button('保存') || page.button('保存').props.disabled)
  await page.click(page.button('取消'))
  check('cancel removal stages no write', page.button('保存').props.disabled)
  await page.click(page.button('移除主机')); await page.click(page.button('确认移除'))
  page.change(page.named('新主机名称'), 'build.eu'); await page.click(page.button('添加主机'))
  check('a staged removal cannot be recreated before Save and erase an existing redacted record', page.nodes().some(node => node.props.role === 'alert'))
  await page.click(page.button('保存'))
  check('confirmed removal unsets only the chosen record and clears a dangling default', JSON.stringify(writes[0].ops) === JSON.stringify([
    { op: 'unset', path: ['peers', 'build.eu'] }, { op: 'set', path: ['defaultPeer'], value: '' },
  ]), JSON.stringify(writes))
  page.dispose()
}
{
  const value = samplePeers()
  const { form } = recordingForm(value, { base: { peers: { 'build.eu': value.peers['build.eu'] } } })
  const page = mount(clientEntry(), form); page.rerender(); page.change(page.named('编辑主机'), 'build.eu')
  check('inherited hosts cannot be accidentally removed via unset-to-inherit', page.button('移除主机').props.disabled && page.text.includes('来自基础配置'))
  page.dispose()
}

console.log('\n== 10. numeric validation and capability controls use safe mutations ==')
{
  const { form, writes } = recordingForm(samplePeers())
  const page = mount(clientEntry(), form); page.rerender()
  for (const raw of ['', '70000', '-1', '12.5', 'not-a-number']) {
    page.change(page.control(['port']), raw)
    check(`invalid port draft ${JSON.stringify(raw)} never enables Save`, page.control(['port']).props['aria-invalid'] === true && page.button('保存').props.disabled)
  }
  page.change(page.control(['port']), '46001')
  page.change(page.control(['remoteCapabilities']), false)
  form.state.value.capabilityDeny = ['blocked_tool']
  page.change(page.control(['capabilityDeny']), 'blocked_tool\n')
  check('multiline deny-list editing preserves a typed trailing newline', page.control(['capabilityDeny']).props.value === 'blocked_tool\n')
  page.change(page.control(['capabilityDeny']), 'blocked_tool\nunsafe_*\n')
  await page.click(page.button('保存'))
  check('capability switch and deny list are independently path addressed', JSON.stringify(writes[0].ops) === JSON.stringify([
    { op: 'set', path: ['remoteCapabilities'], value: false }, { op: 'set', path: ['capabilityDeny'], value: ['blocked_tool', 'unsafe_*'] },
  ]), JSON.stringify(writes))
  check('nonvolatile toolEnabled is read-only with configuration-source guidance', page.control(['toolEnabled']).props.disabled && page.text.includes('结构字段'))
  page.dispose()
}

console.log('\n== 11. the inbound allowlist is a separate trust decision ==')
{
  const value = { host: '127.0.0.1', port: 46010, maxPermission: 2, authorizedPeers: {
    controller: { peerPublicKey: 'fixture-public-pin', maxPermission: 1, workspaceRoot: '/srv/example', unknownFuture: true },
  } }
  const { form, writes } = recordingForm(value)
  const page = mount(serverEntry(), form); page.rerender()
  check('server picks an existing authorization without hiding listener basics', page.control(['host']) && page.control(['port'])
    && page.control(['authorizedPeers', 'controller', 'peerPublicKey']))
  check('the allowlist editor does not invent a remote private key', !page.control(['authorizedPeers', 'controller', 'privateKey']))
  page.change(page.control(['authorizedPeers', 'controller', 'maxPermission']), '2')
  page.change(page.control(['authorizedPeers', 'controller', 'workspaceRoot']), '/srv/example/team')
  await page.click(page.button('保存'))
  check('existing authorization edits preserve pin and unknown fields', writes[0].ops.length === 2 && writes[0].ops.every(op => op.path.length === 3
    && op.path[0] === 'authorizedPeers' && op.path[1] === 'controller' && ['maxPermission', 'workspaceRoot'].includes(op.path[2])))
  check('nonempty allowlist precedence and lower-ceiling behavior are explained', page.text.includes('只接受表内公钥') && page.text.includes('较低者'))
  page.change(page.named('新主机名称'), 'other-controller'); await page.click(page.button('添加主机'))
  page.change(page.control(['authorizedPeers', 'other-controller', 'peerPublicKey']), 'fixture-second-public-pin')
  await page.click(page.button('保存'))
  check('new authorized peer is independent and starts read-only', writes[1].ops.some(op => op.path[0] === 'authorizedPeers' && op.path[1] === 'other-controller' && op.path[2] === 'maxPermission' && op.value === 1))
  page.dispose()
}

console.log('\n== 12. refusal, pending, read-only and discard states ==')
{
  const { form } = recordingForm(samplePeers())
  form.mutate = async () => false
  const page = mount(clientEntry(), form); page.rerender(); page.change(page.control(['host']), 'refused.example.invalid')
  await page.click(page.button('保存'))
  check('refused write is announced and retains an editable draft', page.nodes().some(node => node.props.role === 'alert') && page.text.includes('Host 拒绝'))
  await page.click(page.button('放弃修改'))
  check('discard drops the draft and error', page.button('保存').props.disabled && !page.nodes().some(node => node.props.role === 'alert'))
  page.dispose()
}
{
  const { form } = recordingForm(samplePeers(), { writable: false })
  const page = mount(clientEntry(), form); page.rerender()
  check('read-only source disables all write controls', page.nodes().filter(node => ['input', 'textarea', 'select'].includes(node.type)
    && node.props['aria-label'] !== '编辑主机').every(node => node.props.disabled) && page.button('保存').props.disabled && page.text.includes('不接受写入'))
  page.dispose()
}
{
  const { form } = recordingForm(samplePeers())
  let settle
  form.mutate = () => new Promise(resolve => { settle = resolve })
  const page = mount(clientEntry(), form); page.rerender(); page.change(page.control(['host']), 'pending.example.invalid')
  const pending = page.click(page.button('保存'))
  check('pending save announces busy and disables controls', page.tree.props['aria-busy'] === 'true' && page.control(['host']).props.disabled)
  settle(true); await pending
  check('successful settlement restores controls and announces saved', !page.tree.props['aria-busy'] && page.text.includes('已保存'))
  page.dispose()
}

console.log('\n== 13. localized summaries follow the actual default host ==')
{
  const value = samplePeers()
  const { form } = recordingForm(value)
  const entry = clientEntry(faceWith('dsh-remote-client', [['peers', 'build.eu', 'privateKey']]))
  const summary = render(entry, 'summary', form)
  check('summary uses the selected host rather than legacy endpoint', summary.text.includes('build.example.invalid:46002') && !summary.text.includes('legacy.example.invalid:46001') && summary.text.includes('已设置'))
  const dictionaries = new Map()
  plugin.apply({
    effect: effect => effect(), slots: { inject: (_key, run) => run(), register: () => {} },
    locale: { register: (_ns, values) => { for (const [locale, dictionary] of Object.entries(values)) dictionaries.set(locale, dictionary) },
      bind: () => key => dictionaries.get('en')?.[key], getSnapshot: () => ({ active: 'en' }) },
  })
  const page = mount(entry, form, 'en'); page.rerender()
  const tree = renderDeep(entry.component({ view: 'page', form, lookup: key => dictionaries.get('en')?.[key], locale: 'en' }))
  check('English labels are registered and visible through locale lookup', textOf(tree).includes('Default host') && textOf(tree).includes('Capability switches'))
  page.dispose()
}

console.log('\n== 14. transport security defaults are explicit, scoped and fail closed ==')
{
  const { form, writes } = recordingForm(samplePeers())
  const page = mount(clientEntry(), form); page.rerender()
  check('legacy top-level transport uses secure defaults without writing them',
    page.control(['allowLegacyHandshake']).props.checked === false
      && page.control(['maxSessionMs']).props.value === '3600000' && writes.length === 0)
  check('the page distinguishes a legacy pin from legacy handshake and promises no downgrade',
    page.text.includes('默认禁止旧握手') && page.text.includes('不会自动降级') && page.text.includes('不等于允许旧握手'))
  page.change(page.control(['allowLegacyHandshake']), true)
  page.change(page.control(['maxSessionMs']), '100')
  page.change(page.named('编辑主机'), 'build.eu')
  check('named peer transport defaults do not inherit another host draft', page.control(['peers', 'build.eu', 'allowLegacyHandshake']).props.checked === false
    && page.control(['peers', 'build.eu', 'maxSessionMs']).props.value === '3600000')
  for (const invalid of ['', '0', '99', '3600001', '100.5', 'Infinity']) {
    page.change(page.control(['peers', 'build.eu', 'maxSessionMs']), invalid)
    check(`rejects named-peer lifetime ${JSON.stringify(invalid)}`, page.button('保存').props.disabled
      && page.control(['peers', 'build.eu', 'maxSessionMs']).props['aria-invalid'] === true)
  }
  page.change(page.control(['peers', 'build.eu', 'maxSessionMs']), '3600000')
  page.change(page.control(['peers', 'build.eu', 'allowLegacyHandshake']), true)
  await page.click(page.button('保存'))
  check('transport changes use exact top/peer paths and one revision fence', JSON.stringify(writes) === JSON.stringify([{
    ops: [
      { op: 'set', path: ['allowLegacyHandshake'], value: true },
      { op: 'set', path: ['maxSessionMs'], value: 100 },
      { op: 'set', path: ['peers', 'build.eu', 'maxSessionMs'], value: 3600000 },
      { op: 'set', path: ['peers', 'build.eu', 'allowLegacyHandshake'], value: true },
    ], revision: 1,
  }]), JSON.stringify(writes))
  check('transport edits never restate a private key, unknown fields, or the peers map', writes[0].ops.every(op => !op.path.includes('privateKey')
    && !op.path.includes('unknownFuture') && (op.path[0] !== 'peers' || op.path.length === 3)))
  page.dispose()
}

console.log('\n== 15. network admission budgets are bounded advanced server controls ==')
{
  const limits = [
    ['maxConnections', 64, 1, 1024], ['maxPendingHandshakes', 8, 1, 128],
    ['maxConnectionsPerAddress', 16, 1, 256], ['maxHandshakesPerMinute', 120, 1, 6000],
    ['maxTrackedAddresses', 1024, 16, 65536], ['handshakeTimeoutMs', 15000, 50, 60000],
    ['maxInFlightPerPrincipal', 16, 1, 128], ['maxSessionMs', 3600000, 100, 3600000],
  ]
  const { form, writes } = recordingForm({ host: '127.0.0.1', port: 46010 })
  const page = mount(serverEntry(), form); page.rerender()
  check('server legacy handshake starts off without any mutation', page.control(['allowLegacyHandshake']).props.checked === false && writes.length === 0)
  const advanced = page.nodes().find(node => node.type === 'details' && textOf(node).includes('高级设置'))
  check('network budgets stay in initially folded Advanced settings, not basic listener rows',
    advanced && advanced.props.open !== true && nodesOf(advanced).some(node => node.props?.['data-path'] === '["maxConnections"]'))
  for (const [name, fallback, min, max] of limits) {
    const initial = page.control([name])
    check(`${name} exposes the schema default and bounds`, initial.props.value === String(fallback) && initial.props.min === min && initial.props.max === max)
    for (const invalid of ['', String(min - 1), String(max + 1), `${min}.5`]) {
      page.change(page.control([name]), invalid)
      check(`${name} blocks out-of-bound draft ${JSON.stringify(invalid)}`, page.button('保存').props.disabled && page.control([name]).props['aria-invalid'] === true)
    }
    page.change(page.control([name]), String(min))
  }
  page.change(page.control(['allowLegacyHandshake']), true)
  await page.click(page.button('保存'))
  check('one bounded network save writes only requested top-level leaves', writes.length === 1 && writes[0].revision === 1
    && writes[0].ops.length === limits.length + 1 && writes[0].ops.every(op => op.op === 'set' && op.path.length === 1)
    && limits.every(([name, , min]) => writes[0].ops.some(op => op.path[0] === name && op.value === min)), JSON.stringify(writes))
  page.dispose()
}

console.log('\n== 16. inbound policy has strict timezone and exact-operation validation ==')
{
  const value = { host: '127.0.0.1', port: 46010, authorizedPeers: {
    'control.eu': { peerPublicKey: 'fixture-policy-public-pin', maxPermission: 1, unknownFuture: { retain: true } },
  } }
  const { form, writes } = recordingForm(value)
  const page = mount(serverEntry(), form); page.rerender()
  const prefix = ['authorizedPeers', 'control.eu']
  check('inbound policy defaults are disabled=false, no expiry and an empty restriction list',
    page.control([...prefix, 'disabled']).props.checked === false && page.control([...prefix, 'validUntil']).props.value === ''
      && page.control([...prefix, 'allowedOps']).props.value === '' && writes.length === 0)
  const opsControl = page.control([...prefix, 'allowedOps'])
  const opsHint = page.nodes().find(node => node.props.id === opsControl.props['aria-describedby'])
  check('allowedOps owns an exact-op hint, not the tool mirror wildcard hint', textOf(opsHint).includes('不支持通配符')
    && textOf(opsHint).includes('不表示提权') && !textOf(opsHint).includes('尾随 *'))
  for (const invalid of [
    '2030-01-02T03:04:05', '2030-01-02', '2030-01-02T03:04:05-00:00',
    '2030-02-29T03:04:05Z', '2030-04-31T03:04:05Z', '2030-01-02T24:00:00Z',
    '2030-01-02T03:04:60Z', '2030-01-02T03:04:05+24:00', '2030-01-02T03:04:05+08:60',
    '2030-01-02T03:04:05Z ', 'tomorrow',
  ]) {
    page.change(page.control([...prefix, 'validUntil']), invalid)
    check(`rejects ambiguous or invalid expiry ${JSON.stringify(invalid)}`, page.button('保存').props.disabled
      && page.control([...prefix, 'validUntil']).props['aria-invalid'] === true)
  }
  for (const valid of ['2030-01-02T03:04:05Z', '2030-01-02T11:04:05+08:00', '2030-01-02T00:04:05-03:00', '2032-02-29T03:04:05.125Z']) {
    page.change(page.control([...prefix, 'validUntil']), valid)
    check(`accepts explicit-zone expiry ${valid}`, page.button('保存').props.disabled === false
      && !page.control([...prefix, 'validUntil']).props['aria-invalid'])
  }
  const invalidOps = ['fs.*', '*', 'FS.read', 'fs_read', 'fs-read', 'fs..read', '.read', 'fs.read.', 'fs read', 'a'.repeat(65), Array(65).fill('fs.read').join('\n')]
  for (const invalid of invalidOps) {
    page.change(page.control([...prefix, 'allowedOps']), invalid)
    check(`rejects nonexact or over-budget allowedOps ${JSON.stringify(invalid.slice(0, 72))}`, page.button('保存').props.disabled
      && page.control([...prefix, 'allowedOps']).props['aria-invalid'] === true)
  }
  page.change(page.control([...prefix, 'allowedOps']), 'fs.read\ncaps.list\nagent.prompt\n')
  check('allowedOps keeps text editing intact while staging an array', page.control([...prefix, 'allowedOps']).props.value.endsWith('\n'))
  page.change(page.control([...prefix, 'disabled']), true)
  await page.click(page.button('保存'))
  check('authorization policy saves only requested leaves, preserving pin and unknown data', JSON.stringify(writes) === JSON.stringify([{
    ops: [
      { op: 'set', path: [...prefix, 'validUntil'], value: '2032-02-29T03:04:05.125Z' },
      { op: 'set', path: [...prefix, 'allowedOps'], value: ['fs.read', 'caps.list', 'agent.prompt'] },
      { op: 'set', path: [...prefix, 'disabled'], value: true },
    ], revision: 1,
  }]), JSON.stringify(writes))
  check('unrelated authorization fields stay unchanged', value.authorizedPeers['control.eu'].peerPublicKey === 'fixture-policy-public-pin'
    && value.authorizedPeers['control.eu'].unknownFuture.retain === true)
  page.change(page.control([...prefix, 'validUntil']), '')
  page.change(page.control([...prefix, 'allowedOps']), '')
  await page.click(page.button('保存'))
  check('explicit empty expiry/list use leaf set operations, not unset-to-inherit', JSON.stringify(writes[1].ops) === JSON.stringify([
    { op: 'set', path: [...prefix, 'validUntil'], value: '' }, { op: 'set', path: [...prefix, 'allowedOps'], value: [] },
  ]))
  page.change(page.control([...prefix, 'validUntil']), '2000-01-01T00:00:00Z')
  check('an expired authorization is visibly identified, never silently renewed', page.text.includes('此授权已过期'))
  page.dispose()
}

console.log('\n== 17. readable roots are explicit paths, isolated per authorization ==')
{
  const value = { host: '127.0.0.1', port: 46010, authorizedPeers: {
    controller: { peerPublicKey: 'fixture-read-public-pin', maxPermission: 1, unknownFuture: true },
  } }
  const { form, writes } = recordingForm(value)
  const page = mount(serverEntry(), form); page.rerender()
  const nested = ['authorizedPeers', 'controller', 'readRoots']
  check('new authorization read roots default empty rather than the filesystem root', page.control(nested).props.value === '')
  const control = page.control(nested)
  const hint = page.nodes().find(node => node.props.id === control.props['aria-describedby'])
  check('read roots have their own path guidance with deny-by-default and full-level warning', textOf(hint).includes('空列表禁止权限 1/2')
    && textOf(hint).includes('权限 3 明确允许完整访问') && !textOf(hint).includes('尾随 *') && !textOf(hint).includes('精确操作'))
  for (const invalid of ['relative/root', 'C:relative', '/srv/invalid\u0000root', `/srv/${'a'.repeat(4092)}`, Array(33).fill('/srv/example').join('\n')]) {
    page.change(page.control(nested), invalid)
    check(`rejects invalid or over-budget read roots ${JSON.stringify(invalid.slice(0, 48))}`, page.button('保存').props.disabled
      && page.control(nested).props['aria-invalid'] === true)
  }
  const rootsText = '/srv/shared folder \nC:\\Example Data\\read root\n'
  page.change(page.control(nested), rootsText)
  check('read-root text keeps a literal trailing space and newline', page.control(nested).props.value === rootsText)
  page.change(page.named('编辑授权主机'), '')
  check('legacy pin has a distinct empty read-root list, not a copy of another authorization', page.control(['readRoots']).props.value === '')
  page.change(page.control(['readRoots']), '/srv/legacy-only')
  await page.click(page.button('保存'))
  check('legacy and named read roots save only their requested leaf paths', JSON.stringify(writes) === JSON.stringify([{
    ops: [
      { op: 'set', path: nested, value: ['/srv/shared folder ', 'C:\\Example Data\\read root'] },
      { op: 'set', path: ['readRoots'], value: ['/srv/legacy-only'] },
    ], revision: 1,
  }]), JSON.stringify(writes))
  check('read-root edits never restate peer keys or unknown fields', value.authorizedPeers.controller.peerPublicKey === 'fixture-read-public-pin'
    && value.authorizedPeers.controller.unknownFuture === true && writes[0].ops.every(op => op.path.at(-1) === 'readRoots'))
  page.change(page.control(['readRoots']), '')
  await page.click(page.button('保存'))
  check('empty read roots are explicitly saved as deny-all, never unset-to-inherit', JSON.stringify(writes[1].ops) === JSON.stringify([
    { op: 'set', path: ['readRoots'], value: [] },
  ]))
  page.dispose()
}

console.log('\n== 18. mesh settings keep hub trust separate, lazy and revision-fenced ==')
{
  const value = { host: '', port: 0, privateKey: 'redacted-fixture-must-not-render', unknownFuture: { retain: true } }
  const { form, writes } = recordingForm(value)
  const entry = meshEntry(faceWith('dsh-remote-mesh', ['privateKey']))
  const page = mount(entry, form); page.rerender()
  const names = ['host', 'port', 'privateKey', 'privateKeyFile', 'autoGenerateKey', 'peerPublicKey', 'peerPublicKeyFile',
    'timeoutMs', 'maxSessionMs', 'allowLegacyHandshake', 'acceptInbound', 'targetPort', 'autoReconnect', 'reconnectMinMs', 'reconnectMaxMs']
  check('mesh row has its flat field contract without client peer or authorization editors', names.every(name => page.control([name]))
    && !page.named('编辑主机') && !page.named('编辑授权主机') && !page.named('新主机名称'))
  check('mesh starts disconnected, with generation, inbound access and legacy handshake disabled', page.control(['host']).props.value === ''
    && page.control(['port']).props.value === '0' && page.control(['autoGenerateKey']).props.checked === false
    && page.control(['acceptInbound']).props.checked === false && page.control(['allowLegacyHandshake']).props.checked === false
    && page.control(['autoReconnect']).props.checked === true && writes.length === 0)
  check('mesh explains one public FRP port, loopback targets, compatible phone agents and explicit trust', page.text.includes('FRP 公网单端口')
    && page.text.includes('127.0.0.1') && page.text.includes('手机也需要运行兼容的接入 agent') && page.text.includes('不等于自动信任'))
  check('hub and target pins are distinct and both directions need an explicit pair ACL', page.text.includes('只认证设备↔中心这一层')
    && page.text.includes('不能替换成中心公钥') && page.text.includes('互相包含对方名称') && page.text.includes('空列表拒绝全部'))
  check('mesh promises save-only connection rebuilds, no replay and no keystroke probing', page.text.includes('保存会关闭旧隧道')
    && page.text.includes('不会重放操作') && page.text.includes('本页输入不会探测')
    && !page.nodes().some(node => node.type === 'button' && /连接|探测|生成/.test(textOf(node))))
  const controls = page.nodes().filter(node => ['input', 'select', 'textarea'].includes(node.type))
  const ids = new Set(page.nodes().map(node => node.props.id).filter(Boolean))
  check('mesh controls retain accessible labels and valid description targets', controls.every(node => node.props['aria-label'])
    && controls.every(node => !node.props['aria-describedby'] || node.props['aria-describedby'].split(' ').every(id => ids.has(id))))
  check('mesh private key remains redacted and has its own namespace flag', page.control(['privateKey']).props.value === ''
    && !page.text.includes('redacted-fixture') && page.rowButton(['privateKey'], '清除')
    && render(entry, 'summary', form).text.includes('已设置'))
  for (const [name, fallback, min, max] of [
    ['port', 0, 0, 65535], ['timeoutMs', 15000, 1, 600000], ['maxSessionMs', 3600000, 100, 3600000],
    ['targetPort', 11325, 1, 65535], ['reconnectMinMs', 1000, 100, 60000], ['reconnectMaxMs', 30000, 100, 60000],
  ]) {
    check(`mesh ${name} matches the declared default and bounds`, page.control([name]).props.value === String(fallback)
      && page.control([name]).props.min === min && page.control([name]).props.max === max)
    for (const invalid of ['', String(min - 1), String(max + 1), `${min}.5`]) {
      page.change(page.control([name]), invalid)
      check(`mesh ${name} rejects ${JSON.stringify(invalid)}`, page.button('保存').props.disabled
        && page.control([name]).props['aria-invalid'] === true)
    }
    page.change(page.control([name]), String(fallback))
  }
  await page.click(page.button('放弃修改'))
  page.change(page.control(['host']), 'hub.example.invalid')
  page.change(page.control(['port']), '46020')
  page.change(page.control(['peerPublicKey']), 'fixture-hub-public-pin')
  page.change(page.control(['privateKey']), '')
  check('typing mesh fields and blank secret stages no writes', writes.length === 0)
  await page.click(page.button('保存'))
  check('mesh save mutates only requested leaves behind one revision fence', JSON.stringify(writes) === JSON.stringify([{
    ops: [
      { op: 'set', path: ['host'], value: 'hub.example.invalid' }, { op: 'set', path: ['port'], value: 46020 },
      { op: 'set', path: ['peerPublicKey'], value: 'fixture-hub-public-pin' },
    ], revision: 1,
  }]), JSON.stringify(writes))
  check('mesh save never reconstructs redacted secrets or unknown fields', value.unknownFuture.retain === true
    && writes[0].ops.every(op => !op.path.includes('privateKey') && !op.path.includes('unknownFuture')))
  await page.click(page.rowButton(['privateKey'], '清除')); await page.click(page.button('保存'))
  check('mesh explicit secret Clear writes an empty leaf, never unset-to-inherit', JSON.stringify(writes[1].ops) === JSON.stringify([
    { op: 'set', path: ['privateKey'], value: '' },
  ]))
  page.change(page.control(['privateKey']), 'fixture-stale-mesh-secret')
  form.state = { ...form.state, revision: 2 }; page.rerender()
  check('mesh revision changes erase secret drafts and disable Save', page.control(['privateKey']).props.value === '' && page.button('保存').props.disabled)
  page.dispose()
  const wrongNs = meshEntry(faceWith('dsh-remote-client', ['privateKey']))
  check('a client secret flag never authorizes mesh secret Clear', !render(wrongNs, 'page', form).text.includes('清除'))
}

console.log('\n== 19. hub forwarding requires an explicit exact pair allowlist ==')
{
  const value = { host: '127.0.0.1', port: 11325, authorizedPeers: {
    'control.eu': { peerPublicKey: 'fixture-pair-public-pin', maxPermission: 1, unknownFuture: true },
    target: { peerPublicKey: 'fixture-target-public-pin', maxPermission: 1, relayTargets: [] },
  } }
  const { form, writes } = recordingForm(value)
  const page = mount(serverEntry(), form); page.rerender()
  const path = ['authorizedPeers', 'control.eu', 'relayTargets']
  check('hub forwarding is false and each authorization target list is empty by default', page.control(['relayEnabled']).props.checked === false
    && page.control(path).props.value === '' && writes.length === 0)
  const hint = page.nodes().find(node => node.props.id === page.control(path).props['aria-describedby'])
  check('relay ACL hint says mutual explicit pair, empty-deny and no wildcard, not tool-name globbing', textOf(hint).includes('互相包含对方名称')
    && textOf(hint).includes('空列表拒绝全部') && textOf(hint).includes('不支持通配符') && !textOf(hint).includes('尾随 *'))
  for (const invalid of ['*', 'target.*', 'x', 'rmt', '.', '..', '__proto__', 'Constructor', 'prototype', 'bad/name', ' target ', ' ', '中文', 'a'.repeat(129), Array(65).fill('target').join('\n')]) {
    page.change(page.control(path), invalid)
    check(`rejects invalid relay ACL ${JSON.stringify(invalid.slice(0, 42))}`, page.button('保存').props.disabled
      && page.control(path).props['aria-invalid'] === true)
  }
  page.change(page.control(path), 'target\n' + 'a'.repeat(128) + '\n')
  check('relay ACL accepts exact dotted/ASCII names up to 128 and preserves the typed newline', page.control(path).props.value.endsWith('\n')
    && page.control(path).props['aria-invalid'] === undefined)
  page.change(page.control(['relayEnabled']), true)
  page.change(page.named('编辑授权主机'), 'target')
  check('editing one direction never grants the other direction automatically', page.control(['authorizedPeers', 'target', 'relayTargets']).props.value === '')
  page.change(page.control(['authorizedPeers', 'target', 'relayTargets']), 'control.eu')
  await page.click(page.button('保存'))
  check('hub flag and both ACL directions use independent leaf operations', JSON.stringify(writes) === JSON.stringify([{
    ops: [
      { op: 'set', path, value: ['target', 'a'.repeat(128)] }, { op: 'set', path: ['relayEnabled'], value: true },
      { op: 'set', path: ['authorizedPeers', 'target', 'relayTargets'], value: ['control.eu'] },
    ], revision: 1,
  }]), JSON.stringify(writes))
  check('relay edits preserve target pins and future fields', value.authorizedPeers['control.eu'].peerPublicKey === 'fixture-pair-public-pin'
    && value.authorizedPeers['control.eu'].unknownFuture === true && writes[0].ops.every(op => !op.path.includes('peerPublicKey')))
  page.change(page.control(['authorizedPeers', 'target', 'relayTargets']), ''); await page.click(page.button('保存'))
  check('empty target ACL explicitly sets deny-all rather than restoring inherited grants', JSON.stringify(writes[1].ops) === JSON.stringify([
    { op: 'set', path: ['authorizedPeers', 'target', 'relayTargets'], value: [] },
  ]))
  page.change(page.named('编辑授权主机'), '')
  check('the legacy single-pin path cannot invent a named hub relay allowlist', !page.control(['relayTargets']))
  page.dispose()
}

console.log('\n== 20. routed clients pin the target and never imply direct fallback ==')
{
  const value = samplePeers()
  value.peerPublicKey = 'fixture-legacy-target-pin'
  value.peers['build.eu'].peerPublicKey = 'fixture-build-target-pin'
  const { form, writes } = recordingForm(value)
  const page = mount(clientEntry(), form); page.rerender()
  check('legacy direct mode starts with an empty relayTarget', page.control(['relayTarget']).props.value === '')
  for (const invalid of ['*', 'target.*', 'x', 'rmt', '__proto__', 'constructor', 'prototype', 'bad/name', ' target ', 'a'.repeat(129)]) {
    page.change(page.control(['relayTarget']), invalid)
    check(`rejects invalid routed target ${JSON.stringify(invalid.slice(0, 36))}`, page.button('保存').props.disabled
      && page.control(['relayTarget']).props['aria-invalid'] === true)
  }
  page.change(page.control(['relayTarget']), 'legacy-target')
  page.change(page.named('编辑主机'), 'build.eu')
  check('named routed target does not inherit a legacy routing draft', page.control(['peers', 'build.eu', 'relayTarget']).props.value === '')
  page.change(page.control(['peers', 'build.eu', 'relayTarget']), 'target.eu')
  check('routed target guidance distinguishes target pin, hub pin and target server trust', page.text.includes('不会回退到 host/port')
    && page.text.includes('必须是目标设备公钥，不是中心公钥') && page.text.includes('server 也必须独立授权'))
  await page.click(page.button('保存'))
  check('both routed target writes stay leaf-only without copying target pins', JSON.stringify(writes) === JSON.stringify([{
    ops: [
      { op: 'set', path: ['relayTarget'], value: 'legacy-target' },
      { op: 'set', path: ['peers', 'build.eu', 'relayTarget'], value: 'target.eu' },
    ], revision: 1,
  }]), JSON.stringify(writes))
  check('editing routes preserves both existing target public-key pins', value.peerPublicKey === 'fixture-legacy-target-pin'
    && value.peers['build.eu'].peerPublicKey === 'fixture-build-target-pin')
  page.dispose()
  const routedValue = { ...value, peers: { ...value.peers, 'build.eu': { ...value.peers['build.eu'], relayTarget: 'target.eu' } } }
  const summary = render(clientEntry(), 'summary', recordingForm(routedValue).form)
  check('summary advertises only the routed target, never an unused direct fallback address', summary.text.includes('中心转发 → target.eu')
    && !summary.text.includes('build.example.invalid:46002'))
  const routed = mount(clientEntry(), recordingForm(routedValue).form); routed.rerender(); routed.change(routed.named('编辑主机'), 'build.eu')
  routed.change(routed.control(['peers', 'build.eu', 'relayTarget']), '')
  check('an explicit empty route remains valid and returns to direct mode only by user edit', routed.control(['peers', 'build.eu', 'relayTarget']).props['aria-invalid'] === undefined)
  routed.dispose()
  const routeOnly = render(clientEntry(), 'summary', recordingForm({ relayTarget: 'target.eu', peerName: 'routed-only' }).form)
  check('a relay-only legacy host is still declared without a direct host or port', routeOnly.text.includes('routed-only') && routeOnly.text.includes('target.eu'))
  const dictionaries = new Map()
  const registrations = new Map()
  plugin.apply({
    effect: effect => effect(), slots: { inject: (_key, run) => run(), register: (options, component) => registrations.set(options.key, { options, component }) },
    locale: { register: (_ns, values) => { for (const [locale, dictionary] of Object.entries(values)) dictionaries.set(locale, dictionary) },
      bind: () => key => dictionaries.get('en')?.[key], getSnapshot: () => ({ active: 'en' }) },
  })
  const englishPage = key => textOf(renderDeep(registrations.get(key).component({ view: 'page', form: readyForm,
    lookup: name => dictionaries.get('en')?.[name], locale: 'en' })))
  check('mesh and routed-client safety copy have English locale coverage', englishPage('dsh-remote#dsh-remote-mesh').includes('Pinned hub public key')
    && englishPage('dsh-remote#dsh-remote-mesh').includes('Connecting never establishes trust automatically')
    && englishPage('dsh-remote#dsh-remote-client').includes('never falls back to host/port'))
}

console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`}`)
process.exitCode = failures === 0 ? 0 : 1
