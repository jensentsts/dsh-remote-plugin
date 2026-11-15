/** Pure Hub assertions: no keys, profiles, sockets, external network or RPC. */
import assert from 'node:assert/strict'
import { RelayHub, RELAY_MAX_BLOCK_BYTES } from '../src/relay-hub.ts'
import type { RelayOwner, RelayHubLimits, RelayOperation } from '../src/relay-hub.ts'

let passed = 0
async function check(name: string, fn: () => Promise<void> | void) { await fn(); passed++; console.log(`ok ${name}`) }
const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
const block = (text = 'opaque DSHR2 bytes') => Buffer.from(text).toString('base64')
function fixture(limits: RelayHubLimits = {}, now?: () => number) {
  const policies = new Map<string, string[]>()
  const revoked = new Set<string>()
  const operations: Array<{ name: string, op: RelayOperation }> = []
  const hub = new RelayHub({ limits, now, authorize(owner, op) {
    operations.push({ name: owner.name, op })
    if (revoked.has(owner.principal)) throw new Error('private profile details must not be forwarded')
    return { targets: policies.get(owner.principal) ?? [] }
  } })
  function node(name: string, principal = `key-${name}`) {
    const events: Record<string, unknown>[] = []
    let delivery: (event: Record<string, unknown>) => Promise<void> = async () => {}
    const session = { async send(value: unknown) {
      const event = value as Record<string, unknown>
      events.push(event)
      await delivery(event)
    } }
    const owner: RelayOwner = { session, principal, name, multi: true }
    return { owner, events, delivery(fn: typeof delivery) { delivery = fn }, register() { return hub.register(owner) },
      offers() { return events.filter(event => event.kind === 'relay.offer') },
      data() { return events.filter(event => event.kind === 'relay.data') },
      closed() { return events.filter(event => event.kind === 'relay.closed') } }
  }
  function pair(a: ReturnType<typeof node>, b: ReturnType<typeof node>) {
    policies.set(a.owner.principal, [...new Set([...(policies.get(a.owner.principal) ?? []), b.owner.name])])
    policies.set(b.owner.principal, [...new Set([...(policies.get(b.owner.principal) ?? []), a.owner.name])])
  }
  async function open(a: ReturnType<typeof node>, b: ReturnType<typeof node>) {
    const pending = hub.open(a.owner, { target: b.owner.name })
    const offer = b.offers().at(-1)!
    assert.ok(offer)
    await hub.accept(b.owner, { tunnelId: offer.tunnelId })
    return (await pending).tunnelId
  }
  return { hub, node, pair, open, policies, revoked, operations }
}

await check('open offers opaque identity, waits for exact target acceptance, and routes both directions once', async () => {
  const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b)
  try {
    assert.deepEqual(a.register(), { nodeId: 'alpha' }); b.register()
    let opened = false
    const pending = f.hub.open(a.owner, { target: 'beta', from: 'forged', name: 'forged' }).then(result => { opened = true; return result })
    assert.equal(opened, false)
    const offer = b.offers()[0]!
    assert.deepEqual(Object.keys(offer).sort(), ['from', 'kind', 'tunnelId'])
    assert.equal(offer.from, 'alpha'); assert.match(String(offer.tunnelId), /^[0-9a-f-]{36}$/u)
    await assert.rejects(f.hub.accept(a.owner, { tunnelId: offer.tunnelId }), /offered target/)
    assert.equal(opened, false)
    assert.deepEqual(await f.hub.accept(b.owner, { tunnelId: offer.tunnelId }), { accepted: true })
    const { tunnelId } = await pending
    await assert.rejects(f.hub.accept(b.owner, { tunnelId }), /accept once/)
    assert.deepEqual(await f.hub.write(a.owner, { tunnelId, seq: 1, dataB64: block() }), { written: true })
    await f.hub.write(b.owner, { tunnelId, seq: 1, dataB64: block('reply') })
    assert.deepEqual(b.data(), [{ kind: 'relay.data', tunnelId, seq: 1, dataB64: block() }])
    assert.deepEqual(a.data(), [{ kind: 'relay.data', tunnelId, seq: 1, dataB64: block('reply') }])
    assert.deepEqual(await f.hub.close(a.owner, { tunnelId, reason: 'untrusted reason' }), { closed: true })
    assert.equal(b.closed().at(-1)?.reason, 'closed by endpoint')
    assert.deepEqual(await f.hub.close(a.owner, { tunnelId }), { closed: false })
    assert.ok(f.operations.some(call => call.op === 'relay.write'))
  } finally { f.hub.dispose() }
})

await check('canonical 48 KiB chunks, safe per-direction sequence and no replay fail closed', async () => {
  for (const dataB64 of ['', 'YQ=', 'YR==', 'YQ==\n', '!!!!', 'YQ===', 'YQ__', Buffer.alloc(RELAY_MAX_BLOCK_BYTES + 1).toString('base64')]) {
    const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
    try {
      const tunnelId = await f.open(a, b)
      await assert.rejects(f.hub.write(a.owner, { tunnelId, seq: 1, dataB64 }), /base64/)
      assert.equal(b.data().length, 0)
      assert.equal((f.hub.status(a.owner).tunnels as unknown[]).length, 0)
    } finally { f.hub.dispose() }
  }
  for (const invalid of [0, -1, 1.5, '1', Number.NaN, Number.MAX_SAFE_INTEGER + 1, 3]) {
    const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
    try {
      const tunnelId = await f.open(a, b)
      await assert.rejects(f.hub.write(a.owner, { tunnelId, seq: invalid, dataB64: block() }), /sequence/)
      assert.equal(b.data().length, 0)
    } finally { f.hub.dispose() }
  }
  const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
  try {
    const tunnelId = await f.open(a, b)
    await f.hub.write(a.owner, { tunnelId, seq: 1, dataB64: Buffer.alloc(RELAY_MAX_BLOCK_BYTES).toString('base64') })
    await f.hub.write(b.owner, { tunnelId, seq: 1, dataB64: block() })
    await assert.rejects(f.hub.write(a.owner, { tunnelId, seq: 1, dataB64: block() }), /sequence/)
    assert.equal(b.data().length, 1)
    await assert.rejects(f.hub.write(a.owner, { tunnelId, seq: 2, dataB64: block() }), /not owned/)
  } finally { f.hub.dispose() }
})

await check('registrations and tunnels bind both proven identity and exact Session; no live takeover', async () => {
  const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); const stranger = f.node('stranger')
  f.pair(a, b); a.register(); b.register(); stranger.register()
  try {
    assert.throws(() => f.hub.register({ ...a.owner, multi: false }), /multi-controller/)
    assert.throws(() => f.hub.register({ ...a.owner, name: 'other' }), /cannot change/)
    const sameKey = f.node('alpha', a.owner.principal)
    assert.throws(() => sameKey.register(), /taken over/)
    const sameName = f.node('Alpha', 'new-key')
    assert.throws(() => sameName.register(), /taken over/)
    const tunnelId = await f.open(a, b)
    await assert.rejects(f.hub.write(sameKey.owner, { tunnelId, seq: 1, dataB64: block() }), /not registered/)
    await assert.rejects(f.hub.write({ ...a.owner, principal: 'forged' }, { tunnelId, seq: 1, dataB64: block() }), /not registered/)
    await assert.rejects(f.hub.accept(stranger.owner, { tunnelId }), /not owned/)
    await assert.rejects(f.hub.close(stranger.owner, { tunnelId }), /not owned/)
    assert.deepEqual(f.hub.status(stranger.owner), { nodeId: 'stranger', targets: [], tunnels: [] })
    f.hub.detach(a.owner.session)
    sameKey.register()
    f.hub.detach(a.owner.session) // stale socket finalizer cannot remove replacement
    assert.equal(f.hub.status(sameKey.owner).nodeId, 'alpha')
    await assert.rejects(f.hub.write(sameKey.owner, { tunnelId, seq: 1, dataB64: block() }), /not owned/)
    assert.equal(b.data().length, 0)
    assert.throws(() => f.hub.status(a.owner), /not registered/)
  } finally { f.hub.dispose() }
})

await check('both exact bounded target allowlists required; route removal and malformed policy clean up', async () => {
  const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); a.register(); b.register()
  try {
    f.policies.set(a.owner.principal, ['beta'])
    await assert.rejects(f.hub.open(a.owner, { target: 'beta' }), /both exact/)
    assert.equal(b.offers().length, 0)
    f.pair(a, b)
    await assert.rejects(f.hub.open(a.owner, { target: 'Beta' }), /unavailable/)
    for (const target of ['*', 'a', 'constructor', '../beta', 'x'.repeat(129)]) await assert.rejects(f.hub.open(a.owner, { target }), /target node/)
    const tunnelId = await f.open(a, b)
    f.policies.set(b.owner.principal, [])
    await assert.rejects(f.hub.write(a.owner, { tunnelId, seq: 1, dataB64: block() }), /both exact/)
    assert.equal(b.data().length, 0)
    assert.equal((f.hub.status(a.owner).tunnels as unknown[]).length, 0)
    f.policies.set(a.owner.principal, ['*'])
    assert.throws(() => f.hub.status(a.owner), /not registered|authorization denied/)
    assert.equal((f.hub.status(b.owner).targets as unknown[]).length, 0)
  } finally { f.hub.dispose() }
  for (const targets of [Array.from({ length: 65 }, (_, i) => `node-${i}`), ['beta', 'Beta'], null, ['']]) {
    const test = new RelayHub({ authorize: () => ({ targets } as never) })
    try { assert.throws(() => test.register(f.node('extra').owner), /authorization denied/) } finally { test.dispose() }
  }
  const long = fixture(); const owner = long.node('a'.repeat(128))
  try { assert.equal(owner.register().nodeId.length, 128) } finally { long.hub.dispose() }
})

await check('revocation and detach close only related opening/open tunnels and never trust a reconnect', async () => {
  const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); const c = f.node('charlie'); const d = f.node('delta')
  f.pair(a, b); f.pair(c, d); for (const n of [a, b, c, d]) n.register()
  try {
    const ab = await f.open(a, b); const cd = await f.open(c, d)
    const pending = f.hub.open(a.owner, { target: 'beta' })
    const rejected = assert.rejects(pending, /authorization revoked/)
    f.hub.revoke(b.owner.principal); await rejected
    assert.ok(a.closed().some(event => event.tunnelId === ab))
    assert.equal(c.closed().length, 0); assert.equal(d.closed().length, 0)
    await f.hub.write(c.owner, { tunnelId: cd, seq: 1, dataB64: block() })
    assert.equal(d.data().length, 1)
    f.revoked.add(d.owner.principal)
    await assert.rejects(f.hub.write(c.owner, { tunnelId: cd, seq: 2, dataB64: block() }), /authorization denied/)
    assert.equal(d.data().length, 1)
    assert.ok(c.closed().every(event => !JSON.stringify(event).includes('private profile')))
    assert.throws(() => f.hub.status(d.owner), /not registered/)
    const replacement = f.node('beta', b.owner.principal); replacement.register()
    await assert.rejects(f.hub.write(replacement.owner, { tunnelId: ab, seq: 1, dataB64: block() }), /not owned/)
  } finally { f.hub.dispose() }
})

await check('15 second accept and 10 minute idle bounds release opening and open resources', async () => {
  let now = 0
  const f = fixture({}, () => now); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
  try {
    const pending = f.hub.open(a.owner, { target: 'beta' })
    const rejected = assert.rejects(pending, /accept deadline/)
    now = 15_000; f.hub.status(a.owner); await rejected
    await assert.rejects(f.hub.accept(b.owner, { tunnelId: b.offers()[0]!.tunnelId }), /not owned/)
    const tunnelId = await f.open(a, b)
    now += 599_999
    await f.hub.write(a.owner, { tunnelId, seq: 1, dataB64: block() })
    now += 599_999
    assert.equal((f.hub.status(a.owner).tunnels as unknown[]).length, 1)
    now += 1
    assert.equal((f.hub.status(a.owner).tunnels as unknown[]).length, 0)
    assert.equal(b.closed().at(-1)?.reason, 'idle deadline exceeded')
  } finally { f.hub.dispose() }
  const timed = fixture({ openTimeoutMs: 10 }); const c = timed.node('charlie'); const d = timed.node('delta'); timed.pair(c, d); c.register(); d.register()
  try { const rejected = assert.rejects(timed.hub.open(c.owner, { target: 'delta' }), /accept deadline/); await delay(30); await rejected }
  finally { timed.hub.dispose() }
})

await check('finite global/principal/node budgets count opening tunnels and pending writes honor backpressure', async () => {
  const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
  const waits: Promise<{ tunnelId: string }>[] = []
  try {
    for (let i = 0; i < 16; i++) { const wait = f.hub.open(a.owner, { target: 'beta' }); void wait.catch(() => {}); waits.push(wait) }
    await assert.rejects(f.hub.open(a.owner, { target: 'beta' }), /budget/)
    assert.equal(b.offers().length, 16)
    f.hub.revoke(a.owner.principal); await Promise.all(waits.map(wait => assert.rejects(wait)))
  } finally { f.hub.dispose() }
  const global = fixture(); const pending: Promise<unknown>[] = []
  try {
    for (let i = 0; i < 9; i++) {
      const x = global.node(`source-${i}`); const y = global.node(`target-${i}`); global.pair(x, y); x.register(); y.register()
      for (let j = 0; j < (i < 8 ? 16 : 1); j++) {
        const wait = global.hub.open(x.owner, { target: y.owner.name })
        if (i === 8) await assert.rejects(wait, /budget/)
        else { void wait.catch(() => {}); pending.push(wait) }
      }
    }
    global.hub.dispose(); await Promise.all(pending.map(wait => assert.rejects(wait)))
  } finally { global.hub.dispose() }
  const small = fixture({ maxNodes: 2, maxPendingBytes: 200, sendTimeoutMs: 30 })
  const x = small.node('source'); const y = small.node('target'); small.pair(x, y); x.register(); y.register()
  try {
    assert.throws(() => small.node('third').register(), /budget/)
    const tunnelId = await small.open(x, y)
    let release!: () => void
    y.delivery(event => event.kind === 'relay.data' ? new Promise<void>(resolve => { release = resolve }) : Promise.resolve())
    let settled = false
    const write = small.hub.write(x.owner, { tunnelId, seq: 1, dataB64: block() }).finally(() => { settled = true })
    await Promise.resolve(); assert.equal(settled, false)
    await assert.rejects(small.hub.write(x.owner, { tunnelId, seq: 2, dataB64: Buffer.alloc(150).toString('base64') }), /budget/)
    await assert.rejects(write, /write failed/)
    assert.equal(y.data().length, 1)
    release(); await Promise.resolve()
  } finally { small.hub.dispose() }
  const reserved = fixture({ maxPendingSends: 1 }); const r = reserved.node('origin'); const s = reserved.node('receiver')
  reserved.pair(r, s); r.register(); s.register()
  try {
    const tunnelId = await reserved.open(r, s)
    let release!: () => void
    s.delivery(event => event.kind === 'relay.data' ? new Promise<void>(resolve => { release = resolve }) : Promise.resolve())
    const writing = reserved.hub.write(r.owner, { tunnelId, seq: 1, dataB64: block() })
    const rejected = assert.rejects(writing, /closed by endpoint/)
    await reserved.hub.close(r.owner, { tunnelId }); await rejected
    // Cancelling the caller cannot free bytes still retained by Session.send.
    await assert.rejects(reserved.hub.open(r.owner, { target: 'receiver' }), /offer delivery failed/)
    assert.equal(s.offers().length, 1)
    release(); await Promise.resolve(); await Promise.resolve()
    s.delivery(async () => {})
    const fresh = await reserved.open(r, s)
    await reserved.hub.write(r.owner, { tunnelId: fresh, seq: 1, dataB64: block('not replayed') })
    assert.equal(s.data().length, 2)
  } finally { reserved.hub.dispose() }
})

await check('send failures/timeouts and permanent idempotent disposal settle without unhandled rejection', async () => {
  const unhandled: unknown[] = []
  const listener = (error: unknown) => { unhandled.push(error) }
  process.on('unhandledRejection', listener)
  try {
    for (const failure of ['throw', 'reject', 'hang']) {
      const f = fixture({ sendTimeoutMs: 10, openTimeoutMs: 30 }); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
      try {
        b.delivery(() => { if (failure === 'throw') throw new Error('private delivery details'); if (failure === 'reject') return Promise.reject(new Error('private delivery details')); return new Promise(() => {}) })
        const rejected = assert.rejects(f.hub.open(a.owner, { target: 'beta' }), /offer delivery failed/)
        await delay(20); await rejected
        assert.equal(b.offers().length, 1)
        assert.equal((f.hub.status(a.owner).tunnels as unknown[]).length, 0)
      } finally { f.hub.dispose() }
    }
    const f = fixture(); const a = f.node('alpha'); const b = f.node('beta'); f.pair(a, b); a.register(); b.register()
    const pending = f.hub.open(a.owner, { target: 'beta' }); const rejected = assert.rejects(pending, /disposed/)
    f.hub.dispose(); f.hub.dispose(); f.hub.detach(a.owner.session); f.hub.revoke(a.owner.principal)
    await rejected
    assert.throws(() => a.register(), /disposed/)
    assert.throws(() => f.hub.status(a.owner), /disposed/)
    await assert.rejects(f.hub.open(a.owner, { target: 'beta' }), /disposed/)
    await assert.rejects(f.hub.accept(b.owner, { tunnelId: b.offers()[0]!.tunnelId }), /disposed/)
    await delay(20); assert.deepEqual(unhandled, [])
  } finally { process.off('unhandledRejection', listener) }
})

console.log(`\n${passed} relay hub security groups passed`)
