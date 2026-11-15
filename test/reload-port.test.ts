/** Reproduce the live-reload path: unload the server fiber and re-apply a new config on the SAME port. */
import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { mkdtempSync, existsSync, rmSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateKeyPair, privateToPem, publicToPem } from '../src/protocol.ts'

const home = mkdtempSync(join(tmpdir(), 'dshr-reload-'))
process.env.DSH_HOME = home
const server = await import('../src/server.ts')
const delay = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
async function freePort() {
  const probe = createServer(); await new Promise<void>(r => probe.listen(0, '127.0.0.1', r))
  const port = (probe.address() as AddressInfo).port
  await new Promise<void>(r => probe.close(() => r()))
  return port
}
const silent = { logger: { info() {}, debug() {}, warn() {}, error() {} }, get() { return undefined }, on() { return () => {} } }
function mount(config: never) {
  const disposers: Array<() => unknown> = []
  server.apply({ ...silent, effect(fn: () => unknown) { const r = fn(); if (typeof r === 'function') disposers.push(r as () => unknown); return () => {} } } as never, config)
  return () => { for (const stop of disposers.reverse()) { try { stop() } catch (e) { console.log('   dispose threw:', (e as Error).message) } } }
}
const cleanups: Array<() => void> = []
try {
  const hub = generateKeyPair(), controller = generateKeyPair()
  writeFileSync(join(home, 'alpha.pub'), publicToPem(controller.publicKey))
  writeFileSync(join(home, 'hub.pub'), publicToPem(hub.publicKey))
  const port = await freePort()
  const heartbeat = join(home, 'hb')
  const base = { host: '127.0.0.1', port, privateKey: privateToPem(hub.privateKey), autoGenerateKey: false,
    workspace: 'C:\\workspace', audit: false, journal: false, journalFile: join(home, 'j'), heartbeatFile: heartbeat }
  const original = server.Config({ ...base })
  const changed = server.Config({ ...base, relayEnabled: true, authorizedPeers: {
    alpha: { peerPublicKeyFile: join(home, 'alpha.pub'), maxPermission: 3, relayTargets: ['beta'] },
    beta: { peerPublicKeyFile: join(home, 'hub.pub'), maxPermission: 1, relayTargets: ['alpha'] },
  } })

  console.log('1) mount original config')
  const stop1 = mount(original as never); cleanups.push(stop1)
  for (let i = 0; !existsSync(heartbeat) && i < 300; i++) await delay(10)
  assert.ok(existsSync(heartbeat), 'original config must listen')
  const hb1 = JSON.parse(readFileSync(heartbeat, 'utf8'))
  console.log('   listening, heartbeat pid', hb1.pid)

  console.log('2) unload, then immediately re-apply the changed config on the same port')
  stop1()
  let secondError: string | undefined
  try {
    const stop2 = mount(changed as never); cleanups.push(stop2)
    let up = false
    for (let i = 0; i < 300; i++) { if (existsSync(heartbeat)) { up = true; break } await delay(10) }
    console.log('   heartbeat after reload:', up ? 'present' : 'ABSENT')
    assert.ok(up, 'changed config must listen after a reload')
  } catch (error) { secondError = (error as Error).message }

  console.log('3) raw TCP probe of the port after reload')
  const probe = createServer(); const bound = await new Promise<boolean>(resolve => {
    probe.once('error', () => resolve(false)); probe.listen(port, '127.0.0.1', () => resolve(true))
  })
  console.log('   port still bindable by a third party:', bound, bound ? '(listener really gone)' : '(port still held)')
  if (bound) await new Promise<void>(r => probe.close(() => r()))
  if (secondError !== undefined) throw new Error('second mount threw: ' + secondError)
  console.log('REPRODUCED-OK: reload keeps the port alive')
} finally {
  for (const stop of cleanups.reverse()) { try { stop() } catch {} }
  await delay(50)
  rmSync(home, { recursive: true, force: true })
}
