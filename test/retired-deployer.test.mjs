import assert from 'node:assert/strict'
import { apply } from '../../dsh-remote-deployer/index.js'
let definition
apply({ tools: { register(tool) { definition = tool } } })
assert.ok(definition)
await assert.rejects(definition.execute({ action: 'start' }), /retired/)
for (const action of ['status', 'preflight']) {
  const status = await definition.execute({ action })
  assert.equal(status.phase, 'retired')
  assert.equal(status.mutationAllowed, false)
}
console.log('ALL PASS: retired updater cannot start, schedule timers, install, remove, or write state')
