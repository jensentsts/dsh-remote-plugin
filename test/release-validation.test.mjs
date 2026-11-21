import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { validateDeclaredImports, validateRuntimePackage, importedPackages } from '../tools/release-validation.mjs'
const source = 'import { isVolatile } from "@deepseek-ai/cosmokit";\nconst kit = await import("@deepseek-ai/dsh-subagent");\nimport { readFile } from "node:fs";'
assert.throws(() => validateDeclaredImports({ peerDependencies: {} }, source), /undeclared.*cosmokit/)
const manifest = { peerDependencies: { '@deepseek-ai/cosmokit': '^1.8.5', '@deepseek-ai/dsh-subagent': '^0.2.2-rc.1' }, peerDependenciesMeta: { '@deepseek-ai/dsh-subagent': { optional: true } } }
assert.doesNotThrow(() => validateDeclaredImports(manifest, source))
assert.throws(() => validateDeclaredImports({ ...manifest, peerDependenciesMeta: { '@deepseek-ai/cosmokit': { optional: true } } }, source), /static.*optional/)
assert.doesNotThrow(() => validateDeclaredImports({ ...manifest, peerDependenciesMeta: { '@deepseek-ai/cosmokit': { optional: true } }, dshRemoteHostPeers: ['@deepseek-ai/cosmokit'], dsh: { bundle: { patch: './cordis.patch.yml' } }, engines: { dsh: '>=0.2.2-rc.1 <0.3.0' } }, source))
assert.throws(() => validateDeclaredImports({ peerDependencies: { '@deepseek-ai/cosmokit': '^1.8.5' } }, source), /undeclared.*dsh-subagent/)
assert.deepEqual([...importedPackages('export { foo } from "@scope/pkg/subpath";').staticPackages], ['@scope/pkg'])
assert.equal(validateRuntimePackage(resolve(import.meta.dirname, '..')).runtimeFiles, 8)
console.log('ALL PASS: emitted runtime dependencies, optional-peer safety and exported package closure')
