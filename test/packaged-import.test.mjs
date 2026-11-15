/** Isolated package imports with ONLY declared peers, no live plugin/profile. */
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, cpSync, symlinkSync, realpathSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve, join, dirname } from 'node:path'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { validateRuntimePackage } from '../tools/release-validation.mjs'
const source = resolve(import.meta.dirname, '..'), require = createRequire(resolve(source, 'package.json'))
const temp = mkdtempSync(join(tmpdir(), 'dshr-pack-import-'))
try {
  const target = join(temp, 'package'); mkdirSync(target)
  for (const entry of ['package.json', 'lib', 'client.js', 'cordis.patch.yml', 'icon.svg', 'locale']) cpSync(join(source, entry), join(target, entry), { recursive: true })
  const manifest = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8'))
  const { staticPackages } = (await import('../tools/release-validation.mjs')).importedPackages(readFileSync(join(target, 'lib/client.js'), 'utf8'))
  assert.ok(staticPackages.has('@deepseek-ai/cosmokit'))
  const runtimePeers = new Set()
  for (const entry of ['client', 'server', 'mesh', 'peer-fs', 'file-reference', 'link', 'protocol']) {
    const imports = (await import('../tools/release-validation.mjs')).importedPackages(readFileSync(join(target, 'lib', `${entry}.js`), 'utf8'))
    for (const dependency of imports.staticPackages) runtimePeers.add(dependency)
  }
  for (const dependency of runtimePeers) {
    assert.ok(manifest.peerDependencies[dependency])
    const destination = join(target, 'node_modules', ...dependency.split('/'))
    mkdirSync(dirname(destination), { recursive: true })
    // This fixtures dependency visibility, not an installation. Runtime peers
    // stay outside this package and are never copied, patched or executed as plugins.
    let packageDir = dirname(realpathSync(require.resolve(dependency)))
    while (!(existsSync(join(packageDir, 'package.json')) && JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8')).name === dependency)) {
      const parent = dirname(packageDir)
      assert.notEqual(parent, packageDir, `Cannot locate runtime peer ${dependency}`)
      packageDir = parent
    }
    symlinkSync(packageDir, destination, 'junction')
  }
  assert.equal(validateRuntimePackage(target).runtimeFiles, 7)
  for (const entry of ['client', 'server', 'mesh', 'peer-fs', 'file-reference', 'link', 'protocol']) {
    const module = await import(pathToFileURL(join(target, 'lib', `${entry}.js`)).href)
    assert.ok(Object.keys(module).length > 0)
  }
  console.log('ALL PASS: seven isolated runtime imports with declared peer visibility; no apply, network, key generation or profile installation')
} finally {
  assert.ok(temp.startsWith(join(tmpdir(), 'dshr-pack-import-')))
  rmSync(temp, { recursive: true, force: true })
}
