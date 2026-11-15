/** Build a checksumed runtime-only staging tree; never reads deployment keys. */
import { mkdirSync, readFileSync, copyFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs'
import { resolve, relative, join, dirname, isAbsolute } from 'node:path'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { validateRuntimePackage } from './release-validation.mjs'
const root = resolve(import.meta.dirname, '..')
const output = process.argv[2]
if (!output) throw new Error('Pass a new absolute staging directory')
if (!isAbsolute(output)) throw new Error('Staging directory must be absolute')
validateRuntimePackage(root)
const out = resolve(output)
if (existsSync(out)) throw new Error('Staging directory must not already exist')
const tree = join(out, 'package')
mkdirSync(tree, { recursive: true })
const files = ['package.json', 'client.js', 'cordis.patch.yml', 'icon.svg', 'README.md', 'LICENSE', 'docs/SECURITY.md', 'docs/MULTI-HOST.md', 'docs/MESH.md', 'docs/GUIDE.md', 'docs/DEPLOY-PEER.md', 'docs/MESSAGES-0.5.2.md', 'tools/gen-keys.py']
for (const name of ['client', 'server', 'link', 'protocol', 'peer-fs', 'file-reference', 'mesh']) files.push(`lib/${name}.js`)
for (const name of readdirSync(join(root, 'docs/images'))) files.push(`docs/images/${name}`)
// Generated from lib/peer-fs.js by tools/build.mjs; shipped for direct file:/// alias users.
files.push('lib/peer-fs-0.5.2.js')
for (const dir of ['locale', 'locale/server', 'locale/mesh']) for (const name of readdirSync(join(root, dir))) if (name.endsWith('.json')) files.push(`${dir}/${name}`)
const manifest = { version: JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version, files: [] }
for (const name of files.sort()) {
  const source = resolve(root, name), target = resolve(tree, name)
  if (relative(tree, target).startsWith('..')) throw new Error('unsafe archive path')
  const bytes = readFileSync(source)
  mkdirSync(dirname(target), { recursive: true }); copyFileSync(source, target)
  manifest.files.push({ path: name, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') })
}
validateRuntimePackage(tree)
const manifestFile = join(out, 'release-manifest.json')
writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx' })
const archive = join(out, `dsh-remote-${manifest.version}.tgz`)
const packed = spawnSync('tar', ['-czf', archive, '-C', out, 'package'], { stdio: 'inherit', windowsHide: true })
if (packed.status !== 0) throw new Error('tar failed')
console.log(JSON.stringify({ archive, manifest: manifestFile, files: manifest.files.length, sha256: createHash('sha256').update(readFileSync(archive)).digest('hex') }, null, 2))
