/** Write staged build evidence from actual local artifacts; does not install, connect or execute plugins. */
import { readFileSync, writeFileSync, statSync } from 'node:fs'
import { resolve, relative } from 'node:path'
import { createHash } from 'node:crypto'
import { importedPackages, validateRuntimePackage } from './release-validation.mjs'
const root = resolve(import.meta.dirname, '..')
const exact = process.env.DSH_BUILD_ROOT
if (!exact || JSON.parse(readFileSync(resolve(exact, 'package.json'), 'utf8')).version !== '0.2.2-rc.1') throw new Error('DSH_BUILD_ROOT must name the exact release checkout')
const sha = path => createHash('sha256').update(readFileSync(path)).digest('hex')
const hash = path => ({ path: relative(root, path).replaceAll('\\', '/'), bytes: statSync(path).size, sha256: sha(path) })
const entries = ['client', 'server', 'link', 'protocol', 'peer-fs', 'file-reference', 'mesh']
const files = entries.map(entry => {
  const path = resolve(root, 'lib', `${entry}.js`)
  const imports = importedPackages(readFileSync(path, 'utf8'))
  return { ...hash(path), staticPackages: [...imports.staticPackages].sort(), dynamicPackages: [...imports.dynamicPackages].sort() }
})
const output = { metadataVersion: 1, ...validateRuntimePackage(root), build: { node: process.version, executable: process.execPath,
  sourceRoot: exact, sourceVersion: '0.2.2-rc.1', sourceCommit: '66491b05e3f05ad35bcdd4f6cd7ed26041d9e3db',
  esbuild: '0.28.1', fsAliasSourceRoot: process.env.DSH_FS_ALIAS_SOURCE_ROOT ?? null,
  nativeExternal: ['chokidar', 'koffi'], sharedIdentityExternal: '@deepseek-ai/* except inline fs-local and fs-sandbox in peer-fs only',
}, files, inputs: ['package.json', 'tools/build.mjs', 'src/server.ts', 'src/client.ts', 'src/reply-codec.ts', 'src/agent-delivery.ts', 'src/message-traces.ts'].map(path => hash(resolve(root, path))) }
writeFileSync(resolve(root, 'docs/ARTIFACTS-0.5.2.json'), JSON.stringify(output, null, 2) + '\n')
console.log(JSON.stringify({ artifactMetadata: 'docs/ARTIFACTS-0.5.2.json', peerFs: files.find(file => file.path === 'lib/peer-fs.js') }, null, 2))
