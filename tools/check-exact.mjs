/** Read-only check of this package against the exact DSH source types, without installing or emitting. */
import { readFileSync, readdirSync } from 'node:fs'
import { resolve, relative } from 'node:path'
import { pathToFileURL } from 'node:url'
const root = process.env.DSH_SOURCE_ROOT
if (!root || JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).version !== '0.2.2-rc.1') throw new Error('DSH_SOURCE_ROOT must be DSH 0.2.2-rc.1')
const own = resolve(import.meta.dirname, '..')
const ts = (await import(pathToFileURL(resolve(root, 'node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/lib/typescript.js')))).default
const upstream = ts.readConfigFile(resolve(root, 'tsconfig.base.json'), path => readFileSync(path, 'utf8')).config
const store = resolve(root, 'node_modules/.pnpm')
const paths = Object.fromEntries(Object.entries(upstream.compilerOptions.paths).map(([name, targets]) => [name, targets.map(target => resolve(root, target))]))
for (const name of ['zod']) {
  const dirs = readdirSync(store).filter(entry => entry.startsWith(`${name}@`))
  if (dirs.length !== 1) throw new Error(`Expected one ${name} version in exact source dependency store`)
  paths[name] = [resolve(store, dirs[0], 'node_modules', name)]
}
// Match the exact root manifest/lockfile Node type selection, not an arbitrary transitive version.
const nodeTypes = readdirSync(store).find(entry => entry === '@types+node@22.20.1')
if (!nodeTypes) throw new Error('Exact Node types are not present')
const program = ts.createProgram({ rootNames: readdirSync(resolve(own, 'src')).filter(file => file.endsWith('.ts')).map(file => resolve(own, 'src', file)), options: {
  target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler,
  lib: ['lib.esnext.d.ts'], noEmit: true, strict: true, skipLibCheck: true, noUncheckedIndexedAccess: true, allowImportingTsExtensions: true,
  esModuleInterop: true, erasableSyntaxOnly: true, paths,
  typeRoots: [resolve(store, nodeTypes, 'node_modules/@types')], types: ['node'],
} })
const all = ts.getPreEmitDiagnostics(program)
const local = all.filter(diagnostic => !diagnostic.file || !relative(own, diagnostic.file.fileName).startsWith('..'))
for (const diagnostic of local) {
  const pos = diagnostic.file && diagnostic.start !== undefined ? diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start) : undefined
  console.error(`${diagnostic.file ? relative(own, diagnostic.file.fileName) : 'options'}${pos ? `:${pos.line + 1}:${pos.character + 1}` : ''} TS${diagnostic.code}: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n')}`)
}
console.log(`Exact source typecheck: ${local.length} local diagnostics; ${all.length - local.length} dependency diagnostics (not suppressed by changes to upstream)`)
process.exitCode = local.length ? 1 : 0
