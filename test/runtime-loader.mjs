/** Test-only exact-release resolver/transpiler. Never loads live installed/profile packages or writes outputs. */
import { registerHooks } from 'node:module'
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { resolve, extname, dirname, relative } from 'node:path'
import { pathToFileURL, fileURLToPath } from 'node:url'
const root = process.env.DSH_SOURCE_ROOT
if (!root) throw new Error('DSH_SOURCE_ROOT must point to the exact DSH 0.2.2-rc.1 checkout')
if (JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')).version !== '0.2.2-rc.1') throw new Error('Refusing a non-exact DSH checkout')
const ts = (await import(pathToFileURL(resolve(root, 'node_modules/.pnpm/typescript@6.0.3/node_modules/typescript/lib/typescript.js')))).default
const config = ts.readConfigFile(resolve(root, 'tsconfig.base.json'), path => readFileSync(path, 'utf8')).config
const paths = Object.entries(config.compilerOptions.paths).sort(([a], [b]) => b.length - a.length)
const yaml = await import(pathToFileURL(resolve(root, 'node_modules/.pnpm/js-yaml@4.3.2/node_modules/js-yaml/dist/js-yaml.mjs')))
const lockfile = yaml.load(readFileSync(resolve(root, 'pnpm-lock.yaml'), 'utf8'))
const importers = lockfile.importers
function selectedVersion(name, importer) {
  let current = importer?.startsWith('file:') ? dirname(fileURLToPath(importer)) : root
  while (true) {
    const key = relative(root, current).replaceAll('\\', '/') || '.'
    const medium = /^node_modules\/\.pnpm\/([^/]+)\/node_modules\//u.exec(key)?.[1]
    if (medium) {
      const split = medium.startsWith('@') ? medium.indexOf('@', 1) : medium.indexOf('@')
      if (split > 0) {
        const packageKey = `${medium.slice(0, split).replace('+', '/')}@${medium.slice(split + 1)}`
        const snapshot = lockfile.snapshots?.[packageKey]
        const selected = snapshot?.dependencies?.[name] ?? snapshot?.optionalDependencies?.[name]
        if (typeof selected === 'string' && /^\d/u.test(selected)) return selected.split('(')[0]
      }
    }
    const row = importers[key]
    const dependency = row?.dependencies?.[name] ?? row?.devDependencies?.[name] ?? row?.optionalDependencies?.[name]
    if (typeof dependency?.version === 'string' && /^\d/u.test(dependency.version)) return dependency.version.split('(')[0]
    if (current === root || dirname(current) === current) break
    current = dirname(current)
  }
  // Bundled filesystem imports originate in this package rather than upstream;
  // its exact peers declare the versions inherited from the inline source.
  const manifest = JSON.parse(readFileSync(resolve(import.meta.dirname, '../package.json'), 'utf8'))
  const declared = manifest.peerDependencies?.[name] ?? manifest.dependencies?.[name]
  return typeof declared === 'string' && /^\d[^~^*<>| ]*$/u.test(declared) ? declared : undefined
}
registerHooks({
  resolve(specifier, context, nextResolve) {
    for (const [pattern, targets] of paths) {
      const star = pattern.indexOf('*')
      const match = star === -1 ? specifier === pattern : specifier.startsWith(pattern.slice(0, star)) && specifier.endsWith(pattern.slice(star + 1))
      if (!match) continue
      const middle = star === -1 ? '' : specifier.slice(star, specifier.length - (pattern.length - star - 1))
      for (const target of targets) {
        let absolute = resolve(root, target.replace('*', middle))
        if (existsSync(absolute) && statSync(absolute).isDirectory()) absolute = resolve(absolute, 'index.ts')
        if (existsSync(absolute)) return nextResolve(pathToFileURL(absolute).href, context)
      }
    }
    if (!specifier.startsWith('.') && !specifier.includes(':') && !specifier.startsWith('/')) {
      const parts = specifier.split('/')
      const packageName = specifier.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0]
      const suffix = parts.slice(specifier.startsWith('@') ? 2 : 1).join('/')
      const store = resolve(root, 'node_modules/.pnpm')
      const version = selectedVersion(packageName, context.parentURL)
      const prefix = packageName.replace('/', '+') + '@'
      const candidates = readdirSync(store).filter(name => name.startsWith(prefix) && (!version || name === prefix + version || name.startsWith(prefix + version + '(')))
      if (candidates.length > 1) {
        const fromExact = resolve(root, 'node_modules', packageName)
        if (existsSync(fromExact)) return nextResolve(specifier, { ...context, parentURL: pathToFileURL(resolve(root, 'package.json')).href })
        throw new Error(`Ambiguous exact-release test dependency ${specifier}: ${candidates.join(', ')}`)
      }
      if (candidates.length === 1) {
        const packageDir = resolve(store, candidates[0], 'node_modules', packageName)
        const manifest = JSON.parse(readFileSync(resolve(packageDir, 'package.json'), 'utf8'))
        let target = suffix || manifest.main || manifest.module || 'index.js'
        if (manifest.exports) {
          let exported = manifest.exports[suffix ? `./${suffix}` : '.'] ?? (!suffix ? manifest.exports : undefined)
          while (exported && typeof exported === 'object') exported = exported.import ?? exported.node ?? exported.default
          if (typeof exported === 'string') target = exported
        }
        const absolute = resolve(packageDir, target)
        return nextResolve(context.conditions?.includes('require') ? absolute : pathToFileURL(absolute).href, context)
      }
      if (specifier.startsWith('@deepseek-ai/')) throw new Error(`No exact-release source mapping for ${specifier}`)
    }
    return nextResolve(specifier, context)
  },
  load(url, context, nextLoad) {
    if (url.startsWith('file:') && ['.ts', '.tsx'].includes(extname(fileURLToPath(url)))) {
      const source = readFileSync(fileURLToPath(url), 'utf8')
      const output = ts.transpileModule(source, { fileName: fileURLToPath(url), compilerOptions: {
        target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX,
        esModuleInterop: true, experimentalDecorators: false,
      } })
      return { format: 'module', source: output.outputText, shortCircuit: true }
    }
    return nextLoad(url, context)
  },
})
