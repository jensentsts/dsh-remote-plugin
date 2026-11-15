/** Runtime-package checks that cannot be masked by a linked development tree. */
import { readFileSync, readdirSync, realpathSync, statSync } from 'node:fs'
import { resolve, relative, isAbsolute } from 'node:path'

export function importedPackages(source) {
  const staticPackages = new Set(), dynamicPackages = new Set()
  const packageOf = specifier => specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]
  const bare = specifier => !specifier.startsWith('.') && !specifier.startsWith('/') && !specifier.includes(':')
  // esbuild emits these ESM forms. The closure check is intentionally on the
  // emitted runtime files, not TS imports that can be erased at build time.
  for (const match of source.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?:[^;\n]*?\sfrom\s*)?["']([^"']+)["']/gu)) {
    if (bare(match[1])) staticPackages.add(packageOf(match[1]))
  }
  for (const match of source.matchAll(/\bimport\s*\(\s*["']([^"']+)["']\s*\)/gu)) {
    if (bare(match[1])) dynamicPackages.add(packageOf(match[1]))
  }
  return { staticPackages, dynamicPackages }
}

export function validateDeclaredImports(manifest, source, label = 'runtime') {
  const declared = { ...manifest.dependencies, ...manifest.peerDependencies }
  const { staticPackages, dynamicPackages } = importedPackages(source)
  for (const dependency of new Set([...staticPackages, ...dynamicPackages])) {
    if (!Object.hasOwn(declared, dependency)) throw new Error(`${label}: undeclared external dependency ${dependency}`)
    if (staticPackages.has(dependency) && manifest.peerDependenciesMeta?.[dependency]?.optional === true) {
      throw new Error(`${label}: static dependency ${dependency} cannot be an optional peer`)
    }
  }
  return { staticPackages: [...staticPackages].sort(), dynamicPackages: [...dynamicPackages].sort() }
}

export function validateRuntimePackage(directory) {
  const root = realpathSync(directory)
  const manifest = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'))
  if (manifest.name !== 'dsh-remote' || !manifest.dsh?.bundle?.patch) throw new Error('Expected a dsh-remote bundle')
  const inside = path => {
    const actual = realpathSync(resolve(root, path)), child = relative(root, actual)
    if (child.startsWith('..') || isAbsolute(child)) throw new Error('Runtime export leaves package')
    if (!statSync(actual).isFile()) throw new Error('Runtime export is not a file')
  }
  for (const path of Object.values(manifest.exports ?? {})) {
    if (typeof path !== 'string') throw new Error('Unsupported export descriptor')
    if (!path.includes('*')) inside(path)
  }
  inside(manifest.dsh.bundle.patch)
  const files = readdirSync(resolve(root, 'lib')).filter(name => name.endsWith('.js'))
  for (const name of files) validateDeclaredImports(manifest, readFileSync(resolve(root, 'lib', name), 'utf8'), `lib/${name}`)
  return { name: manifest.name, version: manifest.version, runtimeFiles: files.length }
}
