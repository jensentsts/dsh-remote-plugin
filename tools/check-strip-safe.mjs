#!/usr/bin/env node
/**
 * Refuse to ship TypeScript the controlled machine cannot load.
 *
 * The peer mounts this plugin as a `file://` row and its DSH strips types in
 * Node's **strip-only** mode (no `--experimental-transform-types`). Syntax that
 * cannot be erased — parameter properties, `enum`, `namespace`, `import =` — is
 * transformed away locally by esbuild, so it works here and **fails to load
 * there**. That asymmetry cost a deploy: the peer refused `reuse.ts` with
 * `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` on a constructor parameter property, after
 * the files had already been copied into place.
 *
 * `erasableSyntaxOnly` in `tsconfig.json` catches the same thing at typecheck
 * time. This script is the tsconfig-free twin, so the *peer's own* node can be
 * asked "can you load this?" before anything is restarted:
 *
 *   node tools/check-strip-safe.mjs                 # checks ./src
 *   node tools/check-strip-safe.mjs <dir-or-file>   # checks anything else
 *
 * Exit code 0 = every file strips cleanly; 1 = at least one does not (and the
 * offending file and message are printed).
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { stripTypeScriptTypes } from 'node:module'
import { fileURLToPath } from 'node:url'

const root = resolve(process.argv[2] ?? fileURLToPath(new URL('../src', import.meta.url)))

/** Every `.ts` file under a directory (or the file itself). */
function collect(target) {
  const stat = statSync(target)
  if (stat.isFile()) return target.endsWith('.ts') ? [target] : []
  const out = []
  for (const entry of readdirSync(target)) {
    if (entry === 'node_modules' || entry.startsWith('.')) continue
    out.push(...collect(join(target, entry)))
  }
  return out
}

let failed = 0
let checked = 0
for (const file of collect(root)) {
  checked += 1
  const source = readFileSync(file, 'utf8')
  try {
    // `mode: 'strip'` is exactly what the peer's runtime does: erase types or
    // throw. It never resolves imports, so a file that depends on the host
    // (server.ts imports @deepseek-ai/*) can still be checked.
    stripTypeScriptTypes(source, { mode: 'strip' })
  } catch (error) {
    failed += 1
    const message = error instanceof Error ? error.message.split('\n')[0] : String(error)
    console.error(`STRIP-FAIL ${relative(process.cwd(), file)}: ${message}`)
  }
}

if (failed === 0) {
  console.log(`strip-safe: ${checked} file(s) under ${root} load under Node strip-only mode`)
} else {
  console.error(`\n${failed} of ${checked} file(s) cannot be loaded by a strip-only runtime.`)
  console.error('Rewrite the offending syntax (e.g. a parameter property becomes a field plus an assignment).')
}
process.exitCode = failed === 0 ? 0 : 1
