/**
 * Stamp the version constants into the built bundles.
 *
 * Only used while `src/client.ts` and `src/server.ts` are being reconstructed:
 * the canonical path is `tools/build.mjs` from source. This edit is byte-exact
 * and refuses to run when the marker is not found exactly once.
 */
import { readFileSync, writeFileSync } from 'node:fs'

const stamps = [
  ['lib/client.js', 'var CLIENT_VERSION = "0.5.0";', 'var CLIENT_VERSION = "0.5.1";'],
  ['lib/server.js', 'var SERVER_VERSION = "0.5.0";', 'var SERVER_VERSION = "0.5.1";'],
  ['lib/server.js', 'var BUILD = "r24";', 'var BUILD = "r25";'],
]
for (const [file, from, to] of stamps) {
  const text = readFileSync(file, 'utf8')
  const count = text.split(from).length - 1
  if (count !== 1) throw new Error(`${file}: expected exactly one ${JSON.stringify(from)}, found ${count}`)
  writeFileSync(file, text.split(from).join(to), 'utf8')
  console.log(`${file}: ${from} -> ${to}`)
}
