/**
 * Push one or more built files to a peer's staging directory over the encrypted
 * link, using the plugin's own `fs.write` / `fs.hash` ops.
 *
 * Why a script instead of remote_fs_write: the tool payload travels through a
 * model context, which is fine for a config file and wasteful for a ~100 KB
 * bundle. Here the bytes go straight from disk to the peer.
 *
 * Nothing is installed by this script: the files land in `<remoteHome>/dsh-remote/
 * stage-<tag>/`, hashes are compared, and the (separate) install step only runs
 * after the user agrees to a restart.
 *
 * Usage:
 *   node tools/push-lib.mjs <host> <port> <remoteHome> <tag> <localFile>...
 *   node tools/push-lib.mjs peer.example 50000 'C:/Users/demo/.dsh' r18 lib/server.js lib/client.js
 */

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { basename, join } from 'node:path'

import { LinkClient } from '../lib/link.js'

const [host, portArg, remoteHome, tag, ...files] = process.argv.slice(2)
if (host === undefined || portArg === undefined || remoteHome === undefined || tag === undefined || files.length === 0) {
  console.error('usage: node tools/push-lib.mjs <host> <port> <remoteHome> <tag> <localFile>...')
  process.exit(2)
}

const home = process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? '', '.dsh')
const link = new LinkClient(() => ({
  host,
  port: Number(portArg),
  privateKeyFile: join(home, 'dsh-remote', 'client.key'),
  peerPublicKeyFile: join(home, 'dsh-remote', 'server.pub'),
  timeoutMs: 120_000,
}), message => console.log(message), 'push-lib')

const stage = `${remoteHome.replace(/\/+$/u, '')}/dsh-remote/stage-${tag}`
let failures = 0
for (const file of files) {
  const raw = readFileSync(file)
  const sha256 = createHash('sha256').update(raw).digest('hex')
  const target = `${stage}/${basename(file)}`
  let write
  try {
    write = await link.request('fs.write', {
      path: target,
      dataB64: raw.toString('base64'),
      createOnly: true,
    }, 120_000)
  } catch (error) {
    // A retried push finds its own earlier staging file: overwrite it deliberately.
    if (error?.peerCode !== 'FS_NOT_OBSERVED') throw error
    write = await link.request('fs.write', { path: target, dataB64: raw.toString('base64') }, 120_000)
  }
  const hash = await link.request('fs.hash', { path: target }, 120_000)
  const ok = write.size === raw.length && hash.algo === 'sha256' && String(hash.hash) === sha256
  if (!ok) failures += 1
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${basename(file)}  remote=${write.size}B  sha256=${hash.hash}`)
}
link.close()
process.exitCode = failures === 0 ? 0 : 1
