import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import { downloadToBuffer } from '../src/transfer-client.ts'
import type { TransferRequest } from '../src/transfer-client.ts'
import { decodeTransferBlock } from '../src/transfer-codec.ts'

for (const invalid of ['YQ=', 'YR==', 'YQ==\n', '!!!!', 'YQ===', '', undefined]) {
  if (invalid === '') assert.equal(decodeTransferBlock(invalid, 0).length, 0)
  else assert.throws(() => decodeTransferBlock(invalid, 1), /base64/)
}
assert.equal(decodeTransferBlock('YQ==', 1).toString(), 'a')
assert.throws(() => decodeTransferBlock('a'.repeat(2_000_000), 64 * 1024), /oversized/)
const bomb = gzipSync(Buffer.alloc(2 * 1024 * 1024, 'x'))
let hashes = 0
const request: TransferRequest = async op => {
  if (op === 'fs.stat') return { exists: true, isDir: false, size: 64 * 1024 }
  if (op === 'fs.get') return { dataB64: bomb.toString('base64'), encoding: 'gzip', offset: 0, bytes: 64 * 1024, eof: true }
  if (op === 'fs.hash') { hashes++; return { hash: createHash('sha256').update('fixture').digest('hex') } }
  throw new Error('unexpected op')
}
await assert.rejects(downloadToBuffer(request, '/fixture', { chunkSize: 64 * 1024 }), /corrupt gzip|longer than requested/)
assert.equal(hashes, 0)
const unknownEncoding: TransferRequest = async (op, args, timeout) => op === 'fs.get'
  ? { dataB64: 'YQ==', encoding: 'brotli', offset: 0, bytes: 1, eof: true }
  : request(op, args, timeout)
await assert.rejects(downloadToBuffer(unknownEncoding, '/fixture'), /unknown chunk encoding/)
console.log('ALL PASS: canonical bounded transfer decoding, gzip bomb fence and explicit encoding')
