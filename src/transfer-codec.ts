/** Bound encoded bytes before allocation; Node's permissive decoder alone is
 * not validation. Gzip input gets small header/expansion allowance, never a
 * peer-chosen output budget. */
export function decodeTransferBlock(value: unknown, decodedLimit: number): Buffer {
  if (!Number.isSafeInteger(decodedLimit) || decodedLimit < 0 || decodedLimit > 8 * 1024 * 1024) throw new Error('transfer: invalid block size limit')
  const wireLimit = decodedLimit + 65_536
  const textLimit = 4 * Math.ceil(wireLimit / 3)
  if (typeof value !== 'string' || value.length > textLimit || value.length % 4 !== 0
    || !/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new Error('transfer: invalid or oversized base64 block')
  }
  const data = Buffer.from(value, 'base64')
  if (data.length > wireLimit || data.toString('base64') !== value) throw new Error('transfer: invalid or oversized base64 block')
  return data
}
