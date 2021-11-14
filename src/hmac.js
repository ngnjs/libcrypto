import { nodecrypto } from './common.js'

export function createNodeHMAC (secret, data, algorithm) {
  const buffer = Buffer.alloc(8)

  if (Number.isFinite(data) || typeof data === 'bigint') {
    buffer.write(zeropad(data.toString(16)), 0, 'hex')
  } else if (Buffer.isBuffer(data)) {
    data.copy(buffer)
  } else if (typeof data === 'string') {
    buffer.write(zeropad(data), 0, 'hex')
  } else {
    throw new Error(`Unexpected data type ${typeof data}`)
  }

  return nodecrypto.createHmac(algorithm, secret).update(buffer).digest()
}

// Uint8Array(8)
export function pad (counter) {
  const pairs = counter.toString(16).padStart(16, '0').match(/..?/g)
  const array = pairs.map(v => parseInt(v, 16))
  return Uint8Array.from(array)
}

// Number
export function truncate (hs) {
  const offset = hs[19] & 0b1111
  return ((hs[offset] & 0x7f) << 24) | (hs[offset + 1] << 16) | (hs[offset + 2] << 8) | hs[offset + 3]
}

export function zeropad (value, digits = 16) {
  var fill = '0'.repeat(digits)
  return (fill + value).slice(-digits)
}
