// Modified from https://github.com/beatgammit/base64-js
// Copyright (c) 2014 Jameson Little. MIT License.

const lookup = []
const revLookup = []
const placeHolderPadLookup = [0, 1, , 2, 3, , 4] // eslint-disable-line no-sparse-arrays
const code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
code.split('').forEach((v, i) => {
  lookup[i] = v
  revLookup[code.charCodeAt(i)] = i
})

function _getPadLen (placeHoldersLen) {
  const maybeLen = placeHolderPadLookup[placeHoldersLen]
  if (typeof maybeLen !== 'number') {
    throw new Error('Invalid pad length')
  }
  return maybeLen
}

// function byteLength (b32) {
//   const [validLen, placeHoldersLen] = getLens(b32)
//   return _byteLength(validLen, placeHoldersLen)
// }

function _byteLength (validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 5) / 8 - _getPadLen(placeHoldersLen)
}

function encodeBase32Chunk (uint8, start, end) {
  let tmp
  const output = []
  for (let i = start; i < end; i += 5) {
    tmp = ((uint8[i] << 16) & 0xff0000) |
      ((uint8[i + 1] << 8) & 0xff00) |
      (uint8[i + 2] & 0xff)
    output.push(
      lookup[(tmp >> 19) & 0x1f],
      lookup[(tmp >> 14) & 0x1f],
      lookup[(tmp >> 9) & 0x1f],
      lookup[(tmp >> 4) & 0x1f]
    )
    tmp = ((tmp & 0xf) << 16) |
      ((uint8[i + 3] << 8) & 0xff00) |
      (uint8[i + 4] & 0xff)
    output.push(
      lookup[(tmp >> 15) & 0x1f],
      lookup[(tmp >> 10) & 0x1f],
      lookup[(tmp >> 5) & 0x1f],
      lookup[tmp & 0x1f]
    )
  }
  return output.join('')
}

function getLens (b32) {
  const len = b32.length

  if (len % 8 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 8')
  }

  let validLen = b32.indexOf('=')
  if (validLen === -1) {
    validLen = len
  }

  const placeHoldersLen = validLen === len ? 0 : 8 - (validLen % 8)

  return [validLen, placeHoldersLen]
}

/**
 * Encodes a given Uint8Array into RFC4648 base32 representation
 * @param {Uint8Array} buffer
 * @returns {string}
 */
export function bufToBase32 (uint8) {
  let tmp
  const extraBytes = uint8.length % 5
  const parts = []
  const maxChunkLength = 16385 // must be multiple of 5
  const len = uint8.length - extraBytes

  // go through the array every 5 bytes, we'll deal with trailing stuff later
  for (let i = 0; i < len; i += maxChunkLength) {
    parts.push(
      encodeBase32Chunk(
        uint8,
        i,
        i + maxChunkLength > len ? len : i + maxChunkLength
      )
    )
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 4) {
    tmp = ((uint8[len] & 0xff) << 16) |
      ((uint8[len + 1] & 0xff) << 8) |
      (uint8[len + 2] & 0xff)
    parts.push(
      lookup[(tmp >> 19) & 0x1f],
      lookup[(tmp >> 14) & 0x1f],
      lookup[(tmp >> 9) & 0x1f],
      lookup[(tmp >> 4) & 0x1f]
    )
    tmp = ((tmp & 0xf) << 11) | (uint8[len + 3] << 3)
    parts.push(
      lookup[(tmp >> 10) & 0x1f],
      lookup[(tmp >> 5) & 0x1f],
      lookup[tmp & 0x1f],
      '='
    )
  } else if (extraBytes === 3) {
    tmp = ((uint8[len] & 0xff) << 17) |
      ((uint8[len + 1] & 0xff) << 9) |
      ((uint8[len + 2] & 0xff) << 1)
    parts.push(
      lookup[(tmp >> 20) & 0x1f],
      lookup[(tmp >> 15) & 0x1f],
      lookup[(tmp >> 10) & 0x1f],
      lookup[(tmp >> 5) & 0x1f],
      lookup[tmp & 0x1f],
      '==='
    )
  } else if (extraBytes === 2) {
    tmp = ((uint8[len] & 0xff) << 12) | ((uint8[len + 1] & 0xff) << 4)
    parts.push(
      lookup[(tmp >> 15) & 0x1f],
      lookup[(tmp >> 10) & 0x1f],
      lookup[(tmp >> 5) & 0x1f],
      lookup[tmp & 0x1f],
      '===='
    )
  } else if (extraBytes === 1) {
    tmp = (uint8[len] & 0xff) << 2
    parts.push(
      lookup[(tmp >> 5) & 0x1f],
      lookup[tmp & 0x1f],
      '======'
    )
  }

  return parts.join('')
}

/**
 * Decodes a given RFC4648 base32 encoded string.
 * @param {string} data
 * @returns {Uint8Array}
 */
export function base32ToBuf (b32) {
  let tmp
  let curByte = 0
  const [validLen, placeHoldersLen] = getLens(b32)
  const arr = new Uint8Array(_byteLength(validLen, placeHoldersLen))

  // if there are placeholders, only get up to the last complete 8 chars
  const len = placeHoldersLen > 0 ? validLen - 8 : validLen

  let i
  for (i = 0; i < len; i += 8) {
    tmp = (revLookup[b32.charCodeAt(i)] << 20) |
      (revLookup[b32.charCodeAt(i + 1)] << 15) |
      (revLookup[b32.charCodeAt(i + 2)] << 10) |
      (revLookup[b32.charCodeAt(i + 3)] << 5) |
      revLookup[b32.charCodeAt(i + 4)]
    arr[curByte++] = (tmp >> 17) & 0xff
    arr[curByte++] = (tmp >> 9) & 0xff
    arr[curByte++] = (tmp >> 1) & 0xff

    tmp = ((tmp & 1) << 15) |
      (revLookup[b32.charCodeAt(i + 5)] << 10) |
      (revLookup[b32.charCodeAt(i + 6)] << 5) |
      revLookup[b32.charCodeAt(i + 7)]
    arr[curByte++] = (tmp >> 8) & 0xff
    arr[curByte++] = tmp & 0xff
  }

  if (placeHoldersLen === 1) {
    tmp = (revLookup[b32.charCodeAt(i)] << 20) |
      (revLookup[b32.charCodeAt(i + 1)] << 15) |
      (revLookup[b32.charCodeAt(i + 2)] << 10) |
      (revLookup[b32.charCodeAt(i + 3)] << 5) |
      revLookup[b32.charCodeAt(i + 4)]
    arr[curByte++] = (tmp >> 17) & 0xff
    arr[curByte++] = (tmp >> 9) & 0xff
    arr[curByte++] = (tmp >> 1) & 0xff
    tmp = ((tmp & 1) << 7) |
      (revLookup[b32.charCodeAt(i + 5)] << 2) |
      (revLookup[b32.charCodeAt(i + 6)] >> 3)
    arr[curByte++] = tmp & 0xff
  } else if (placeHoldersLen === 3) {
    tmp = (revLookup[b32.charCodeAt(i)] << 19) |
      (revLookup[b32.charCodeAt(i + 1)] << 14) |
      (revLookup[b32.charCodeAt(i + 2)] << 9) |
      (revLookup[b32.charCodeAt(i + 3)] << 4) |
      (revLookup[b32.charCodeAt(i + 4)] >> 1)
    arr[curByte++] = (tmp >> 16) & 0xff
    arr[curByte++] = (tmp >> 8) & 0xff
    arr[curByte++] = tmp & 0xff
  } else if (placeHoldersLen === 4) {
    tmp = (revLookup[b32.charCodeAt(i)] << 11) |
      (revLookup[b32.charCodeAt(i + 1)] << 6) |
      (revLookup[b32.charCodeAt(i + 2)] << 1) |
      (revLookup[b32.charCodeAt(i + 3)] >> 4)
    arr[curByte++] = (tmp >> 8) & 0xff
    arr[curByte++] = tmp & 0xff
  } else if (placeHoldersLen === 6) {
    tmp = (revLookup[b32.charCodeAt(i)] << 3) |
      (revLookup[b32.charCodeAt(i + 1)] >> 2)
    arr[curByte++] = tmp & 0xff
  }

  return arr
}
