import { BTOA, ATOB } from './common.js'

const encoder = new TextEncoder()

/**
 * Convert an ArrayBuffer to a Base64 string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 * @tag ArrayBufferToBase64
 */
export function encode (buffer) {
  if (typeof buffer === 'string') {
    return encode(encoder.encode(buffer))
  }

  return BTOA(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+/g, '')
}

/**
 * Convert a Base64 string to an ArrayBuffer
 * @param {string} string
 * String to decode into an ArrayBuffer
 * @param {boolean} [url=true]
 * Apply URL encoding (replaces `-` with `+` and `_` with `/`
 * and removes whitespace)
 * @returns {ArrayBuffer}
 * @tag Base64ToArrayBuffer
 * @tag UrlBase64ToBinaryString
 */
export function decode (string, url = true) {
  if (url) {
    string = string.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '')
  }

  return Uint8Array.from(ATOB(string), c => c.charCodeAt(0))
}

export function Base64ToArrayBuffer (str) {
  return Uint8Array.from(ATOB(str), c => c.charCodeAt(0))
}


/**
 * Convert an ArrayBuffer or Base64 string to ASCII string
 * @param {ArrayBuffer|string} buffer
 * @returns
 */
export function stringify (buffer) {
  return typeof buffer === 'string'
    ? stringify(Base64.decode(buffer))
    : decoder.decode(buffer)
}

/**
 * Convert an ArrayBuffer to a Base64 string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 * A Base64 string
 */
// export function ArrayBufferToBase64 (buffer) {
//   return BTOA(ArrayBufferToString(buffer))
// }

/**
 * Convert a Base64 string to an ArrayBuffer
 * @param {string} base64string
 * The Base64 string to convert to ArrayBuffer
 * @returns {ArrayBuffer}
 */
// export function Base64ToArrayBuffer (str) {
//   return Uint8Array.from(ATOB(str), c => c.charCodeAt(0))
// }

export function createCipher(salt, iv, cipher, tag) {
  const encryptedContent = new Uint8Array(cipher)
  const tagLength = (tag ? tag.byteLength : 0)
  const buf = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength + tagLength)

  buf.set(salt, 0)
  buf.set(iv, salt.byteLength)
  if (tagLength > 0) {
    buf.set(tag, salt.byteLength + iv.byteLength)
  }
  buf.set(encryptedContent, salt.byteLength + iv.byteLength + tagLength)

  return encode(buf.buffer)
}

// export function UrlBase64ToBase64(str) {
//   const r = str % 4
//   if (r === 2) {
//     str += '=='
//   } else if (r === 3) {
//     str += '='
//   }
//   return str.replace(/-/g, '+').replace(/_/g, '/')
// }


// export function BinaryStringToUrlBase64(input) {
//   return BTOA(input)
//     .replace(/\+/g, '-')
//     .replace(/\//g, '_')
//     .replace(/=+/g, '')
// }

// export function UrlBase64ToBinaryString (input) {
//   return ATOB(UrlBase64ToString(input))
// }

// export function StringToUrlBase64(input) {
//   return BinaryStringToUrlBase64(Utf8ToBinaryString(input))
// }

// export function UrlBase64ToString(input) {
//   input = input
//     .replace(/-/g, '+')
//     .replace(/_/g, '/')

//   let pad = input.length % 4
//   if (pad) {
//     if (pad === 1) {
//       throw new Error('InvalidLengthError: input base64url string is invalid (incorrect length)')
//     }

//     input += new Array(5 - pad).join('=')
//   }

//   return input
// }

// export const URL = {
//   stringify: a => ArrayBufferToBase64(a).replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
//   parse: s => Base64ToArrayBuffer(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
// }
