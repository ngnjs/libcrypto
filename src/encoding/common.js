/**
 * Common encoding utilities
 * @module encoding
 */

/**
 * @method BTOA
 * Convert a binary string to Base64 string
 * @param {string} binaryString
 * The binary string to convert to a Base64-encoded ASCII string.
 * @returns {string}
 * The Base64-encoded ASCII string
 */
export const BTOA = globalThis.btoa || function (v) { return Buffer.from(v, 'binary').toString('base64') }

/**
 * @method ATOB
 * Base64 decode a string to binary data
 * @param {string} Base64string
 * The Base64-encoded string to convert to binary data.
 * @result {string}
 * Returns a binary encoded string
 */
export const ATOB = globalThis.atob || function (v) { return Buffer.from(v, 'base64').toString('binary') }

/**
 * Convert a string to an ArrayBuffer
 * @param {string} str
 * The string to convert.
 * @returns {ArrayBuffer}
 * The resulting ArrayBuffer
 */
export function StringToArrayBuffer (str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * Convert an ArrayBuffer to a string
 * @param {ArrayBuffer} buffer
 * The ArrayBuffer to convert.
 * @returns {String}
 */
export function ArrayBufferToString (buffer) {
  return String.fromCharCode.apply(null, new Uint8Array(buffer))
}

/**
 * Convert a UTF-8 string to a binary string
 * @param {string} input
 * A UTF-8 string
 * @returns {string}
 * Returns a binary string
 */
export function Utf8ToBinaryString (input) {
  // replaces any uri escape sequence, such as %0A,
  // with binary escape, such as 0x0A
  return encodeURIComponent(input).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode(parseInt(p1, 16)))
}
