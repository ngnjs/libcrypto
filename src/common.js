export const runtime = globalThis.process !== undefined ? 'node' : (globalThis.hasOwnProperty('Deno') ? 'deno' : 'browser') // eslint-disable-line no-prototype-builtins
let nodecrypto // For Node.js only
let cryptography = null
if (runtime === 'node') {
  ; (async () => {
    nodecrypto = await import('crypto')
    try {
      cryptography = nodecrypto.webcrypto
    } catch (e) { }
  })()
} else {
  cryptography = globalThis.crypto
}

export { nodecrypto, cryptography }

export const BTOA = globalThis.btoa || function (v) { return Buffer.from(v, 'binary').toString('base64') }
export const ATOB = globalThis.atob || function (v) { return Buffer.from(v, 'base64').toString('hex') }
export const bufToBase64 = buff => BTOA(arrayBufferToString(buff))
export const base64ToBuf = str => Uint8Array.from(ATOB(str), c => c.charCodeAt(null))
export const arrayBufferToString = buffer => String.fromCharCode.apply(null, new Uint8Array(buffer))

export function stringToArrayBuffer (str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

// export function bufToHex (buffer) {
//   return Array.prototype.slice
//     .call(new Uint8Array(buffer))
//     .map(x => [x >> 4, x & 15])
//     .map(ab => ab.map(x => x.toString(16)).join(''))
//     .join('')
// }

// export const hexToBuf = str => new Uint8Array(str.match(/.{2}/g).map(byte => parseInt(byte, 16)))

// export function hexToBase64 (hexstring) {
//   return BTOA(hexstring.match(/\w{2}/g).map(function (a) {
//     return String.fromCharCode(parseInt(a, 16))
//   }).join(''))
// }

// export const base64ToHex = str => bufToHex(stringToArrayBuffer(str))

export function createBase64Cipher (salt, iv, cipher, tag) {
  const encryptedContent = new Uint8Array(cipher)
  const tagLength = (tag ? tag.byteLength : 0)
  const buf = new Uint8Array(salt.byteLength + iv.byteLength + encryptedContent.byteLength + tagLength)

  buf.set(salt, 0)
  buf.set(iv, salt.byteLength)
  if (tagLength > 0) {
    buf.set(tag, salt.byteLength + iv.byteLength)
  }
  buf.set(encryptedContent, salt.byteLength + iv.byteLength + tagLength)

  return bufToBase64(buf.buffer)
}
