const runtime = globalThis.process !== undefined ? 'node' : (globalThis.hasOwnProperty('Deno') ? 'deno' : 'browser') // eslint-disable-line no-prototype-builtins
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

export { nodecrypto, cryptography, runtime }

export const BTOA = globalThis.btoa || function (v) { return Buffer.from(v, 'binary').toString('base64') }

export const arrayBufferToString = buffer => String.fromCharCode.apply(null, new Uint8Array(buffer))

export function stringToArrayBuffer (str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

export function bufToHex (buffer) {
  return Array.prototype.slice
    .call(new Uint8Array(buffer))
    .map(x => [x >> 4, x & 15])
    .map(ab => ab.map(x => x.toString(16)).join(''))
    .join('')
}

export const hexToBuf = str => new Uint8Array(str.match(/.{2}/g).map(byte => parseInt(byte, 16)))
