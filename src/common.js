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

export const arrayBufferToString = buffer => String.fromCharCode.apply(null, new Uint8Array(buffer))

export function stringToArrayBuffer (str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}
