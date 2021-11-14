import { arrayBufferToString } from '../common.js'

export const BTOA = globalThis.btoa || function (v) { return Buffer.from(v, 'binary').toString('base64') }
export const ATOB = globalThis.atob || function (v) { return Buffer.from(v, 'base64').toString('hex') }
export const bufToBase64 = buff => BTOA(arrayBufferToString(buff))
export const base64ToBuf = str => Uint8Array.from(ATOB(str), c => c.charCodeAt(0))
export const URL = {
  stringify: a => bufToBase64(a).replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
  parse: s => base64ToBuf(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
}

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
