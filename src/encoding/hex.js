import { stringToArrayBuffer } from '../common.js'
import { BTOA } from './base64.js'

export function bufToHex (buffer) {
  return Array.prototype.slice
    .call(new Uint8Array(buffer))
    .map(x => [x >> 4, x & 15])
    .map(ab => ab.map(x => x.toString(16)).join(''))
    .join('')
}

export const hexToBuf = str => new Uint8Array(str.match(/.{2}/g).map(byte => parseInt(byte, 16)))

export function hexToBase64 (hexstring) {
  return BTOA(hexstring.match(/\w{2}/g).map(function (a) {
    return String.fromCharCode(parseInt(a, 16))
  }).join(''))
}

export const base64ToHex = str => bufToHex(stringToArrayBuffer(str))
