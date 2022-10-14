import { crypto } from '../lib/base.js'
import { ALGORITHMS } from '../lib/algorithms.js'
import {
  BTOA,
  ATOB,
  StringToArrayBuffer
} from './common.js'
import { Base64ToArrayBuffer } from './base64.js'

/**
 * PEM encoding utilities
 * @module encoding/PEM
 */

export const PEM_PATTERN = /^(?<raw>(?<header>-{1,}BEGIN\s+(?<algorithm>[A-Z-_0-9]+)(?=\sP(RIVATE|UBLIC))\s?(?<access>PRIVATE|PUBLIC)?(\s+)?(?<type>KEY|CERTIFICATE)-{2,})\n(?<body>[^-]+)\n?(?<footer>-{2,}(END\s[A-Z-_0-9\s]+-{2,})))$/i

/**
 * Encode a crypto key in PEM format.
 * @param {CryptoKey} key
 * The CryptoKey to encode in PEM format.
 * @returns {string}
 */
export async function encode (key) {
  if (!key.extractable) {
    throw new Error(`cannot encode ${key.type}Key (key must be extractable)`)
  }

  let exportedKey
  let body

  switch (key.type) {
    case 'public':
      exportedKey = await crypto.subtle.exportKey('spki', key)
      body = BTOA(String.fromCharCode(...new Uint8Array(exportedKey)))
      return `-----BEGIN ${key.algorithm.name} PUBLIC KEY-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END ${key.algorithm.name} PUBLIC KEY-----`
    case 'private':
      exportedKey = await crypto.subtle.exportKey('pkcs8', key)
      body = BTOA(String.fromCharCode(...new Uint8Array(exportedKey)))
      return `-----BEGIN ${key.algorithm.name} PRIVATE KEY-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END ${key.algorithm.name} PRIVATE KEY-----`
    case 'secret':
      exportedKey = await crypto.subtle.exportKey('raw', key)
      body = BTOA(String.fromCharCode(...new Uint8Array(exportedKey)))
      return `-----BEGIN ${key.algorithm.name} PUBLIC KEY-----\n${body.match(/.{1,64}/g).join('\n')}\n-----END ${key.algorithm.name} PUBLIC KEY-----`
  }

  throw new Error(`${key.type} cannot be encoded in PEM format (only 'public' and 'private' keys)`)
}

/**
 * Decode a PEM string to a CryptoKey.
 * @param {string} pem
 * The PEM string to decode.
 * @param {string|object} [algorithm=EC256]
 * The algorithm to decode the PEM key with
 * @param {string[]} [usage]
 * Usage of the key. If unspecified, an attempt to auto-identify
 * usage is determined based on the PEM data (type, public/private).
 * @returns {CryptoKey}
 */
export async function decode (pem, algorithm = 'ES256', usage) {
  const key = info(pem)

  if (!key.private && !key.public) {
    throw new Error('cannot decode PEM content because it is neither public or private')
  }

  if (!usage) {
    usage = []
    if (key.private) {
      usage.push('sign')
    }
    if (key.public) {
      usage.push('verify')
    }
  }

  const binaryDerString = ATOB(key.body)
  const binaryDer = StringToArrayBuffer(binaryDerString)

  if (typeof algorithm === 'string') {
    const original = algorithm
    algorithm = ALGORITHMS[algorithm]
    if (!algorithm) {
      throw new Error(`invalid or unrecognized algorithm "${original}" - use a recognized algorithm: ${Object.keys(ALGORITHMS).join(',')}`)
    }
  }

  return crypto.subtle.importKey(
    key.private ? 'pkcs8' : 'spki',
    binaryDer,
    algorithm,
    true,
    usage
  )
}

/**
 * Extract info about a PEM-encoded string.
 * @param {string} pem
 * A PEM-encoded string.
 * @returns {Object}
 * The result object containst the following attributes:
 * - `header (string)`: The PEM header
 * - `body (string)`: The PEM content
 * - `footer (string)`: The PEM footer
 * - `raw (string)`: The complete raw PEM
 * - `algorithm (string)`: The algorithm used to create the PEM (if available)
 * - `access (string)`: The PEM access type (typically `PUBLIC` or `PRIVATE` for keys, `null` for certificates)
 * - `type (string)`: The PEM content type (typically `KEY` or `CERTIFICATE`)
 * - `private (boolean)`: Indicates the PEM is private
 * - `public (boolean)`: Indicates the PEM is public
 * - `length (number)`: The length of the body
 */
export function info (pem) {
  let match = PEM_PATTERN.exec(pem)
  if (match === null) {
    // Rerun the match (which fails in some runtimes due to runtime-specific timing issues)
    match = PEM_PATTERN.exec(pem)
    if (match === null) {
      throw Error('error parsing PEM content (invalid format)')
    }
  }

  const data = {
    header: match[2],
    body: match[8],
    footer: match[9],
    raw: match[1],
    algorithm: match[3],
    access: match[5],
    type: match[7]
  }

  data.length = data.body.length + data.body.split('\n').length - 1
  // data.hash = 'SHA-' + data.size
  data.private = data.access.toUpperCase() === 'PRIVATE'
  data.public = data.access.toUpperCase() === 'PUBLIC'

  return data
}

/**
 * Convert a CryptoKey or keypair to PEM-encoded string(s).
 * @param {CryptoKey|Object} keypair
 * A CryptoKey or keypair (of publicKey and privateKey CryptoKeys)
 * to convert to PEM-encoded string(s).
 * @returns {string|object}
 * Returns the PEM-encoded string for the key(s)
 */
export async function ToPEM (keypair) {
  if (keypair instanceof CryptoKey) {
    return await encode(keypair)
  }

  return {
    publicKey: await encode(keypair.publicKey),
    privateKey: await encode(keypair.privateKey)
  }
}

/**
 * Convert a PEM-encoded string to a CryptoKey
 * @param {string} pem
 * The PEM-encoded string.
 * @param {object} algorithm
 * The algorithm object used to import the key.
 * See the [available options](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#:~:text=the%20given%20format.-,algorithm,-An%20object%20defining).
 * @param {string[]} usage
 * The usage of the key, such as `sign` and/or `verify`
 * @returns {CryptoKey}
 * The imported key.
 */
export async function ToCryptoKey (pem, algorithm, usage) {
  const keyinfo = info(pem)
  const format = keyinfo.public ? 'spki' : (keyinfo.private ? 'pkcs8' : 'raw')
  const binaryDer = Base64ToArrayBuffer(keyinfo.body)

  return await crypto.subtle.importKey(
    ['HMAC'].indexOf(algorithm.name) >= 0 ? 'raw' : format,
    binaryDer,
    algorithm,
    true,
    usage
  )
}

/**
 * Accepts a PEM-encoded string, CryptoKey, named algorithm, and usage
 * to produce a CryptoKey. Use this function to normalize a key (i.e. any
 * input, guaranteed CryptoKey output).
 * @param {string|CryptoKey} key
 * The PEM-encoded string or CryptoKey
 * @param {string|object} algorithm
 * The named algorithm or algorithm object.
 * @param {string[]} [usage=[]]
 * The key usage.
 * @returns {CryptoKey}
 * Returns a CryptoKey.
 */
export async function normalizeKey (key, algorithm, usage = []) {
  key = typeof key === 'string' ? await ToCryptoKey(key, algorithm, usage) : key

  if (!(key instanceof CryptoKey)) {
    throw new Error(`invalid key - expected CryptoKey, got ${typeof key}`)
  }

  return key
}