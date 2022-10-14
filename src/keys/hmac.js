import { HMAC_ALGORITHMS, normalize } from '../lib/algorithms.js'
import { ToPEM } from '../encoding/pem.js'

/**
 * Create HMAC cryptokeys
 * @module HMAC
 */

const encoder = new TextEncoder()

/**
 * @function createKey
 * Create a secret key using the `HMAC` (default) strategy.
 * @async
 * @param {string} [algorithm=HS256] (HS256, HS384, HS512)
 * The algorithm used to hash the keypair.
 * - `HS256` = HMAC SHA-256
 * - `HS384` = HMAC SHA-384
 * - `HS512` = HMAC SHA-512
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {CryptoKey}
 * Returns an object with a single crypto key, called `key`.
 */
export async function createKey(secret, algorithm = 'HS256', usage = ['sign', 'verify']) {
  if (typeof secret !== 'string' || secret.replace(/\s+/gi, '').length < 8) {
    throw new Error('invalid HMAC secret - must be a string, 8 non-blank characters or more')
  }

  algorithm = normalize(algorithm, HMAC_ALGORITHMS)

  return await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    algorithm,
    true,
    usage
  )
}

/**
 * @function createKeyPEM
 * Create a key using the `HMAC` strategy.
 * @async
 * @param {string} [algorithm=HS256] (HS256, HS384, HS512)
 * The algorithm used to hash the keypair.
 * - `HS256` = HMAC P-256
 * - `HS384` = HMAC P-384
 * - `HS512` = HMAC P-512
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {string}
 * Returns a PEM-encoded string, called `key`.
 */
export async function createKeyPEM() {
  return await ToPEM(await createKey(...arguments))
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