import {
  ASYMMETRIC_ENCRYPTION_ALGORITHMS,
  ENCRYPTION_ALGORITHMS,
  ALGORITHMS,
  normalize
} from '../lib/algorithms.js'
import { encode } from '../encoding/pem.js'

/**
 * Create a keypair
 * @param {Object} algorithm - The [algorithm](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey) configuration object.
 * @param {boolean} [exportable=true] - Indicates the keypair is exportable/extractable.
 * @param {string[]} [usage=['sign', 'view']] - Identify the usage of the keypair.
 * @returns {Object} - The returned object contains a privateKey and publicKey. Each key is either a CryptoKey or PEM string, depending on the value of the `pem` argument.
 */
export async function createKeypair (algorithm = 'ES256', usage = ['sign', 'verify'], exportable = true) {
  algorithm = normalize(algorithm)

  const keypair = await crypto.subtle.generateKey(
    algorithm,
    exportable,
    usage
  )

  return keypair
}

/**
 * Create a keypair
 * @param {Object} algorithm
 * The [algorithm](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey) configuration object.
 * @param {boolean} [exportable=true]
 * Indicates the keypair is exportable/extractable.
 * @param {string[]} [usage=['sign','view']]
 * Identify the usage of the keypair.
 * @returns {Object}
 * The returned object contains a privateKey and publicKey.
 * Each key is a PEM string.
 */
export async function createKeypairPEM () {
  const { publicKey, privateKey } = await createKeypair(...arguments)
  return {
    publicKey: await encode(publicKey),
    privateKey: await encode(privateKey)
  }
}

export async function deriveEncryptionKey (privateKey, publicKey, algorithm = 'EC256', cipherAlgorithm = 'GCM256') {
  algorithm = normalize(algorithm, ASYMMETRIC_ENCRYPTION_ALGORITHMS)
  cipherAlgorithm = normalize(cipherAlgorithm, ENCRYPTION_ALGORITHMS)

  algorithm.public = publicKey
  delete cipherAlgorithm.hash

  return await crypto.subtle.deriveKey(
    algorithm,
    privateKey,
    cipherAlgorithm,
    false,
    ['encrypt', 'decrypt']
  )
}

export function extractKeyType (algorithm) {
  let keyType = ALGORITHMS[algorithm]
  let { algo, size } = /(?<algo>[^0-9]+)(?<size>[0-9]+)/.exec(algorithm).groups

  switch (algo.toUpperCase()) {
    case 'ES':
      break
    case 'RS':
      keyType.modulusLength = rsabitsize (size)
      keyType.publicExponent = new Uint8Array([1, 0, 1])
    case 'PS':
      keyType.name = 'RSA-PSS'
      keyType.modulusLength = size === '512' ? 4096 : size === '384' ? 3072 : 2048
      keyType.publicExponent = new Uint8Array([1, 0, 1])
      break
    case 'HMAC':
      keyType = {
        name: 'HMAC',
        hash: `SHA-${size}`
      }
      break
  }

  return [keyType, algo.toUpperCase(), size]
}

export function rsabitsize (hash) {
  switch (hash.toString()) {
    case '384':
      return 3072
    case '512':
      return 4096
    default:
      return 2048
  }
}