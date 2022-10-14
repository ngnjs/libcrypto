import { ECDSA_ALGORITHMS } from '../lib/algorithms.js'
import { createKeypair as createKeypairBase } from './keypair.js'
import { ToPEM } from '../encoding/pem.js'

/**
 * Create ECDSA cryptokey pairs
 * @module ECDSA
 */

/**
 * @function createKeypair
 * Create a keypair using the `ECDSA` strategy.
 * @async
 * @param {string} [algorithm=ES256] (ES256, ES384, ES512)
 * The algorithm used to hash the keypair.
 * - `ES256` = ECDSA P-256
 * - `ES384` = ECDSA P-384
 * - `ES512` = ECDSA P-512 (not supported on Deno)
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two crypto keys, called `publicKey`
 * and `privateKey`
 */
export async function createKeypair (algorithm = 'ES256', usage = ['sign', 'verify']) {
  if (typeof algorithm === 'string') {
    if (!ECDSA_ALGORITHMS[algorithm.trim().toUpperCase()]) {
      throw new Error(`invalid ECDSA algorithm "${algorithm}" - must be one of: ${Array.from(ECDSA_ALGORITHMS).join(', ')}`)
    }

    algorithm = ECDSA_ALGORITHMS[algorithm]
  }

  return await createKeypairBase(algorithm, usage)
}

/**
 * @function createKeypairPEM
 * Create a keypair using the `ECDSA` strategy.
 * @async
 * @param {string} [algorithm=ES256] (ES256, ES384, ES512)
 * The algorithm used to hash the keypair.
 * - `ES256` = ECDSA P-256
 * - `ES384` = ECDSA P-384
 * - `ES512` = ECDSA P-512 (not supported on Deno)
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two PEM-encoded values, called `publicKey`
 * and `privateKey`
 */
export async function createKeypairPEM () {
  return await ToPEM(await createKeypair(...arguments))
}