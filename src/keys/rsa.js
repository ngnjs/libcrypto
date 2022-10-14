import { createKeypair as createKeypairBase } from './keypair.js'
import { normalize, RSA_ALGORITHMS } from '../lib/algorithms.js'
import { ToPEM } from '../encoding/pem.js'

/**
 * Create RSA cryptokey pairs
 * @module RSA
 */

function RSA (algorithm, hash = 'SHA-256', modulusLength) {
  algorithm = normalize(algorithm, RSA_ALGORITHMS)
  algorithm.modulusLength = modulusLength || algorithm.modulusLength
  algorithm.publicExponent = new Uint8Array([1, 0, 1])
  algorithm.hash = algorithm.hash || { name: hash }
  return algorithm
}

/**
 * @function createRSAKeypair
 * A helper method to create an RSA keypair using a named algorithm:
 * @param {string} [name=RS256]
 * The algorithm name:
 * - `RS256`: RSASSA-PKCS1-v1_5 SHA-256 2048 bit
 * - `RS384`: RSASSA-PKCS1-v1_5 SHA-384 3072 bit
 * - `RS512`: RSASSA-PKCS1-v1_5 SHA-512 4096 bit
 * - `PS256`: RSA-PSS SHA-256 salt 2048 bit
 * - `PS384`: RSA-PSS SHA-384 salt 3072 bit
 * - `PS512`: RSA-PSS SHA-512 salt 4096 bit
 * @param {string[]} [usage=['sign', 'verify']]
 * The keypair usage.
 * @returns {Object}
 * Returns an object with two crypto keys, called `publicKey`
 * and `privateKey`
 */
export async function createKeypair(name = 'RS256', usage = ['sign', 'verify']) {
  return await createKeypairBase(RSA(name), usage)
}

/**
 * @function createRSAKeypairPEM
 * A helper method to create an RSA keypair using a named algorithm:
 * The results will be PEM-encoded strings.
 * @param {string} [name=RS256]
 * The algorithm name:
 * - `RS256`: RSASSA-PKCS1-v1_5 SHA-256 2048 bit
 * - `RS384`: RSASSA-PKCS1-v1_5 SHA-384 3072 bit
 * - `RS512`: RSASSA-PKCS1-v1_5 SHA-512 4096 bit
 * - `PS256`: RSA-PSS SHA-256 salt 2048 bit
 * - `PS384`: RSA-PSS SHA-384 salt 3072 bit
 * - `PS512`: RSA-PSS SHA-512 salt 4096 bit
 * @param {string[]} [usage=['sign', 'verify']]
 * The keypair usage.
 * @returns {Object}
 * Returns an object with two PEM-encoded values, called `publicKey`
 * and `privateKey`
 */
export async function createKeypairPEM() {
  return await ToPEM(await createKeypair(...arguments))
}

/**
 * @function createPKCS1Keypair
 * Create a keypair using the `RSASSA-PKCS1-v1_5` strategy.
 * This is the most commonly used keypair type.
 * @async
 * @param {string} [hash=SHA-256] (SHA-256, SHA-384, SHA-512)
 * The algorithm used to hash the keypair.
 * @param {number} [size] (2048, 3072, 4096)
 * The modulus length/size of the keypair.
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two crypto keys, called `publicKey`
 * and `privateKey`
 */
export async function createPKCS1Keypair (hash = 'SHA-256', size, usage) {
  return createKeypairBase(RSA(`RS${hash.replace(/[^0-9]+/gi, '')}`, size), usage)
}

/**
 * @function createPKCS1KeypairPEM
 * Create a keypair using the `RSASSA-PKCS1-v1_5` strategy.
 * The results will be PEM-encoded strings.
 * @async
 * @param {string} [hash=SHA-256] (SHA-256, SHA-384, SHA-512)
 * The algorithm used to hash the keypair.
 * @param {number} [size] (2048, 3072, 4096)
 * The modulus length/size of the keypair.
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two PEM-encoded values, called `publicKey`
 * and `privateKey`
 */
export async function createPKCS1KeypairPEM () {
  return await ToPEM(await createPKCS1Keypair(...arguments))
}

/**
 * @function createPSSKeypair
 * Create a keypair using the `RSA-PSS` strategy.
 * This is the most commonly used keypair type.
 * @async
 * @param {string} [hash=SHA-256] (SHA-256, SHA-384, SHA-512)
 * The algorithm used to hash the keypair.
 * @param {number} [size=2048] (2048, 3072, 4096)
 * The modulus length/size of the keypair.
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two crypto keys, called `publicKey`
 * and `privateKey`
 */
export async function createPSSKeypair (hash = 'SHA-256', size, usage) {
  return createKeypairBase(RSA(`PS${hash.replace(/[^0-9]+/gi, '')}`, size), usage)
}

/**
 * @function createPSSKeypairPEM
 * Create a keypair using the `RSA-PSS` strategy.
 * The results will be PEM-encoded strings.
 * @async
 * @param {string} [hash=SHA-256] (SHA-256, SHA-384, SHA-512)
 * The algorithm used to hash the keypair.
 * @param {number} [size=2048] (2048, 3072, 4096)
 * The modulus length/size of the keypair.
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two PEM-encoded values, called `publicKey`
 * and `privateKey`
 */
export async function createPSSKeypairPEM() {
  return await ToPEM(await createPSSKeypair(...arguments))
}
