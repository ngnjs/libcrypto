import { ECDH_ALGORITHMS, normalize } from "../lib/algorithms.js"

/**
 * Create ECDH keypairs
 * @module ECDH
 */

export async function createKeypair (algorithm = 'EC256') {
  algorithm = normalize(algorithm, ECDH_ALGORITHMS)

  return await crypto.subtle.generateKey(
    algorithm,
    true,
    ['encrypt', 'decrypt']
  )
}
