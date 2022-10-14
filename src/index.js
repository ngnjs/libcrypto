import * as PEM from './encoding/pem.js'
import * as Base64 from './encoding/base64.js'
import * as Base32 from './encoding/base32.js'
import * as RSA from './keys/rsa.js'
import * as ECDSA from './keys/ecdsa.js'
import * as OTP from './otp/otp.js'
// import * as JWT from './jwt/token.js'
// import * as ECDH from './keys/ecdh.js'
import * as HMAC from './keys/hmac.js'
import {
  normalize,
  ABBREVIATIONS,
  AES_ALGORITHMS,
  DERIVE_ALGORITHMS,
  ENCRYPTION_ALGORITHMS,
  RSA_OAEP_ALGORITHMS,
  SALT_LENGTH,
  SIGNING_ALGORITHMS,
  // ECDH_ALGORITHMS
} from './lib/algorithms.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/**
 * Create a common keypair using the `ECDSA P-256 (ES256)` strategy.
 * This is the most commonly used keypair type.
 * @async
 * @param {string} [algorithm=S256]
 * The named algorithm to use when generating the keypairs
 * - `RS256` RSASSA-PKCS1-v1_5 SHA-256 2048 bit keys
 * - `RS384` RSASSA-PKCS1-v1_5 SHA-384 3072 bit keys
 * - `RS512` RSASSA-PKCS1-v1_5 SHA-512 4096 bit keys
 * - `PS256` RSA-PSS SHA-256 2048 bit keys
 * - `PS384` RSA-PSS SHA-384 3072 bit keys
 * - `PS512` RSA-PSS SHA-512 4096 bit keys
 * - `ES256` ECDSA P-256 keys
 * - `ES384` ECDSA P-384 keys
 * - `ES512` ECDSA P-512 keys (not supported in Deno)
 * @param {string[]} [usage=['sign', 'verify']]
 * The privileges assigned to the keypair.
 * @returns {Object}
 * Returns an object with two crypto keys, called `publicKey`
 * and `privateKey`
 */
export async function createKeypair (algorithm = 'ES256', usage = ['sign', 'verify']) {
  algorithm = normalize(algorithm, SIGNING_ALGORITHMS)

  if (algorithm.name === 'ECDSA') {
    return ECDSA.createKeypair(algorithm, usage)
  }

  return RSA.createKeypair(algorithm, usage)
}

/**
 * Create a keypair using the `RSASSA-PKCS1-v1_5` strategy.
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
export async function createKeypairPEM () {
  return await PEM.ToPEM(await createKeypair(...arguments))
}

/**
 * @param {string} [algorithm=OAEP256]
 * The named algorithm used to produce asymmetric encryption/decryption keys.
 * - `OAEP256` RSA-OAEP SHA-256 2048-bit
 * - `OAEP384` RSA-OAEP SHA-384 3072-bit
 * - `OAEP512` RSA-OAEP SHA-512 4096-bit
 * @returns {Object}
 * Returns an object with two PEM-encoded keys: `encryptionKey` and `decryptionKey`.
 * The encryption key is a public key while the decryption key is a private key.
 */
export async function createEncryptionKeypair (algorithm = 'OAEP256') {
  algorithm = normalize(algorithm, Object.assign({}, RSA_OAEP_ALGORITHMS/*, ECDH_ALGORITHMS*/))

  let keypair
  if (algorithm.name === 'RSA-OAEP') {
    keypair = await createKeypairPEM(algorithm, ['encrypt', 'decrypt'])
  // } else {
  //   keypair = await createKeypairPEM(algorithm, ['deriveKey', 'deriveBits'])
  //   return {
  //     encryptionKey: keypair.privateKey,
  //     decryptionKey: keypair.publicKey
  //   }
  }

  return {
    encryptionKey: keypair.publicKey,
    decryptionKey: keypair.privateKey
  }
}

/**
 * Create a signing/verification keypair.
 * @param {string} [algorithm=ES256]
 * The named algorithm used to produce the keypair.
 * - `RS256` RSASSA-PKCS1-v1_5 SHA-256 2048 bit keys
 * - `RS384` RSASSA-PKCS1-v1_5 SHA-384 3072 bit keys
 * - `RS512` RSASSA-PKCS1-v1_5 SHA-512 4096 bit keys
 * - `PS256` RSA-PSS SHA-256 2048 bit keys
 * - `PS384` RSA-PSS SHA-384 3072 bit keys
 * - `PS512` RSA-PSS SHA-512 4096 bit keys
 * - `ES256` ECDSA P-256 keys
 * - `ES384` ECDSA P-384 keys
 * - `ES512` ECDSA P-512 keys (not supported in Deno)
 * @param {string} [secret]
 * A (required) password for HMAC (HS256, HS384, HS512) keys.
 * Optional for all other algorithms.
 * @returns {object}
 * Returns an object with two PEM-encoded values, called `signingKey`
 * (private key) and `verificationKey` (public key).
 * The HMAC algorithm uses a shared secret. As such, both
 * keys are the same.
 */
export async function createSigningKeypair (algorithm = 'ES256', secret) {
  algorithm = normalize(algorithm, SIGNING_ALGORITHMS)

  if (algorithm.name === 'HMAC') {
    if (!secret) {
      throw new Error('HMAC keys require a secret')
    }

    const key = await HMAC.createKeyPEM(secret, algorithm)
    return {
      verificationKey: key,
      signingKey: key
    }
  }

  const { privateKey, publicKey } = await createKeypairPEM(algorithm, ['sign', 'verify'])
  return {
    verificationKey: publicKey,
    signingKey: privateKey
  }
}

/**
 * Sign content and return the signature.
 * @param {CryptoKey|string} key
 * The signing key (typically a private key). This can
 * be a CryptoKey or PEM-encoded string.
 * @param {string|object} data
 * The data to sign. Objects are automatically converted to strings
 * using `JSON.stringify()`.
 * @param {string} [algorithm]
 * The algorithm used to sign the content. If no algorithm is
 * defined, an attempt will be made to identify the algorithm
 * from the signing key. Falls back to `ES256` if no other
 * algorithm is detected.
 * - `HS256` HMAC SHA-256 keys
 * - `HS384` HMAC SHA-384 keys
 * - `HS512` HMAC SHA-512 keys
 * - `RS256` RSASSA-PKCS1-v1_5 SHA-256 2048 bit keys
 * - `RS384` RSASSA-PKCS1-v1_5 SHA-384 3072 bit keys
 * - `RS512` RSASSA-PKCS1-v1_5 SHA-512 4096 bit keys
 * - `PS256` RSA-PSS SHA-256 2048 bit keys
 * - `PS384` RSA-PSS SHA-384 3072 bit keys
 * - `PS512` RSA-PSS SHA-512 4096 bit keys
 * - `ES256` ECDSA P-256 keys
 * - `ES384` ECDSA P-384 keys
 * - `ES512` ECDSA P-512 keys (not supported in Deno)
 * @returns {string}
 * Returns the Base64 signature.
 */
export async function sign (data, key, algorithm) {
  if (!algorithm) {
    const keyparts = PEM.info(key)
    algorithm = `${ABBREVIATIONS[keyparts.algorithm]}256`
  }

  algorithm = normalize(algorithm)
  key = await PEM.normalizeKey(key, algorithm, ['sign'])
  data = normalizeData(data)

  delete algorithm.publicExponent
  delete algorithm.modulusLength
  if (algorithm.name === 'RSA-PSS') {
    algorithm.saltLength = 32
  }

  const buffer = await crypto.subtle.sign(
    algorithm,
    key,
    encoder.encode(data)
  )

  return Base64.ArrayBufferToBase64(buffer)
}

/**
 * Verify content with the provided signature.
 * @param {string|object} data
 * The data to verify.
 * @param {string} signature
 * The signature to verify the data with.
 * @param {string|CryptoKey} key
 * A PEM-encoded public (or shared secret) string or CryptoKey object.
 * @param {string} [algorithm=ES256]
 * The key algorithm. If this is not supplied, an _attempt_
 * will be made to autodetect the algorithm. Defaults to
 * `ES256` when an algorithm cannot be detected.
 * @returns
 */
export async function verify (data, signature, key, algorithm = 'ES256') {
  algorithm = normalize(algorithm)
  data = normalizeData(data)
  key = await PEM.normalizeKey(key, algorithm, ['verify'])

  if (key.type !== 'public' && key.type !== 'secret') {
    throw new Error(`invalid key - must use a public or secret key, not ${key.type}`)
  }

  return await crypto.subtle.verify(
    algorithm,
    key,
    Base64.Base64ToArrayBuffer(signature),
    encoder.encode(data)
  )
}

/**
 * Encrypt text or objects.
 * @param {string|object} plaintext
 * The text or object to encrypt. Since objects cannot be encrypted, they
 * are automatically serialized to a string before encrypting.
 * @param {string|CryptoKey} [passphrase]
 * For shared-key encryption (i.e. "password-based"), a text-based password can be
 * used to encrypt the plaintext. Alternatively, a valid RSA-OAEP CryptoKey can
 * be supplied to encrypt the plaintext. This function also accepts PEM-encoded
 * RSA-OAEP public keys (text), which are automatically converted into a CryptoKey.
 * @param {string} [encryptionAlgorithm]
 * The named algorithm will be used to encrypt data. By default, this will be
 * `RS256` (RSA-OAEP SHA-256) for PEM-encoded keys or `GCM256` (AES-GCM 256-bit)
 * for shared key (password-based) encryption. Valid options include:
 * **_Asymmetric Key Encryption (Recommended)_**:
 * - `RS256` RSA-OAEP SHA-256 2048-bit (default for asymmetric encryption)
 * - `RS384` RSA-OAEP SHA-384 3072-bit
 * - `RS512` RSA-OAEP SHA-512 4096-bit
 *
 * **_Shared Key Encryption_**:
 * - `GCM128` AES-GCM 128-bit (12 character IV)
 * - `GCM192` AES-GCM 192-bit (12 character IV)
 * - `GCM256` AES-GCM 256-bit (12 character IV) (default for shared-key encryption)
 * - `CBC128` AES-CBC 128-bit (16 character IV)
 * - `CBC192` AES-CBC 192-bit (16 character IV)
 * - `CBC256` AES-CBC 256-bit (16 character IV)
 * - `CTR128` AES-CTR 128-bit (16 character counter)
 * @param {string} [derivationAlgorithm=PB256]
 * _For shared-key encryption only._ When encrypting/decrypting, a key is
 * automatically derived from the shared key. The algorithm used for this
 * can be defined. This usually doesn't need to be configred. Options include:
 * - `PB256` PBKDF2 SHA-256 with 10000 iterations (default/recommended)
 * - `PB384` PBKDF2 SHA-384 with 10000 iterations
 * - `PB512` PBKDF2 SHA-512 with 10000 iterations
 * @returns {string}
 * The Base64-encoded hash.
 */
export async function encrypt (plaintext, passphrase, encryptionAlgorithm, derivationAlgorithm = 'PB256') {
  if (typeof plaintext === 'object') {
    plaintext = JSON.stringify(plaintext)
  }

  let key

  // If a PEM certificate is provided, use it to encrypt plaintext
  if (PEM.PEM_PATTERN.test(passphrase)) {
    const keyinfo = PEM.info(passphrase)
    encryptionAlgorithm = normalize(encryptionAlgorithm || (keyinfo.algorithm === 'ECDH' ? 'EC256' : 'OAEP256'), Object.assign({}, RSA_OAEP_ALGORITHMS/*, ECDH_ALGORITHMS*/))

    if (encryptionAlgorithm.name === 'RSA-OAEP') {
      key = await PEM.normalizeKey(passphrase, encryptionAlgorithm, ['encrypt'])
    // } else {
    //   key = await PEM.normalizeKey(passphrase, encryptionAlgorithm)
    }

    if (key.type === 'private'/* && encryptionAlgorithm.name !== 'ECDH'*/) {
      throw new Error('encryption requires a public key')
    }

    const ciphertext = await crypto.subtle.encrypt(encryptionAlgorithm, key, encoder.encode(plaintext))

    return Base64.ArrayBufferToBase64(ciphertext)
  } else {
    encryptionAlgorithm = normalize(encryptionAlgorithm || 'GCM256', AES_ALGORITHMS)
    const { iv } = encryptionAlgorithm
    const result = await Key(passphrase, null, Object.assign({}, encryptionAlgorithm, { iv }), derivationAlgorithm)
    const { key, salt } = result
    const { counter } = result.encryptionAlgorithm
    const algorithm = Object.assign({}, result.encryptionAlgorithm, { iv, counter })
    const ciphertext = await crypto.subtle.encrypt(algorithm, key, encoder.encode(plaintext))

    return Base64.createBase64Cipher(salt, iv || counter, ciphertext)
  }
}

export async function decrypt (cipher, passphrase, encryptionAlgorithm, derivationAlgorithm = 'PB256', autoparse = true) {
  const encrypted = Base64.Base64ToArrayBuffer(cipher)

  let result
  if (PEM.PEM_PATTERN.test(passphrase)) {
    encryptionAlgorithm = normalize(encryptionAlgorithm || 'OAEP256', RSA_OAEP_ALGORITHMS, ['decrypt'])
    const key = await PEM.normalizeKey(passphrase, encryptionAlgorithm, ['decrypt'])
    const buffer = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, encrypted)
    result = new Uint8Array(buffer)
  } else {
    encryptionAlgorithm = normalize(encryptionAlgorithm || 'GCM256', AES_ALGORITHMS)
    derivationAlgorithm = normalize(derivationAlgorithm, DERIVE_ALGORITHMS)

    const salt = encrypted.slice(0, SALT_LENGTH)
    const iv = encrypted.slice(salt.byteLength, salt.byteLength + (encryptionAlgorithm?.iv || encryptionAlgorithm?.counter).length)
    const data = encrypted.slice(salt.byteLength + iv.byteLength)
    const keydata = await Key(passphrase, salt, Object.assign({}, encryptionAlgorithm, { iv }), derivationAlgorithm)
    const algorithm = Object.assign({}, keydata.encryptionAlgorithm, { iv, counter: iv })

    result = await crypto.subtle.decrypt(
      algorithm,
      keydata.key,
      data
    )
  }

  result = decoder.decode(result)

  if (autoparse) {
    try {
      return JSON.parse(result)
    } catch (e) { }
  }

  return result
}

async function Key (passphrase, salt, encryptionAlgorithm = 'GCM256', derivationAlgorithm = 'PB256') {
  derivationAlgorithm = normalize(derivationAlgorithm, DERIVE_ALGORITHMS)
  encryptionAlgorithm = normalize(encryptionAlgorithm, ENCRYPTION_ALGORITHMS)
  salt = salt || crypto.getRandomValues(new Uint8Array(SALT_LENGTH))

  derivationAlgorithm.salt = salt

  const secret = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    derivationAlgorithm,
    false,
    ['deriveKey', 'deriveBits']
  )

  const key = await crypto.subtle.deriveKey(
    derivationAlgorithm,
    secret,
    encryptionAlgorithm,
    false,
    ['encrypt', 'decrypt']
  )

  return { key, salt, encryptionAlgorithm, derivationAlgorithm }
}

function normalizeData(data) {
  switch (typeof data) {
    // Autoconvert data object to string
    case 'object':
      return JSON.stringify(data)
    default:
      return data
  }
}

const { HOTP, TOTP } = OTP

export {
  RSA,
  ECDSA,
  // ECDH,
  HMAC,
  PEM,
  Base64,
  Base32,
  OTP,
  HOTP,
  TOTP,
  // JWT
}
