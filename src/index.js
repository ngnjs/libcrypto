import PEM from './pem.js'
import {
  nodecrypto,
  cryptography,
  runtime
} from './common.js'
import {
  bufToBase64,
  base64ToBuf,
  createBase64Cipher
} from './encoding/base64.js'
import { HOTP, TOTP } from './otp.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()
const SALT_LENGTH = 16
const IV_LENGTH = runtime === 'deno' ? 16 : 12
const AUTH_TAG_LENGTH = 16
const ENCRYPTION_ALGORITHM = runtime === 'deno' ? 'AES-CBC' : 'AES-GCM'

/**
 * Generate a TLS public/private key pair using RSA.
 * Both keys are PEM formatted as `spki` (public) and
 * `pkcs8` (private) keys. This is the most common
 * form of keypair generation, but produces larger keys
 * than ECDSA keys.
 * @param {number} [bit=2048] (1024, 2048, 4096)
 * The bit length of the key. Standard is `2048`. For high
 * security, use `4096` (slower).
 * @param {string} [hash=SHA-256] (SHA-256, SHA-384, SHA-512)
 * The hashing algorithm used to generate keys.
 * @returns {Object}
 * The object returned contains two keys, both of which are in PEM format:
 * ```
 * {
 *   public: '-----BEGIN RSA PUBLIC KEY-----...'
 *   private: '-----BEGIN RSA PRIVATE KEY-----...'
 * }
 * ```
 */
export async function generateRSAKeyPair (bit = 2048, hash = 'SHA-256') {
  // In Node.js < 17, use Node crypto
  if (runtime === 'node' && !cryptography) {
    return new Promise((resolve, reject) => {
      nodecrypto.generateKeyPair('rsa', {
        modulusLength: bit,
        publicExponent: 0x10101,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }, (err, publicKey, privateKey) => {
        if (err) {
          reject(err)
        } else {
          resolve({ publicKey, privateKey })
        }
      })
    })
  }

  // All other runtimes
  return await generateKeyPair({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: bit,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash
  }, 'RSA')
}

/**
 * Generate public and private keys.
 * By default, this generates 2048-bit RSA keys using SHA-256.
 * @alias generateRSAKeyPair
 * @returns {Object}
 * The object returned contains two keys, both of which are in PEM format:
 * ```
 * {
 *   public: '-----BEGIN RSA PUBLIC KEY-----...'
 *   private: '-----BEGIN RSA PRIVATE KEY-----...'
 * }
 * ```
 */
export async function generateKeys () {
  return await generateRSAKeyPair(...arguments)
}

/**
 * Generate a TLS public/private key pair using ECDSA.
 * This uses the `P-256` named curve by default. Both keys are PEM
 * formatted as `spki` (public) and `pkcs8` (private) keys.
 * ECDSA provides the same encryption strength as RSA, but
 * with smaller keys.
 * @param {string} [namedCurve=P-256] (P-256, P-384, P-521)
 * The named curve to use.
 * @returns {Object}
 * The object returned contains two keys, both of which are in PEM format:
 * ```
 * {
 *   public: '-----BEGIN EC PUBLIC KEY-----...'
 *   private: '-----BEGIN EC PRIVATE KEY-----...'
 * }
 * ```
 */
export async function generateECDSAKeyPair (namedCurve = 'P-256') {
  // In Node.js < 17, use Node crypto
  if (runtime === 'node' && !cryptography) {
    return new Promise((resolve, reject) => {
      nodecrypto.generateKeyPair('ec', {
        namedCurve,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      }, (err, publicKey, privateKey) => {
        if (err) {
          reject(err)
        } else {
          resolve({ publicKey, privateKey })
        }
      })
    })
  }

  return await generateKeyPair({
    name: 'ECDSA',
    namedCurve
  }, 'EC')
}

/**
 * @alias generateECDSAKeyPair
 */
export async function generateECKeyPair () {
  return await generateECDSAKeyPair(...arguments)
}

/**
 * Sign content and return the signature.
 * @param {string} key
 * The signing key (typically a private key)
 * @param {string|object} data
 * The data to sign. Objects are automatically converted to strings
 * using `JSON.stringify()`.
 * @param {string} [algorithm]
 * The algorithm used to sign the content. By default, RSA keys
 * use a named format, `RSASSA-PKCS1-v1_5`. ECDSA keys use a named
 * curve, `P-256`, by default.
 *
 * In **Node.js _< v17.0.0_**, `SHA256` is always used for the algorithm.
 * @returns {string}
 * Returns the base64 signature.
 */
export async function sign (data, pem, algorithm) {
  // Autoconvert data object to string
  if (typeof data === 'object') {
    data = JSON.stringify(data)
  }

  if (runtime === 'node' && !cryptography) {
    const signer = nodecrypto.createSign('SHA256')
    signer.update(data)
    signer.end()

    return signer.sign(pem).toString('base64')
  }

  algorithm = { name: PEM.getDefaultAlgorithm(pem, algorithm) }
  if (algorithm.name === 'ECDSA') {
    algorithm.hash = 'SHA-256'
  }

  const key = await PEM.extractKey(pem, algorithm)
  const buffer = await cryptography.subtle.sign(
    algorithm,
    key,
    encoder.encode(data)
  )

  return bufToBase64(buffer)
}

/**
 * Verify signed content.
 * @param {string} key
 * The verification key (typically a public key)
 * @param {string} signature
 * The signature to verify.
 * @param {string} data
 * The data to verify. Objects are automatically converted to strings
 * using `JSON.stringify()`.
 * @param {string} [algorithm]
 * The algorithm used to sign the content. By default, RSA keys
 * use a named format, `RSASSA-PKCS1-v1_5`. ECDSA keys use a named
 * curve, `P-256`, by default.
 *
 * In **Node.js _< v17.0.0_**, `SHA256` is always used for the algorithm.
 * @returns {boolean}
 * Indicates the signature is valid.
 */
export async function verify (data, signature, pem, algorithm = 'RSASSA-PKCS1-v1_5') {
  // Autoconvert data object to string
  if (typeof data === 'object') {
    data = JSON.stringify(data)
  }

  if (runtime === 'node' && !cryptography) {
    const verifier = nodecrypto.createVerify('SHA256')
    verifier.update(data)
    verifier.end()

    return verifier.verify(pem, signature, 'base64')
  }

  algorithm = { name: PEM.getDefaultAlgorithm(pem, algorithm) }
  if (algorithm.name === 'ECDSA') {
    algorithm.hash = 'SHA-256'
  }

  const key = await PEM.extractKey(pem, algorithm)
  const verified = await cryptography.subtle.verify(
    algorithm,
    key,
    base64ToBuf(signature),
    encoder.encode(data)
  )

  return verified
}

/**
 * Encrypts plaintext using AES-GCM with supplied secret/key, for decryption with decrypt().
 * If a PEM private key is supplied as the secret, RSA-OAEP is used instead of AES-GCM.
 * @warning Some versions of Deno do not support AES-GCM. AES-CBC is used instead.
 * @param   {String|Object} plaintext
 * Plaintext to be encrypted. Objects are automatically converted to plaintext
 * using `JSON.stringify`.
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @returns {String}
 * Base64 encrypted cipher text.
 * @example
 * `const ciphertext = await encrypt('my secret text', 'pw')`
 */
export async function encrypt (plaintext, secret) {
  if (PEM.isPrivateKey(secret)) {
    throw new Error('Encryption requires a public key (a private key was specified)')
  }

  if (typeof plaintext === 'object') {
    plaintext = JSON.stringify(plaintext)
  }

  if (runtime === 'node' && !cryptography) {
    if (PEM.isPublicKey(secret)) {
      const buffer = Buffer.from(plaintext, 'utf8')
      return nodecrypto.publicEncrypt({
        key: secret,
        padding: nodecrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, buffer).toString('base64')
    }

    const iv = nodecrypto.randomBytes(IV_LENGTH)
    const salt = nodecrypto.randomBytes(SALT_LENGTH)
    const cipher = nodecrypto.createCipheriv('aes-256-gcm', simpleKey(secret), iv, { authTagLength: AUTH_TAG_LENGTH })
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
    const tag = cipher.getAuthTag()

    return Buffer.concat([salt, iv, tag, encrypted]).toString('base64')
    // return createBase64Cipher(salt, iv, encrypted, tag)
  }

  // If a PEM public key is specified, use it to encrypt the data
  if (PEM.isPublicKey(secret)) {
    const pemKey = await PEM.extractKey(secret, { name: 'RSA-OAEP', hash: 'SHA-256' })
    const ciphertext = await cryptography.subtle.encrypt({ name: 'RSA-OAEP' }, pemKey, encoder.encode(plaintext))

    return bufToBase64(ciphertext)
  }

  const iv = cryptography.getRandomValues(new Uint8Array(IV_LENGTH))
  const data = encoder.encode(plaintext)
  const { key, salt } = await Key(secret)
  const ciphertext = await cryptography.subtle.encrypt({ name: ENCRYPTION_ALGORITHM, iv }, key, data)

  return createBase64Cipher(salt, iv, ciphertext)
}

/**
 * Decrypts ciphertext encrypted with encrypt() using the supplied secret/key.
 * If a PEM public key is supplied as the secret, RSA-OAEP is used instead of AES-GCM.
 * @warning Some versions of Deno do not support AES-GCM. AES-CBC is used instead.
 * @param   {String} ciphertext
 * Base64 ciphertext to be decrypted.
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @param   {Boolean} [autoparse=true]
 * Automatically parse JSON strings into objects.
 * @returns {String}
 * Decrypted plaintext.
 * @example
 * `const plaintext = await decrypt(ciphertext, 'pw')`
 */
export async function decrypt (cipher, secret, autoparse = true) {
  if (PEM.isPublicKey(secret)) {
    throw new Error('Decryption requires a private key (a public key was specified)')
  }

  const useNode = runtime === 'node' && !cryptography
  const isPrivateKey = PEM.isPrivateKey(secret)
  const encrypted = useNode && !isPrivateKey ? Buffer.from(cipher, 'base64') : base64ToBuf(cipher)
  const salt = encrypted.slice(0, SALT_LENGTH)
  const iv = encrypted.slice(salt.byteLength, salt.byteLength + IV_LENGTH)
  const tag = useNode && !isPrivateKey ? encrypted.slice(salt.byteLength + iv.byteLength, salt.byteLength + iv.byteLength + AUTH_TAG_LENGTH) : null
  const data = encrypted.slice(salt.byteLength + iv.byteLength + (tag ? tag.byteLength : 0))

  if (useNode) {
    if (isPrivateKey) {
      const buffer = Buffer.from(cipher, 'base64')
      return parse(nodecrypto.privateDecrypt({
        key: secret,
        padding: nodecrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, buffer).toString('utf8'), autoparse)
    }

    const decipher = nodecrypto.createDecipheriv('aes-256-gcm', simpleKey(secret), iv, { authTagLength: AUTH_TAG_LENGTH })
    decipher.setAuthTag(tag)

    const decrypted = decipher.update(data, 'base64', 'utf-8') + decipher.final('utf-8')

    return parse(decrypted, autoparse)
  }

  // If a PEM private key is specified, use it to decrypt the cipher
  if (PEM.isPrivateKey(secret)) {
    const pemKey = await PEM.extractKey(secret, { name: 'RSA-OAEP' })
    const buffer = await cryptography.subtle.decrypt({ name: 'RSA-OAEP' }, pemKey, base64ToBuf(cipher))
    const data = new Uint8Array(buffer)
    return parse(decoder.decode(data), autoparse)
  }

  const { key } = await Key(secret, salt)
  const decrypted = await cryptography.subtle.decrypt({ name: ENCRYPTION_ALGORITHM, iv }, key, data).catch(e => console.log(`e: ${e.message}`))

  return parse(decoder.decode(decrypted), autoparse)
}

function parse (content, autoparse = true) {
  if (!autoparse) {
    return content
  }

  try {
    return JSON.parse(content)
  } catch (e) {
    return content
  }
}

/**
 * Identify the encoding type of a secret/key
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @returns {String}
 * Returns the encryption hash type, such as `rsa256oaep` or `aes256cbc`.
 */
export const encryptionAlgorithm = secret => PEM.isKey(secret) ? 'rsa256oaep' : ENCRYPTION_ALGORITHM.toLowerCase().replace('-', '256')

// Older Node.js only - the md5 hash produces a 32 character hash from any
// encryption key. This is not designed to be a stored secret.
const simpleKey = secret => nodecrypto.createHash('md5').update(secret, 'utf8').digest('hex')

async function generateKeyPair (algorithm, type = '') {
  const keypair = await cryptography.subtle.generateKey(
    algorithm,
    true,
    ['sign', 'verify']
  )

  const privateKey = await PEM.encodePrivateKey(keypair.privateKey, type)
  const publicKey = await PEM.encodePublicKey(keypair.publicKey, type)

  return { privateKey, publicKey }
}

async function Key (passphrase, salt, hash = 'SHA-256') {
  salt = salt || cryptography.getRandomValues(new Uint8Array(SALT_LENGTH))
  const secret = await cryptography.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey', 'deriveBits'])
  const key = await cryptography.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 10000, hash },
    secret,
    { name: ENCRYPTION_ALGORITHM, length: parseInt(hash.split('-').pop(), 10) },
    false,
    ['encrypt', 'decrypt']
  )

  return { key, salt }
}

const crypto = {
  encrypt,
  decrypt,
  encryptionAlgorithm,
  generateKeys,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  generateECKeyPair,
  PEM,
  sign,
  verify,
  HOTP,
  TOTP
}

export {
  crypto as default,
  PEM,
  HOTP,
  TOTP
}
