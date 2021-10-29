import PEM from './pem.js'
import {
  bufToHex,
  hexToBuf,
  nodecrypto,
  cryptography,
  runtime
} from './common.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

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
 * @param {string} data
 * The data to sign.
 * @param {string} [algorithm]
 * The algorithm used to sign the content. By default, RSA keys
 * use a named format, `RSASSA-PKCS1-v1_5`. ECDSA keys use a named
 * curve, `P-256`, by default.
 *
 * In **Node.js _< v17.0.0_**, `SHA256` is always used for the algorithm.
 * @returns {string}
 * Returns the base64 signature.
 */
export async function sign (pem, data, algorithm) {
  if (runtime === 'node' && !cryptography) {
    const signer = nodecrypto.createSign('SHA256')
    signer.update(data)
    signer.end()

    const signature = signer.sign(pem)
    return bufToHex(signature)
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

  return bufToHex(buffer)
}

/**
 * Verify signed content.
 * @param {string} key
 * The verification key (typically a public key)
 * @param {string} signature
 * The signature to verify.
 * @param {string} data
 * The data to verify.
 * @param {string} [algorithm]
 * The algorithm used to sign the content. By default, RSA keys
 * use a named format, `RSASSA-PKCS1-v1_5`. ECDSA keys use a named
 * curve, `P-256`, by default.
 *
 * In **Node.js _< v17.0.0_**, `SHA256` is always used for the algorithm.
 * @returns {boolean}
 * Indicates the signature is valid.
 */
export async function verify (pem, signature, data, algorithm = 'RSASSA-PKCS1-v1_5') {
  if (runtime === 'node' && !cryptography) {
    const verifier = nodecrypto.createVerify('SHA256')
    verifier.update(data)
    verifier.end()
    return verifier.verify(pem, hexToBuf(signature))
  }

  algorithm = { name: PEM.getDefaultAlgorithm(pem, algorithm) }
  if (algorithm.name === 'ECDSA') {
    algorithm.hash = 'SHA-256'
  }

  const key = await PEM.extractKey(pem, algorithm)
  const verified = await cryptography.subtle.verify(
    algorithm,
    key,
    hexToBuf(signature),
    encoder.encode(data)
  )

  return verified
}

/**
 * Encrypts plaintext using AES-GCM with supplied secret/key, for decryption with decrypt().
 * If a PEM private key is supplied as the secret, RSA-OAEP is used instead of AES-GCM.
 * @param   {String} plaintext
 * Plaintext to be encrypted.
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @returns {String}
 * Encrypted ciphertext.
 * @example
 * `const ciphertext = await encrypt('my secret text', 'pw')`
 */
export async function encrypt (plaintext, secret) {
  if (PEM.isPrivateKey(secret)) {
    throw new Error('Encryption requires a public key (a private key was specified)')
  }

  if (runtime === 'node' && !cryptography) {
    if (PEM.isPublicKey(secret)) {
      const buffer = Buffer.from(plaintext, 'utf8')
      return nodecrypto.publicEncrypt(secret, buffer).toString('base64')
    }

    const iv = nodecrypto.randomBytes(16)
    const salt = nodecrypto.randomBytes(16)
    const cipher = nodecrypto.createCipheriv('aes-256-cbc', simpleKey(secret), iv)
    let encrypted = cipher.update(plaintext, 'utf-8', 'hex')
    encrypted += cipher.final('hex')

    return `${bufToHex(salt).replace(/-/g, '+').replace(/_/g, '/')}-${bufToHex(iv).replace(/-/g, '+').replace(/_/g, '/')}-${encrypted.replace(/-/g, '+').replace(/_/g, '/')}`
  }

  // If a PEM public key is specified, use it to encrypt the data
  if (PEM.isPublicKey(secret)) {
    const pemKey = await PEM.extractKey(secret, { name: 'RSA-OAEP', hash: 'SHA-256' })
    const ciphertext = await cryptography.subtle.encrypt({ name: 'RSA-OAEP' }, pemKey, encoder.encode(plaintext))

    return bufToHex(ciphertext)
  }

  const iv = cryptography.getRandomValues(new Uint8Array(16))
  const data = encoder.encode(plaintext)
  const { key, salt } = await Key(secret)
  const ciphertext = await cryptography.subtle.encrypt({ name: 'AES-CBC', iv }, key, data)

  return `${bufToHex(salt).replace(/-/g, '+').replace(/_/g, '/')}-${bufToHex(iv).replace(/-/g, '+').replace(/_/g, '/')}-${bufToHex(ciphertext).replace(/-/g, '+').replace(/_/g, '/')}`
}

/**
 * Decrypts ciphertext encrypted with encrypt() using the supplied secret/key.
 * If a PEM public key is supplied as the secret, RSA-OAEP is used instead of AES-GCM.
 * @param   {String} ciphertext
 * Ciphertext to be decrypted.
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @returns {String}
 * Decrypted plaintext.
 * @example
 * `const plaintext = await decrypt(ciphertext, 'pw')`
 */
export async function decrypt (cipher, secret) {
  if (PEM.isPublicKey(secret)) {
    throw new Error('Decryption requires a private key (a public key was specified)')
  }

  const [salt, iv, data] = cipher.split('-').map(hexToBuf)

  if (runtime === 'node' && !cryptography) {
    if (PEM.isPrivateKey(secret)) {
      const buffer = Buffer.from(cipher, 'base64')
      return nodecrypto.privateDecrypt({ key: secret }, buffer).toString('utf8')
    }

    const decipher = nodecrypto.createDecipheriv('aes-256-cbc', simpleKey(secret), iv)
    let decrypted = decipher.update(bufToHex(data), 'hex', 'utf-8')
    decrypted = decrypted + decipher.final('utf8')
    return decrypted.replace(/-/g, '+').replace(/_/g, '/')
  }

  // If a PEM private key is specified, use it to decrypt the cipher
  if (PEM.isPrivateKey(secret)) {
    const pemKey = await PEM.extractKey(secret, { name: 'RSA-OAEP' })
    const buffer = await cryptography.subtle.decrypt({ name: 'RSA-OAEP' }, pemKey, hexToBuf(cipher))
    const data = new Uint8Array(buffer)
    return decoder.decode(data)
  }

  const { key } = await Key(secret, salt)
  const result = await cryptography.subtle.decrypt({ name: 'AES-CBC', iv }, key, data)
  return decoder.decode(result).replace(/-/g, '+').replace(/_/g, '/')
}

/**
 * Encrypts JSON using AES-GCM with supplied secret/key, for decryption with decrypt().
 * If a PEM private key is supplied as the secret, RSA-OAEP is used instead of AES-GCM.
 * @param   {Object} data
 * Data object to be encrypted.
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @returns {String}
 * Encrypted ciphertext.
 */
export async function encryptJSON (obj, secret) {
  return await encrypt(JSON.stringify(obj), secret)
}

/**
 * Decrypts ciphertext encrypted with encryptJSON() using the supplied secret/key.
 * If a PEM public key is supplied as the secret, RSA-OAEP is used instead of AES-GCM.
 * @param   {String} ciphertext
 * Ciphertext to be decrypted.
 * @param   {String} secret
 * Secret or PEM key to encrypt plaintext.
 * @returns {Object}
 * Decrypted object.
 */
export async function decryptJSON (cipher, secret) {
  return JSON.parse(await decrypt(...arguments))
}

// Older Node.js only - the md5 hash produces 32 character hash from any
// encryption key. This is not designed to be a stored secret.
function simpleKey (secret) {
  return nodecrypto.createHash('md5').update(secret, 'utf-8').digest('hex')
}

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
  salt = salt || cryptography.getRandomValues(new Uint8Array(8))
  const raw = await cryptography.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey', 'deriveBits'])
  const key = await cryptography.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 10000, hash },
    raw,
    { name: 'AES-CBC', length: parseInt(hash.split('-').pop(), 10) },
    // { name: 'AES-GCM', length: parseInt(hash.split('-').pop(), 10) },
    false,
    ['encrypt', 'decrypt']
  )

  return { key, salt }
}

const crypto = {
  encrypt,
  decrypt,
  encryptJSON,
  decryptJSON,
  generateKeys,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  generateECKeyPair,
  PEM,
  sign,
  verify
}

// Expose crypto as a plugin
// NGN.crypto = all

export { crypto as default, PEM }
