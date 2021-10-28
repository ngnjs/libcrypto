import Reference from '@ngnjs/plugin'

const NGN = new Reference()
const encoder = new TextEncoder()
const decoder = new TextDecoder()
const BTOA = globalThis.btoa || function (v) { return Buffer.from(v, 'binary').toString('base64') }
const {runtime} = NGN

let nodecrypto // For Node.js only
let cryptography = null
if (runtime === 'node') {
  ;(async () => {
    nodecrypto = await import('crypto')
    try {
      cryptography = nodecrypto.webcrypto
    } catch (e) {}
  })()
} else {
  cryptography = globalThis.crypto
}

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
  if (NGN.runtime === 'node' && !cryptography) {
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
  if (NGN.runtime === 'node' && !cryptography) {
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
 * Attempts to determine whether a key was created using RSA or
 * ECDSA (Elliptic Curve).
 * @param {string} pem
 * The public or private key, in PEM format.
 * @returns {string}
 * Returns `RSA` or `EC`. Returns `null` if type cannot be determined.
 */
export function getPEMType (pem) {
  if (/-{5}(BEGIN RSA.+)-{5}/.test(pem)) {
    return 'RSA'
  } else if (/-{5}(BEGIN EC.+)-{5}/.test(pem)) {
    return 'EC'
  } else if (!/-{5}(BEGIN.+KEY)-{5}/.test(pem)) {
    return null
  }

  // Public RSA keys are approximately 451 characters long
  // Private RSA keys are approximately 1704 characters long
  // EC keys are all less than 400 characters long
  if (pem.length > 425) {
    return 'RSA'
  }

  return 'EC'
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
  if (NGN.runtime === 'node' && !cryptography) {
    const signer = nodecrypto.createSign('SHA256')
    signer.update(data)
    signer.end()

    const signature = signer.sign(pem)
    return bufToHex(signature)
  }

  algorithm = { name: getDefaultAlgorithm(pem, algorithm) }
  if (algorithm.name === 'ECDSA') {
    algorithm.hash = 'SHA-256'
  }

  const key = await extractKey(pem, algorithm)
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
  if (NGN.runtime === 'node' && !cryptography) {
    const verifier = nodecrypto.createVerify('SHA256')
    verifier.update(data)
    verifier.end()
    return verifier.verify(pem, hexToBuf(signature))
  }

  algorithm = { name: getDefaultAlgorithm(pem, algorithm) }
  if (algorithm.name === 'ECDSA') {
    algorithm.hash = 'SHA-256'
  }

  const key = await extractKey(pem, algorithm)
  const verified = await cryptography.subtle.verify(
    algorithm,
    key,
    hexToBuf(signature),
    encoder.encode(data)
  ).catch(e => console.log(e.message))

  return verified
}

/**
 * @method encrypt
 * Encrypts plaintext using AES-GCM with supplied password, for decryption with aesGcmDecrypt().
 * @param   {String} plaintext
 * Plaintext to be encrypted.
 * @param   {String} password
 * Password to use to encrypt plaintext.
 * @returns {String}
 * Encrypted ciphertext.
 * @example
 * `const ciphertext = await encrypt('my secret text', 'pw')`
 */
export async function encrypt(plaintext, secret) {
  if (NGN.runtime === 'node' && !cryptography) {
    while (secret.length < 32) { secret += '0' }
    const iv = nodecrypto.randomBytes(16)
    const salt = nodecrypto.randomBytes(16)
    const cipher = nodecrypto.createCipheriv('aes-256-cbc', secret, iv)
    let encrypted = cipher.update(plaintext, 'utf-8', 'hex')
    encrypted += cipher.final('hex')
    return `${bufToHex(salt).replace(/\-/g, '+').replace(/_/g, '\/')}-${bufToHex(iv).replace(/\-/g, '+').replace(/_/g, '\/')}-${encrypted.replace(/\-/g, '+').replace(/_/g, '\/')}`
  }

  const iv = cryptography.getRandomValues(new Uint8Array(16))
  const data = encoder.encode(plaintext)
  const { key, salt } = await Key(secret)
  const ciphertext = await cryptography.subtle.encrypt({ name: 'AES-CBC', iv }, key, data).catch(e => console.log(e.message))
  return `${bufToHex(salt).replace(/\-/g, '+').replace(/_/g, '\/')}-${bufToHex(iv).replace(/\-/g, '+').replace(/_/g, '\/')}-${bufToHex(ciphertext).replace(/\-/g, '+').replace(/_/g, '\/')}`
}

/**
 * @method decrypt
 * Decrypts ciphertext encrypted with aesGcmEncrypt() using supplied password.
 * @param   {String} ciphertext
 * Ciphertext to be decrypted.
 * @param   {String} password
 * Password to use to decrypt ciphertext.
 * @returns {String}
 * Decrypted plaintext.
 * @example
 * `const plaintext = await decrypt(ciphertext, 'pw')`
 */
export async function decrypt(cipher, secret) {
  const [salt, iv, data] = cipher.split('-').map(hexToBuf)

  if (NGN.runtime === 'node' && !cryptography) {
    while (secret.length < 32) { secret += '0' }
    const decipher = nodecrypto.createDecipheriv('aes-256-cbc', secret, iv)
    let decrypted = decipher.update(bufToHex(data), 'hex', 'utf-8')
    decrypted = decrypted + decipher.final('utf8')
    return decrypted.replace(/\-/g, '+').replace(/_/g, '\/')
  }

  const { key } = await Key(secret, salt)
  const result = await cryptography.subtle.decrypt({ name: 'AES-CBC', iv }, key, data)
  return decoder.decode(result).replace(/\-/g, '+').replace(/_/g, '\/')
}

async function generateKeyPair (algorithm, type = '') {
  const keypair = await cryptography.subtle.generateKey(
    algorithm,
    true,
    ['sign', 'verify']
  )

  const privateKey = await pemEncodedPrivateKey(keypair.privateKey, type)
  const publicKey = await pemEncodedPublicKey(keypair.publicKey, type)

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

async function extractKey (pem, algorithm) {
  const pemtype = getPEMType(pem)

  // Use the specified algorithm or appropriate defaults for RSA/ECDSA
  return pemtype === 'RSA'
    ? await importStringAsRSAKey(pem, getDefaultAlgorithm(pem, algorithm, pemtype).name)
    : await importStringAsECDSAKey(pem)
}

function getDefaultAlgorithm (pem, algorithm, pemtype) {
  if (algorithm) {
    return algorithm
  }

  pemtype = pemtype || getPEMType(pem)

  return pemtype === 'RSA' ? 'RSASSA-PKCS1-v1_5' : 'P-256'
}

function bufToHex (buffer) {
  return Array.prototype.slice
    .call(new Uint8Array(buffer))
    .map(x => [x >> 4, x & 15])
    .map(ab => ab.map(x => x.toString(16)).join(''))
    .join('')
}

function hexToBuf (str) {
  return new Uint8Array(str.match(/.{2}/g).map(byte => parseInt(byte, 16)))
}

function arrayBufferToString (buffer) {
  return String.fromCharCode.apply(null, new Uint8Array(buffer))
}

function stringToArrayBuffer (str) {
  const buf = new ArrayBuffer(str.length)
  const bufView = new Uint8Array(buf)
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

function pemEncode (label, data, type = '') {
  const base64encoded = BTOA(data)
  const base64encodedWrapped = base64encoded.replace(/(.{64})/g, '$1\n')

  label = (type.length > 0 ? type.trim().toUpperCase() + ' ' : '') + label
  return `-----BEGIN ${label}-----\n${base64encodedWrapped}\n-----END ${label}-----`
}

function pemDecode (key) {
  const pem = key.replace(/(-{5}([A-Za-z\s]+)KEY-{5})/gi, '').trim()
  const binaryDerString = globalThis.atob(pem)

  return stringToArrayBuffer(binaryDerString)
}

async function pemEncodedPrivateKey (key, type = '') {
  return pemEncode('PRIVATE KEY', await exportKeyAsString('pkcs8', key), type)
}

async function pemEncodedPublicKey (key, type = '') {
  return pemEncode('PUBLIC KEY', await exportKeyAsString('spki', key), type)
}

async function exportKeyAsString (format, key) {
  return arrayBufferToString(await cryptography.subtle.exportKey(format, key))
}

async function importStringAsRSAKey (pem, algorithm = 'RSASSA-PKCS1-v1_5', hash = 'SHA-256') {
  return importStringAsKey(pem, typeof algorithm === 'object' ? algorithm : { name: algorithm, hash })
}

async function importStringAsECDSAKey (pem, namedCurve = 'P-256') {
  return importStringAsKey(pem, { name: 'ECDSA', namedCurve })
}

async function importStringAsKey (pem, algorithm) {
  const encoding = pem.indexOf('PRIVATE KEY') > 0 ? 'pkcs8' : 'spki'

  // Attempt to import the string as a signing key.
  // If that fails, import as a verification key.
  const key = await cryptography.subtle.importKey(
    encoding,
    pemDecode(pem),
    algorithm,
    true,
    [encoding === 'pkcs8' ? 'sign' : 'verify']
  ).catch(e => console.log(e.message))

  return key
}

const all = {
  encrypt,
  decrypt,
  generateKeys,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  generateECKeyPair,
  getPEMType,
  sign,
  verify
}

export { all as default }
