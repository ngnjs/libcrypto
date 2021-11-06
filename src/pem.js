import {
  arrayBufferToString,
  stringToArrayBuffer,
  BTOA,
  cryptography
} from './common.js'

const PEM_KEY_PATTERN = /-{5}(BEGIN\s.+\s?KEY)-{5}.+-{5}(END\s.+\s?KEY)-{5}/i
const PEM_PUBLIC_KEY_PATTERN = /-{5}(BEGIN\s((RSA|EC)\s)?PUBLIC\sKEY)-{5}/i
const PEM_PRIVATE_KEY_PATTERN = /-{5}(BEGIN\s((RSA|EC)\s)?PRIVATE\sKEY)-{5}/i

export const isPrivateKey = pem => PEM_PRIVATE_KEY_PATTERN.test(pem)
export const isPublicKey = pem => PEM_PUBLIC_KEY_PATTERN.test(pem)
export const isKey = pem => PEM_KEY_PATTERN.test(pem)

/**
 * Attempts to determine whether a key was created using RSA or
 * ECDSA (Elliptic Curve).
 * @param {string} pem
 * The public or private key, in PEM format.
 * @returns {string}
 * Returns `RSA` or `EC`. Returns `null` if type cannot be determined.
 */
export const typeOf = pem => {
  if (/-{5}(BEGIN (ENCRYPTED\s)?RSA.+)-{5}/.test(pem)) {
    return 'RSA'
  } else if (/-{5}(BEGIN (ENCRYPTED\s)?EC.+)-{5}/.test(pem)) {
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

export const extractKey = async (pem, algorithm) => {
  const pemtype = typeOf(pem)

  // Use the specified algorithm or appropriate defaults for RSA/ECDSA
  return pemtype === 'RSA'
    ? await importStringAsRSAKey(pem, getDefaultAlgorithm(pem, algorithm, pemtype).name)
    : await importStringAsECDSAKey(pem)
}

export const encode = (label, data, type = '') => {
  const base64encoded = BTOA(data)
  const base64encodedWrapped = base64encoded.replace(/(.{64})/g, '$1\n')

  label = (type.length > 0 ? type.trim().toUpperCase() + ' ' : '') + label
  return `-----BEGIN ${label}-----\n${base64encodedWrapped}\n-----END ${label}-----`
}

export const decode = key => {
  const pem = key.replace(/(-{5}([A-Za-z\s]+)KEY-{5})/gi, '').trim()
  // binaryDerString = globalThis.atob(pem)
  return stringToArrayBuffer(globalThis.atob(pem))
}

export const encodePrivateKey = async (key, type = '') => encode('PRIVATE KEY', await exportKeyAsString('pkcs8', key), type)
export const encodePublicKey = async (key, type = '') => encode('PUBLIC KEY', await exportKeyAsString('spki', key), type)

async function exportKeyAsString (format, key) {
  return arrayBufferToString(await cryptography.subtle.exportKey(format, key))
}

async function importStringAsRSAKey (pem, algorithm = 'RSASSA-PKCS1-v1_5', hash = 'SHA-256') {
  algorithm = typeof algorithm === 'object' ? algorithm : { name: algorithm, hash }
  return importStringAsKey(pem, algorithm)
}

const importStringAsECDSAKey = async (pem, namedCurve = 'P-256') => importStringAsKey(pem, { name: 'ECDSA', namedCurve })

async function importStringAsKey (pem, algorithm) {
  const privateKey = isPrivateKey(pem)
  const encoding = privateKey ? 'pkcs8' : 'spki'
  const usage = []

  // RSA-OAEP keys are used for encryption/decryption.
  // All other keys are used for signing/verifying content.
  if (algorithm.name === 'RSA-OAEP') {
    usage.push(privateKey ? 'decrypt' : 'encrypt')
  } else {
    usage.push(privateKey ? 'sign' : 'verify')
  }

  // Attempt to import the string as a signing key.
  // If that fails, import as a verification key.
  return await cryptography.subtle.importKey(
    encoding,
    decode(pem),
    algorithm,
    true,
    usage
  )
}

export function getDefaultAlgorithm (pem, algorithm, pemtype) {
  if (algorithm) {
    return algorithm
  }

  pemtype = pemtype || typeOf(pem)

  return pemtype === 'RSA' ? 'RSASSA-PKCS1-v1_5' : 'P-256'
}

const PEM = {
  isPrivateKey,
  isPublicKey,
  isKey,
  typeOf,
  extractKey,
  encodePrivateKey,
  encodePublicKey,
  encode,
  decode,
  getDefaultAlgorithm
}

export { PEM as default, PEM }
