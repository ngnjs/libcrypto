import { runtime } from '../lib/base.js'

export const SALT_LENGTH = 16
export const AUTH_TAG_LENGTH = 16
export const SHA256 = { name: 'SHA-256' }
export const SHA384 = { name: 'SHA-384' }
export const SHA512 = { name: 'SHA-512' }
const ECDSA_ALGORITHMS = {
  ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: SHA256 },
  ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: SHA384 },
  ES512: { name: 'ECDSA', namedCurve: 'P-521', hash: SHA512 },
  ES521: { name: 'ECDSA', namedCurve: 'P-521', hash: SHA512 }
}

if (runtime === 'deno') {
  delete ECDSA_ALGORITHMS.ES512
  delete ECDSA_ALGORITHMS.ES521
}

export { ECDSA_ALGORITHMS }
export const HMAC_ALGORITHMS = {
  HS256: { name: 'HMAC', hash: SHA256 },
  HS384: { name: 'HMAC', hash: SHA384 },
  HS512: { name: 'HMAC', hash: SHA512 }
}
export const PKCS1_ALGORITHMS = {
  RS256: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, hash: SHA256, saltLength: 256 },
  RS384: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 3072, hash: SHA384, saltLength: 384 },
  RS512: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, hash: SHA512, saltLength: 512 }
}
export const PSS_ALGORITHMS = {
  PS256: { name: 'RSA-PSS', modulusLength: 2048, hash: SHA256, saltLength: 256 },
  PS384: { name: 'RSA-PSS', modulusLength: 3072, hash: SHA384, saltLength: 384 },
  PS512: { name: 'RSA-PSS', modulusLength: 4096, hash: SHA512, saltLength: 512 }
}
export const RSA_ALGORITHMS = Object.assign(
  PKCS1_ALGORITHMS,
  PSS_ALGORITHMS
)
export const SIGNING_ALGORITHMS = Object.assign(
  HMAC_ALGORITHMS,
  RSA_ALGORITHMS,
  ECDSA_ALGORITHMS
)
export const RSA_OAEP_ALGORITHMS = {
  OAEP256: {
    name: 'RSA-OAEP',
    hash: SHA256,
    modulusLength: 2048,
    get iv () { return crypto.getRandomValues(new Uint8Array(16)) }
  },
  OAEP384: {
    name: 'RSA-OAEP',
    hash: SHA384,
    modulusLength: 3072,
    get iv () { return crypto.getRandomValues(new Uint8Array(16)) }
  },
  OAEP512: {
    name: 'RSA-OAEP',
    hash: SHA512,
    modulusLength: 4096,
    get iv () { return crypto.getRandomValues(new Uint8Array(16)) }
  }
}
export const AES_ALGORITHMS = {
  CTR128: {
    name: 'AES-CTR',
    length: 128,
    get counter () { return crypto.getRandomValues(new Uint8Array(16)) }
  },
  CBC128: {
    name: 'AES-CBC',
    get iv () { return crypto.getRandomValues(new Uint8Array(16)) },
    length: 128
  },
  CBC192: {
    name: 'AES-CBC',
    get iv () { return crypto.getRandomValues(new Uint8Array(16)) },
    length: 192
  },
  CBC256: {
    name: 'AES-CBC',
    get iv () { return crypto.getRandomValues(new Uint8Array(16)) },
    length: 256
  },
  GCM128: {
    name: 'AES-GCM',
    get iv () { return crypto.getRandomValues(new Uint8Array(12)) },
    length: 128
  },
  GCM192: {
    name: 'AES-GCM',
    get iv () { return crypto.getRandomValues(new Uint8Array(12)) },
    length: 256
  },
  GCM256: {
    name: 'AES-GCM',
    get iv () { return crypto.getRandomValues(new Uint8Array(12)) },
    length: 256
  }
}
export const ENCRYPTION_ALGORITHMS = Object.assign({},
  RSA_OAEP_ALGORITHMS,
  AES_ALGORITHMS
)
export const ECDH_ALGORITHMS = {
  EC256: { name: 'ECDH', namedCurve: 'P-256' },
  EC384: { name: 'ECDH', namedCurve: 'P-384' },
  EC512: { name: 'ECDH', namedCurve: 'P-521' },
  EC521: { name: 'ECDH', namedCurve: 'P-521' },
}

if (runtime === 'deno') {
  delete ECDH_ALGORITHMS.EC512
  delete ECDH_ALGORITHMS.EC521
}

export const HKDF_ALGORITHMS = {
  HK256: { name: 'HKDF', hash: SHA256 },
  HK384: { name: 'HKDF', hash: SHA384 },
  HK512: { name: 'HKDF', hash: SHA512 }
}
export const PBKDF2_ALGORITHMS = {
  PB256: { name: 'PBKDF2', iterations: 10000, hash: SHA256 },
  PB384: { name: 'PBKDF2', iterations: 10000, hash: SHA384 },
  PB512: { name: 'PBKDF2', iterations: 10000, hash: SHA512 }
}
export const DERIVE_ALGORITHMS = Object.assign({},
  ECDH_ALGORITHMS,
  HKDF_ALGORITHMS,
  PBKDF2_ALGORITHMS
)
export const ASYMMETRIC_ENCRYPTION_ALGORITHMS = Object.assign({},
  RSA_ALGORITHMS,
  ECDH_ALGORITHMS
)
export const ALGORITHMS = Object.assign({},
  SIGNING_ALGORITHMS,
  ENCRYPTION_ALGORITHMS
)
export const ABBREVIATIONS = {
  ECDSA: 'ES',
  'RSASSA-PKCS1-v1_5': 'RS',
  'RSA-PSS': 'PS',
  HMAC: 'HS',
  ECDH: 'EC'
}

export function normalize (algorithm = 'ES256', VALID = ALGORITHMS) {
  const namedAlgorithm = algorithm

  if (typeof algorithm === 'string') {
    algorithm = algorithm.trim().toUpperCase()

    if (runtime === 'deno' && algorithm === 'ES512') {
      throw new Error(`${runtime} does not support the ${namedAlgorithm} algorithm.`)
    }

    if (!VALID[algorithm]) {
      throw new Error(`invalid key algorithm "${algorithm}" - use one of the following instead: ${Object.keys(VALID).join(', ')}`)
    }

    algorithm = VALID[algorithm]
  }

  if (algorithm.namedCurve || (ASYMMETRIC_ENCRYPTION_ALGORITHMS[namedAlgorithm] && algorithm.name.substring(0, 3) !== 'RSA')) {
    delete algorithm.modulusLength
    delete algorithm.publicExponent
    if (algorithm.namedCurve) {
      algorithm.hash = algorithm.hash || { name: `SHA-${algorithm.namedCurve.split('-').pop()}` }
    }
  } else {
    algorithm.hash = algorithm.hash || { name: `SHA-${(namedAlgorithm?.name || namedAlgorithm).replace(/[^0-9]+/gi, '')}` }
  }

  return algorithm
}
