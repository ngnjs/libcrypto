import { cryptography, nodecrypto, runtime } from './common.js'
import { URL, BTOA } from './encoding/base64.js'

const HOUR = 60 * 60 * 1000
const SHA256 = { name: 'SHA-256' }
const SHA384 = { name: 'SHA-384' }
const SHA512 = { name: 'SHA-512' }
const ALGORITHMS = {
  HS256: { name: 'HMAC', hash: SHA256 },
  HS384: { name: 'HMAC', hash: SHA384 },
  HS512: { name: 'HMAC', hash: SHA512 },
  RS256: { name: 'RSASSA-PKCS1-v1_5', hash: SHA256 },
  RS384: { name: 'RSASSA-PKCS1-v1_5', hash: SHA384 },
  RS512: { name: 'RSASSA-PKCS1-v1_5', hash: SHA512 },
  EC256: { name: 'ECDSA', namedCurve: 'P-256', hash: SHA256 },
  EC384: { name: 'ECDSA', namedCurve: 'P-384', hash: SHA384 },
  EC512: { name: 'ECDSA', namedCurve: 'P-512', hash: SHA512 }
}

/**
 * Create a JWT token
 * @param {object} config
 * JWT configuration
 * @param {string} [config.account]
 * The account name
 * @param {object} [config.claims={}]
 * Claims of the token
 * @param {string} [config.algorithm=HS256] (HS256, HS384, HS512, RS256, RS384, RS512, EC256, EC384, EC512)
 * The algorithm used to sign the token.
 *
 * - `HS` = `HMAC`
 * - `RS` = `RSA`
 * - `EC` = `ECDSA`
 *
 * Each is available as 256-bit, 384-bit, or 512-bit.
 * @param {string} config.secret
 * The secret used to hash the token (UTF-8 string).
 * @param {date} [config.expiration]
 * The expiration date of the token. Defaults to an hour from the current time.
 * @param {string} [config.issuer]
 * The token issuer.
 * @param {object} [config.headers]
 * Additional headers to add to the token.
 * @returns {string}
 * A UTF-8 version of the token.
 */
export async function createToken ({ account, secret, claims = {}, algorithm = 'HS256', expiration, issuer, headers = null }) {
  const header = Object.assign({
    typ: 'JWT',
    alg: ALGORITHMS[algorithm].name
  }, headers)
  const claim = Object.assign(claims, {
    iat: new Date().getTime(),
    exp: expiration || new Date().getTime() + HOUR,
    jti: NANOID(28)
  })

  if (account) {
    claim.sub = account
  }

  if (issuer) {
    claim.iss = issuer
  }

  const prefix = URL.stringify(utf8ToUint8Array(JSON.stringify(header)))
  const data = URL.stringify(utf8ToUint8Array(JSON.stringify(claim)))
  const payload = `${prefix}.${data}`

  if (runtime === 'node' && !cryptography) {
    const sig = nodecrypto
      .createHmac(ALGORITHMS[algorithm].hash.name.replace('-', ''), secret)
      .update(payload)
      .digest('base64')
      .replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_')

    return `${payload}.${sig}`
  }

  const key = await hmac(secret, algorithm, payload)
  const signature = await sign(key, payload, algorithm)

  return `${payload}.${URL.stringify(new Uint8Array(signature))}`
}

/**
 * Verify a JWT token
 * @param {string} token
 * The raw JWT string (UTF-8).
 * @param {string} secret
 * The secret used to hash the token (UTF-8 string).
 * @param {string} [algorithm=HS256] (HS256, HS384, HS512, RS256, RS384, RS512, EC256, EC384, EC512)
 * The algorithm used to sign the token.
 *
 * - `HS` = `HMAC`
 * - `RS` = `RSA`
 * - `EC` = `ECDSA`
 *
 * Each is available as 256-bit, 384-bit, or 512-bit.
 * @returns {boolean}
 */
export async function verifyToken (token, secret, alg = 'HS256') {
  const payload = token.split('.').slice(0, 2).join('.')

  if (runtime === 'node' && !cryptography) {
    const sig = nodecrypto
      .createHmac(ALGORITHMS[alg].hash.name.replace('-', ''), secret)
      .update(payload)
      .digest('base64')
      .replace(/=+/g, '').replace(/\+/g, '-').replace(/\//g, '_')

    return sig === token.split('.').pop()
  }

  const key = await hmac(secret, alg)
  const signature = await sign(key, payload, alg)

  return await cryptography.subtle.verify(
    { name: ALGORITHMS[alg].name },
    key,
    signature,
    utf8ToUint8Array(payload)
  )
}

const utf8ToUint8Array = str => URL.parse(BTOA(unescape(encodeURIComponent(str))))

async function hmac (secret, alg = 'HS256', data) {
  return await cryptography.subtle.importKey(
    'raw',
    utf8ToUint8Array(secret),
    ALGORITHMS[alg],
    false,
    ['sign', 'verify']
  )
}

async function sign (key, data, alg = 'HS256') {
  return await cryptography.subtle.sign(
    { name: ALGORITHMS[alg].name },
    key,
    utf8ToUint8Array(data)
  )
}

function NANOID (size = 21) {
  if (typeof size === 'string') {
    size = isNaN(size) ? 21 : parseInt(size, 10)
  }

  const bytes = runtime === 'node' ? nodecrypto.randomBytes(size) : cryptography.getRandomValues(new Uint8Array(size))
  let id = ''
  while (size--) {
    const n = 63 & bytes[size]
    id += n < 36 ? n.toString(36) : n < 62 ? (n - 26).toString(36).toUpperCase() : n < 63 ? '_' : '-'
  }

  return id
}

const all = {
  createToken,
  verifyToken
}

export { all as default }
