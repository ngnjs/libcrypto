import { cryptography, runtime, stringToArrayBuffer, arrayBufferToString } from './common.js'
import { base32ToBuf, bufToBase32 } from './encoding/base32.js'
import { pad, truncate, zeropad, createNodeHMAC } from './hmac.js'

const base32encode = str => bufToBase32(Uint8Array.from(Array.from(str).map(l => l.charCodeAt(0))))
const base32decode = input => arrayBufferToString(base32ToBuf(input))
export const base32 = { encode: base32encode, decode: base32decode }

/**
 * HMAC-based OTP
 * @param {string} secret
 * UTF-8 secret/key used to create the OTP
 * @param {object} options
 * Configuration options.
 * @param {number} [options.counter=0]
 * The counter to base the OTP on
 * @param {string} [options.algorithm=SHA-1] (SHA-1, SHA-256, SHA-384, SHA-512)
 * The algorithm used to generate the OTP.
 * @param {number} [options.digits=6]
 * Number of digits to produce for the final TOTP
 * @returns {string}
 * Returns a string of numbers with the configured number of digits.
 */
export async function HOTP (secret, cfg = {}) {
  const algorithm = cfg.algorithm || 'SHA-1'
  const algo = algorithm.trim().replace('-', '').toLowerCase()
  const counter = cfg.counter || 0
  const digits = cfg.digits || 6

  if (runtime === 'node' && !cryptography) {
    const hmac = createNodeHMAC(secret, counter, algo)
    return zeropad(truncate(hmac, digits), digits)
  }

  secret = stringToArrayBuffer(secret)

  const key = await cryptography.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: { name: algorithm } },
    false,
    ['sign']
  )

  const hmac = new Uint8Array(await cryptography.subtle.sign('HMAC', key, pad(counter)))

  // HOTP(K, C) = truncate(HMAC(K, C))
  const num = truncate(hmac)

  // return 6 digits, padded with leading zeros
  return num.toString().padStart(digits, '0').slice(0 - digits)
}

/**
 * Time-based OTP
 * @param {string} secret
 * UTF-8 secret/key used to create the OTP
 * @param {object} options
 * Configuration options.
 * @param {number} [options.digits=6]
 * Number of digits to produce for the final TOTP
 * @param {number} [options.seconds=30]
 * Number of seconds in the time interval
 * @param {number} [options.timestamp]
 * A specific timestamp to generate TOTP for. This is
 * typically only used to generate older versions of the TOTP.
 * @param {string} [options.algorithm=SHA-1] (SHA-1, SHA-256, SHA-384, SHA-512)
 * The algorithm used to generate the OTP.
 * @returns {string}
 * Returns a string of numbers with the configured number of digits.
 */
export async function TOTP (secret, cfg = {}) {
  cfg.counter = cfg.timestamp || Math.floor(+new Date() / ((cfg.seconds || 30) * 1000))
  cfg.digits = cfg.digits || 6

  return HOTP(secret, cfg)
}
