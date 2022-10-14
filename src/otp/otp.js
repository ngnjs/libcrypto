import { ArrayBufferToString, StringToArrayBuffer } from '../encoding/common.js'
import { Base32ToUint8Array, Uint8ArrayToBase32 } from '../encoding/base32.js'
import { pad, truncate } from '../keys/hmac.js'

/**
 * HMAC-based OTP
 * @param {string} secret
 * UTF-8 secret/key used to create the OTP. The number of characters
 * must be evenly divisible by 8. If it is not, the secret will be padded
 * with the equal sign (`=`). For example, a password called `secret` is
 * only 6 characters. It will be automatically padded as `secret==`. Similarly,
 * a secret of `thesecret` is 9 characters. It will be padded with 7 additional
 * characters (total 16) to be evenly divisible by 8 (`thesecret=======`).
 * @param {object} options
 * Configuration options.
 * @param {number} [options.counter=0]
 * The counter to base the OTP on
 * @param {string} [options.hash=SHA-1] (SHA-1, SHA-256, SHA-384, SHA-512)
 * The algorithm used to generate the OTP.
 * @param {number} [options.digits=6]
 * Number of digits to produce for the final TOTP
 * @returns {string}
 * Returns a string of numbers with the configured number of digits.
 */
export async function HOTP (secret, cfg = {}) {
  const hash = cfg.hash || 'SHA-1'
  const counter = cfg.counter || 0
  const digits = cfg.digits || 6

  while (secret.length % 8 !== 0) {
    secret += '='
  }

  secret = StringToArrayBuffer(secret)

  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: { name: hash } },
    false,
    ['sign']
  )

  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, pad(counter)))

  // HOTP(K, C) = truncate(HMAC(K, C))
  const num = truncate(hmac)

  // return 6 digits (default), padded with leading zeros
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
