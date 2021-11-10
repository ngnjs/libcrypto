import { cryptography, nodecrypto, runtime } from './common.js'
import { base32ToBuf } from './encoding/base32.js'

/**
 * HMAC-based OTP
 * @param {string} secret
 * Secret/key used to create the OTP
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
  secret = base32ToBuf(secret)

  if (runtime === 'node' && !cryptography) {
    const buffer = Buffer.alloc(8)
    if (Number.isFinite(counter) || typeof counter === 'bigint') {
      buffer.write(zeropad(counter.toString(16)), 0, 'hex')
    } else if (Buffer.isBuffer(counter)) {
      counter.copy(buffer)
    } else if (typeof counter === 'string') {
      buffer.write(zeropad(counter), 0, 'hex')
    } else {
      throw new Error(`Unexpected counter type ${typeof counter}`)
    }
    const hmac = nodecrypto.createHmac(algo, secret).update(buffer).digest()

    return zeropad(truncate(hmac, digits), digits)
  }

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

// Uint8Array(8)
function pad (counter) {
  const pairs = counter.toString(16).padStart(16, '0').match(/..?/g)
  const array = pairs.map(v => parseInt(v, 16))
  return Uint8Array.from(array)
}

// Number
function truncate (hs) {
  const offset = hs[19] & 0b1111
  return ((hs[offset] & 0x7f) << 24) | (hs[offset + 1] << 16) | (hs[offset + 2] << 8) | hs[offset + 3]
}

function zeropad (value, digits = 16) {
  var fill = '0'.repeat(digits)
  return (fill + value).slice(-digits)
}
