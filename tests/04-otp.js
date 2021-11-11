import test from 'tappedout'
import NGN from 'ngn'
import crypto from '@ngnjs/libcrypto'

test('One Time Passwords (OTP)', async t => {
  // secret is base32 encoding of "passwordpassword"
  // const secret = 'OBQXG43XN5ZGI4DBONZXO33SMQ======'
  const secret = 'passwordpassword'
  // console.log('encode', crypto.base32.encode(secret), '<<<')
  // console.log('decode', crypto.base32.decode('OBQXG43XN5ZGI4DBONZXO33SMQ======'), '<<<')
  const hotp = await crypto.HOTP(secret)
  const totp = await crypto.TOTP(secret)

  t.expect(647830, parseInt(hotp, 10), 'generate HOTP')
  t.ok(parseInt(totp, 10) > 99999, 'generate TOTP')

  t.end()
})
