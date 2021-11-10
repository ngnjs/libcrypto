import test from 'tappedout'
import NGN from 'ngn'
import crypto from '@ngnjs/libcrypto'

test('One Time Passwords (OTP)', async t => {
  const secret = 'password'
  const hotp = await crypto.HOTP(secret)
  const totp = await crypto.TOTP(secret)

  t.expect(328482, parseInt(hotp, 10), 'generate HOTP')
  t.ok(parseInt(totp, 10) > 99999, 'generate TOTP')

  t.end()
})
