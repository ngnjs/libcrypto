import test from 'tappedout'
import NGN from 'ngn'
import crypto from '@ngnjs/libcrypto'

test('One Time Passwords (OTP)', async t => {
  const secret = 'password'
  const result = await crypto.HOTP(secret, { counter: 0 })
  t.expect(328482, parseInt(result, 10), 'generate HOTP')

  const totp = await crypto.TOTP(secret)

  t.ok(parseInt(totp, 10) > 99999, 'generate TOTP')

  t.end()
})
