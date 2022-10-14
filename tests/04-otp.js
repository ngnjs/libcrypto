import test from 'tappedout'
import { HOTP, TOTP, Base32 } from '@ngnjs/libcrypto'

const secret = 'passwordpassword'

test('Base32 Encoding for OTP', async t => {
  const base32secret = 'OBQXG43XN5ZGI4DBONZXO33SMQ======'

  t.expect(base32secret, await Base32.encode(secret), 'Base32-encoded secret generated correctly')
  t.expect(secret, await Base32.decode(base32secret), 'Decoded base32 string to plaintext')

  t.end()
})

test('One Time Passwords (OTP)', async t => {
  const hotp = await HOTP(secret)
  const totp = await TOTP(secret)

  t.expect(647830, parseInt(hotp, 10), 'HOTP generated successfully')
  t.ok(parseInt(totp, 10) > 99999, 'TOTP is at least 6 digits')
  t.ok(parseInt(totp, 10) < 100000000, 'TOTP is at most 8 digits')

  t.end()
})
