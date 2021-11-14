import test from 'tappedout'
import NGN from 'ngn'
import crypto from '@ngnjs/libcrypto'

test('JSON Web Tokens (JWT)', async t => {
  const secret = 'secret'
  const token = await crypto.JWT.createToken({
    secret,
    issuer: 'acme corp',
    account: 'acct name',
    claims: {
      name: 'John Doe',
      admin: true
    },
    headers: { kid: 'testdata' }
  }).catch(t.abort)

  t.expect(3, token.split('.').length, 'JWT contains 3 segments')

  const verified = await crypto.JWT.verifyToken(token, secret)
  t.expect(true, verified, 'verified JWT')

  t.end()
})
