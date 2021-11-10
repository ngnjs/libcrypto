import test from 'tappedout'
import crypto from '@ngnjs/libcrypto'

test('Sanity', t => {
  t.expect('function', typeof crypto.encrypt, 'encrypt function available')
  t.expect('function', typeof crypto.decrypt, 'decrypt function available')
  t.expect('function', typeof crypto.generateRSAKeyPair, 'generateRSAKeyPair function available')
  t.expect('function', typeof crypto.generateECDSAKeyPair, 'generateECDSAKeyPair function available')
  t.expect('function', typeof crypto.generateECKeyPair, 'generateECKeyPair function available')
  t.expect('function', typeof crypto.generateKeys, 'generateKeys function available')
  t.expect('function', typeof crypto.sign, 'sign function available')
  t.expect('function', typeof crypto.verify, 'verify function available')
  t.expect('function', typeof crypto.HOTP, 'HOTP function available')
  t.expect('function', typeof crypto.TOTP, 'TOTP function available')
  t.expect('object', typeof crypto.PEM, 'PEM object recognized')

  t.end()
})
