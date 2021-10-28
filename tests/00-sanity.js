import test from 'tappedout'
import ngn from 'ngn'
import crypto from '@ngnjs/crypto'

test('Sanity', t => {
  t.expect('function', typeof crypto.encrypt, 'encrypt function available')
  t.expect('function', typeof crypto.decrypt, 'decrypt function available')
  t.expect('function', typeof crypto.generateRSAKeyPair, 'generateRSAKeyPair function available')
  t.expect('function', typeof crypto.sign, 'sign function available')
  t.expect('function', typeof crypto.verify, 'verify function available')

  t.end()
})
