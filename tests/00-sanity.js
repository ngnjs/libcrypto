import test from 'tappedout'
import * as crypto from '@ngnjs/libcrypto'

test('Sanity', t => {
  t.expect('object', typeof crypto.RSA, 'RSA methods available')
  t.expect('function', typeof crypto.RSA.createKeypair, 'generic function to create RSA keypair available')
  t.expect('function', typeof crypto.RSA.createKeypairPEM, 'generic function to create RSA PEM-encoded keypair available')
  t.expect('function', typeof crypto.RSA.createPKCS1Keypair, 'function to create RSASSA-PKCS1-v1_5 keypair available')
  t.expect('function', typeof crypto.RSA.createPKCS1KeypairPEM, 'function to create RSASSA-PKCS1-v1_5 PEM-encoded keypair available')
  t.expect('function', typeof crypto.RSA.createPSSKeypair, 'function to create RSA-PSS keypair available')
  t.expect('function', typeof crypto.RSA.createPSSKeypairPEM, 'function to create RSA-PSS PEM-encoded keypair available')

  t.expect('object', typeof crypto.ECDSA, 'ECDSA methods available')
  t.expect('function', typeof crypto.ECDSA.createKeypair, 'function to create ECDSA keypair available')
  t.expect('function', typeof crypto.ECDSA.createKeypairPEM, 'function to create ECDSA PEM-encoded keypair available')

  t.expect('object', typeof crypto.HMAC, 'HMAC methods available')
  t.expect('function', typeof crypto.HMAC.createKey, 'function to create HMAC key available')
  t.expect('function', typeof crypto.HMAC.createKeyPEM, 'function to create HMAC PEM-encoded key available')

  t.expect('object', typeof crypto.PEM, 'PEM encoding methods available')
  t.expect('object', typeof crypto.PEM.PEM_PATTERN, 'A RegExp pattern for parsing PEM-encoded strings')
  t.expect('function', typeof crypto.PEM.encode, 'PEM encoder function available')
  t.expect('function', typeof crypto.PEM.decode, 'PEM decoder function available')
  t.expect('function', typeof crypto.PEM.info, 'PEM metadata extraction function available')
  t.expect('function', typeof crypto.PEM.ToPEM, 'function to convert a CryptoKey or pair of CryptoKeys to PEM-encoded versions available')
  t.expect('function', typeof crypto.PEM.ToCryptoKey, 'function to convert PEM-encoded key to a CryptoKey available')

  t.expect('function', typeof crypto.createKeypair, 'general createKeypair function available')
  t.expect('function', typeof crypto.createKeypairPEM, 'general createKeypair function (PEM-encoded results) available')
  t.expect('function', typeof crypto.createSigningKeypair, 'general function for creating PEM-encoded signing/verification keypairs available')
  t.expect('function', typeof crypto.sign, 'sign function available')
  t.expect('function', typeof crypto.verify, 'verify function available')

  t.expect('function', typeof crypto.createEncryptionKeypair, 'general function to create encryption/decryption keys available')
  // t.expect('function', typeof crypto.encrypt, 'encrypt function available')
  // t.expect('function', typeof crypto.decrypt, 'decrypt function available')
  // t.expect('function', typeof crypto.generateRSAKeyPair, 'generateRSAKeyPair function available')
  // t.expect('function', typeof crypto.generateECDSAKeyPair, 'generateECDSAKeyPair function available')
  // t.expect('function', typeof crypto.generateECKeyPair, 'generateECKeyPair function available')
  // t.expect('function', typeof crypto.generateKeys, 'generateKeys function available')
  // t.expect('function', typeof crypto.HOTP, 'HOTP function available')
  // t.expect('function', typeof crypto.TOTP, 'TOTP function available')

  t.end()
})
