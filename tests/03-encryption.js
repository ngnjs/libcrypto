import test from 'tappedout'
import NGN from 'ngn'
import crypto from '@ngnjs/crypto'

const x = NGN.runtime // Prevent test suite import from conflicting with plugin in Node.js

test('Reversible Encryption/Decryption', async t => {
  const encryptionKey = 'my secret'
  const source = 'crypto makes things hard to read'
  const encrypted = await crypto.encrypt(source, encryptionKey).catch(t.abort)
  t.ok(source !== encrypted, 'Encrypted content is obfuscated')

  const decrypted = await crypto.decrypt(encrypted, encryptionKey).catch(t.abort)
  t.expect(source, decrypted, 'Decryption converts cipher to original content')

  t.end()
})

test('Public Key Encryption/Private Key Decryption', async t => {
  if (NGN.runtime === 'deno') {
    t.pass('KEY-BASED ENCRYPTION NOT YET SUPPORTED IN DENO')
    t.end()
    return
  }

  const keypair = await crypto.generateRSAKeyPair().catch(t.abort)
  const { publicKey, privateKey } = keypair
  const source = 'crypto makes things hard to read'
  const encrypted = await crypto.encrypt(source, publicKey).catch(t.abort)
  t.ok(source !== encrypted, 'Public key encrypted content is obfuscated')

  const decrypted = await crypto.decrypt(encrypted, privateKey).catch(t.abort)
  t.expect(source, decrypted, 'Private key decryption converts cipher to original content')

  t.end()
})
