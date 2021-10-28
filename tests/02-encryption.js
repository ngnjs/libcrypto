import test from 'tappedout'
import ngn from 'ngn'
import crypto from '@ngnjs/crypto'

const x = ngn.runtime // Prevent test suite import from conflicting with plugin in Node.js

test('Reversible Encryption/Decryption', async t => {
  const encryptionKey = 'my secret'
  const source = 'crypto makes things hard to read'
  const encrypted = await crypto.encrypt(source, encryptionKey).catch(t.abort)
  t.ok(source !== encrypted, 'Encrypted content is obfuscated')

  const decrypted = await crypto.decrypt(encrypted, encryptionKey).catch(t.abort)
  t.expect(source, decrypted, 'Decryption converts cipher to original content')

  t.end()
})
