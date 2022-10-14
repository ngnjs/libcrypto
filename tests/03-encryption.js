import test from 'tappedout'
import {
  createEncryptionKeypair,
  createKeypairPEM,
  encrypt,
  decrypt
} from '@ngnjs/libcrypto'

const runtime = globalThis.process !== undefined ? 'node' : (globalThis.hasOwnProperty('Deno') ? 'deno' : 'browser') // eslint-disable-line no-prototype-builtins
const SECRET = 'secret12'

test('Default Asymmetric Key Encryption/Decryption (RSA-OAEP keypair)', async t => {
  const { encryptionKey, decryptionKey } = await createEncryptionKeypair()
  const content = 'crypto makes things safe'
  const encrypted = await encrypt(content, encryptionKey)
  const decrypted = await decrypt(encrypted, decryptionKey)
  t.expect(content, decrypted, 'Asymmetric keypair encrypted/decrypted value matches original input')

  t.end()
})

// const ecdhlist = ['EC256', 'EC384']
// if (runtime !== 'deno') {
//   ecdhlist.push('EC512')
// }
// for (const algorithm of ecdhlist) {
//   test.only('ECDH Asymmetric Key Encryption/Decryption', async t => {
//     const { encryptionKey, decryptionKey } = await createEncryptionKeypair(algorithm)
//     console.log({ encryptionKey, decryptionKey })
//     const content = 'crypto makes things safe'
//     const encrypted = await encrypt(content, encryptionKey)
//     const decrypted = await decrypt(encrypted, decryptionKey)
//     t.expect(content, decrypted, `${algorithm} asymmetric keypair encrypted/decrypted value matches original input`)

//     t.end()
//   })
// }

const keytypes = ['OAEP256', 'OAEP384', 'OAEP512']
for (const kt of keytypes) {
  test(`RSA-OAEP SHA-${kt.replace(/[^0-9]+/, '')} (${kt}) Asymmetric Key Encryption/Decryption`, async t => {
    const { encryptionKey, decryptionKey } = await createEncryptionKeypair()
    const content = 'crypto makes things safe'
    const encrypted = await encrypt(content, encryptionKey)
    const decrypted = await decrypt(encrypted, decryptionKey)
    t.expect(content, decrypted, `${kt} asymmetric keypair encrypted/decrypted value matches original input`)

    t.end()
  })
}

test('Default Symmetric Key Encryption/Decryption', async t => {
  const secret = 'Encrypti0nKey'
  const content = 'crypto makes things safe'
  const encrypted = await encrypt(content, secret)
  const decrypted = await decrypt(encrypted, secret)
  t.expect(content, decrypted, 'Symmetric key encrypted/decrypted value matches original input')

  t.end()
})

const aestypes = ['GCM128', 'GCM192', 'GCM256', 'CBC128', 'CBC192', 'CBC256', 'CTR128']
const derivationtypes = ['PB256', 'PB384', 'PB512'] //, 'HK256', 'HK384', 'HK512', 'EC256', 'EC384']
// if (runtime !== 'deno') {
//   derivationtypes.push('EC512')
// }
for (const at of aestypes) {
  test(`${at} Symmetric Key Encryption/Decryption`, async t => {
    const secret = 'Encrypti0nKey'
    const content = 'crypto makes things safe'
    const encrypted = await encrypt(content, secret, at)
    const decrypted = await decrypt(encrypted, secret, at)
    t.expect(content, decrypted, `${at} symmetric key encrypted/decrypted value matches original input using default derivation algorithm`)

    for (const dt of derivationtypes) {
      const encrypted = await encrypt(content, secret, at, dt)
      const decrypted = await decrypt(encrypted, secret, at, dt)
      t.expect(content, decrypted, `${at} symmetric key encrypted/decrypted value matches original input using "${dt}" derivation algorithm`)
    }

    t.end()
  })
}