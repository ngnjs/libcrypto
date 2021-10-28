import test from 'tappedout'
import ngn from 'ngn'
import crypto from '@ngnjs/crypto'

const PEM_PUBLIC_PATTERN = /-{5}(BEGIN\s((RSA|EC)\s)?PUBLIC\sKEY)-{5}/
const PEM_PRIVATE_PATTERN = /-{5}(BEGIN\s((RSA|EC)\s)?PRIVATE\sKEY)-{5}/

test('RSA Keypairs', async t => {
  let keypair = await crypto.generateRSAKeyPair().catch(t.abort)

  t.ok(keypair.privateKey, 'contains a private key')
  t.ok(keypair.publicKey, 'contains a public key')
  t.expect(true, PEM_PRIVATE_PATTERN.test(keypair.privateKey), 'private key is PEM encoded')
  t.expect(true, PEM_PUBLIC_PATTERN.test(keypair.publicKey), 'public key is PEM encoded')

  keypair = await crypto.generateRSAKeyPair(4096, 'SHA-512').catch(t.abort)
  t.ok(keypair.privateKey, '4096-bit/SHA-512 keypair contains a private key')
  t.ok(keypair.publicKey, '4096-bit/SHA-512 keypair contains a public key')
  t.expect(true, PEM_PRIVATE_PATTERN.test(keypair.privateKey), '4096-bit/SHA-512 keypair private key is PEM encoded')
  t.expect(true, PEM_PUBLIC_PATTERN.test(keypair.publicKey), '4096-bit/SHA-512 keypair public key is PEM encoded')

  t.end()
})

test('ECDSA Keypairs', async t => {
  // TODO: Compare the Deno runtime version to the active one.
  // Once the runtime supports importKey (https://github.com/denoland/deno/issues/11690),
  // it will be possible to run tests on modern Deno versions.
  // console.log(ngn.runtime_version)
  if (ngn.runtime === 'deno') {
    t.pass('ECDSA NOT YET SUPPORTED IN DENO')
  } else {
    const keypair = await crypto.generateECKeyPair().catch(t.abort)

    t.ok(keypair.privateKey, 'contains a private key')
    t.ok(keypair.publicKey, 'contains a public key')
    t.expect(true, PEM_PRIVATE_PATTERN.test(keypair.privateKey), 'private key is PEM encoded')
    t.expect(true, PEM_PUBLIC_PATTERN.test(keypair.publicKey), 'public key is PEM encoded')
  }

  t.end()
})

test('Content Signing', async t => {
  // TODO: Compare the Deno runtime version to the active one.
  // Once the runtime supports importKey (https://github.com/denoland/deno/issues/11690),
  // it will be possible to run tests on modern Deno versions.
  // console.log(ngn.runtime_version)
  if (ngn.runtime === 'deno') {
    t.pass('CONTENT SIGNING NOT YET SUPPORTED IN DENO')
  } else {
    const { publicKey, privateKey } = await crypto.generateKeys().catch(t.abort)
    const content = 'crypto makes things safe'
    const signature = await crypto.sign(privateKey, content).catch(t.abort)
    const verified = await crypto.verify(publicKey, signature, content).catch(t.abort)

    t.expect(true, verified, 'signing and verification succeeds for generated signature')

    const keypairs = await crypto.generateKeys().catch(t.abort)
    const invalid = await crypto.verify(keypairs.publicKey, signature, content).catch(t.abort)
    t.expect(false, invalid, 'verification fails for incorrect private key')
  }

  t.end()
})