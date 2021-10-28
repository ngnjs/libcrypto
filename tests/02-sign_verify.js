import test from 'tappedout'
import NGN from 'ngn'
import crypto from '@ngnjs/crypto'

test('Content Signing & Verification', async t => {
  // TODO: Compare the Deno runtime version to the active one.
  // Once the runtime supports importKey (https://github.com/denoland/deno/issues/11690),
  // it will be possible to run tests on modern Deno versions.
  // console.log(ngn.runtime_version)
  if (NGN.runtime === 'deno') {
    t.pass('CONTENT SIGNING NOT YET SUPPORTED IN DENO')
    t.end()
    return
  }

  const { publicKey, privateKey } = await crypto.generateKeys().catch(t.abort)
  const content = 'crypto makes things safe'
  const signature = await crypto.sign(privateKey, content).catch(t.abort)
  const verified = await crypto.verify(publicKey, signature, content).catch(t.abort)

  t.expect(true, verified, 'signing and verification succeeds for generated signature')

  const keypairs = await crypto.generateKeys().catch(t.abort)
  const invalid = await crypto.verify(keypairs.publicKey, signature, content).catch(t.abort)
  t.expect(false, invalid, 'verification fails for incorrect private key')

  t.end()
})