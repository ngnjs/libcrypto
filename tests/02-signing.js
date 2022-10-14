import test from 'tappedout'
import {
  createSigningKeypair,
  sign,
  verify
} from '@ngnjs/libcrypto'

const runtime = globalThis.process !== undefined ? 'node' : (globalThis.hasOwnProperty('Deno') ? 'deno' : 'browser') // eslint-disable-line no-prototype-builtins
const SECRET = 'secret12'

// Signing and Verification
test('Default Content Signing & Verification', async t => {
  const { signingKey, verificationKey } = await createSigningKeypair().catch(t.abort)
  const content = 'crypto makes things safe'
  const signature = await sign(content, signingKey).catch(t.abort)
  const verified = await verify(content, signature, verificationKey).catch(t.abort)
  t.expect(true, verified, 'signing and verification succeed with generated signature (default keypair)')

  const obj = { text: 'crypto makes things safe' }
  const sig = await sign(obj, signingKey).catch(t.abort)
  const ok = await verify(obj, sig, verificationKey).catch(t.abort)
  t.expect(true, ok, 'signing and verification succeed with a JSON object (default keypair)')

  t.end()
})

const SIGNING_ALGORITHMS = new Set(['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'ES256', 'ES384'])
if (runtime !== 'deno') {
  SIGNING_ALGORITHMS.add('ES512')
}

for (const name of SIGNING_ALGORITHMS.values()) {
  test(`${name} Key(pair) Content Signing & Verification`, async t => {
    const { signingKey, verificationKey } = await createSigningKeypair(name, SECRET).catch(t.abort)
    const content = 'crypto makes things safe'
    const signature = await sign(content, signingKey, name).catch(t.abort)
    const verified = await verify(content, signature, verificationKey, name).catch(t.abort)
    t.expect(true, verified, `${name} signing and verification succeed with generated signature`)

    const obj = { text: 'crypto makes things safe' }
    const sig = await sign(obj, signingKey, name).catch(t.abort)
    const ok = await verify(obj, sig, verificationKey, name).catch(t.abort)
    t.expect(true, ok, `${name} signing and verification succeed with a JSON object`)

    t.end()
  })
}