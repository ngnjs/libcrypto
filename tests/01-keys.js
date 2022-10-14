import test from 'tappedout'
import {
  createKeypair,
  createKeypairPEM,
  createSigningKeypair,
  RSA,
  ECDSA,
  HMAC,
  sign,
  verify
} from '@ngnjs/libcrypto'

const runtime = globalThis.process !== undefined ? 'node' : (globalThis.hasOwnProperty('Deno') ? 'deno' : 'browser') // eslint-disable-line no-prototype-builtins
const PEM_PATTERN = /^(?<raw>(?<header>-{1,}BEGIN\s+(?<algorithm>[A-Z-_0-9]+)(?=\sP(RIVATE|UBLIC))\s?(?<access>PRIVATE|PUBLIC)?(\s+)?(?<type>KEY|CERTIFICATE)-{2,})\n(?<body>[^-]+)\n?(?<footer>-{2,}(END\s[A-Z-_0-9\s]+-{2,})))$/i
const SECRET = 'secret12'

test('RSASSA-PKCS1-v1_5 Keypairs', async t => {
  const { privateKey, publicKey } = await RSA.createPKCS1Keypair().catch(t.abort)

  t.ok(privateKey instanceof CryptoKey, 'generate a private CryptoKey')
  t.ok(publicKey instanceof CryptoKey, 'generate a public CryptoKey')

  const pem = await RSA.createPKCS1KeypairPEM().catch(t.abort)
  t.expect(typeof pem.privateKey, 'string', 'generate private key in PEM format')
  t.expect(typeof pem.publicKey, 'string', 'generate public key in PEM format')
  t.ok(PEM_PATTERN.test(pem.privateKey), 'private key is properly encoded in PEM format')
  t.ok(PEM_PATTERN.test(pem.publicKey), 'public key is properly encoded in PEM format')

  t.end()
})

test('RSA-PSS Keypairs', async t => {
  const { privateKey, publicKey } = await RSA.createPSSKeypair().catch(t.abort)

  t.ok(privateKey instanceof CryptoKey, 'generate a private CryptoKey')
  t.ok(publicKey instanceof CryptoKey, 'generate a public CryptoKey')

  const pem = await RSA.createPSSKeypairPEM().catch(t.abort)
  t.expect(typeof pem.privateKey, 'string', 'generate private key in PEM format')
  t.expect(typeof pem.publicKey, 'string', 'generate public key in PEM format')
  t.ok(PEM_PATTERN.test(pem.privateKey), 'private key is properly encoded in PEM format')
  t.ok(PEM_PATTERN.test(pem.publicKey), 'public key is properly encoded in PEM format')

  t.end()
})

let shas = new Set(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'])
for (const sha of shas.values()) {
  test(`RSA ${sha} Keypair`, async t => {
    const { privateKey, publicKey } = await RSA.createKeypair(sha).catch(t.abort)

    t.ok(privateKey instanceof CryptoKey, `generate a private ${sha} CryptoKey`)
    t.ok(publicKey instanceof CryptoKey, `generate a public ${sha} CryptoKey`)

    const pem = await RSA.createKeypairPEM(sha).catch(t.abort)
    t.expect(typeof pem.privateKey, 'string', `generate ${sha} private key in PEM format`)
    t.expect(typeof pem.publicKey, 'string', `generate ${sha} public key in PEM format`)
    t.ok(PEM_PATTERN.test(pem.privateKey), `${sha} private key is properly encoded in PEM format`)
    t.ok(PEM_PATTERN.test(pem.publicKey), `${sha} public key is properly encoded in PEM format`)

    t.end()
  })
}

test('ECDSA Keypairs', async t => {
  const { privateKey, publicKey } = await ECDSA.createKeypair().catch(t.abort)

  t.ok(privateKey instanceof CryptoKey, 'generate a private ECDSA CryptoKey')
  t.ok(publicKey instanceof CryptoKey, 'generate a public ECDSA CryptoKey')

  const pem = await ECDSA.createKeypairPEM().catch(t.abort)
  t.expect(typeof pem.privateKey, 'string', 'generate private ECDSA key in PEM format')
  t.expect(typeof pem.publicKey, 'string', 'generate public ECDSA key in PEM format')
  t.ok(PEM_PATTERN.test(pem.privateKey), 'ECDSA private key is properly encoded in PEM format')
  t.ok(PEM_PATTERN.test(pem.publicKey), 'ECDSA public key is properly encoded in PEM format')

  t.end()
})

shas = new Set(['ES256', 'ES384'])
if (runtime !== 'deno') {
  shas.add('ES512')
}
for (const sha of shas.values()) {
  test(`ECDSA ${sha} Keypair`, async t => {
    const { privateKey, publicKey } = await ECDSA.createKeypair(sha).catch(t.abort)
    t.ok(privateKey instanceof CryptoKey, `generate a private ${sha} CryptoKey`)
    t.ok(publicKey instanceof CryptoKey, `generate a public ${sha} CryptoKey`)

    const pem = await ECDSA.createKeypairPEM(sha).catch(t.abort)
    t.expect(typeof pem.privateKey, 'string', `generate ${sha} private key in PEM format`)
    t.expect(typeof pem.publicKey, 'string', `generate ${sha} public key in PEM format`)
    t.ok(PEM_PATTERN.test(pem.privateKey), `${sha} private key is properly encoded in PEM format`)
    t.ok(PEM_PATTERN.test(pem.publicKey), `${sha} public key is properly encoded in PEM format`)

    t.end()
  })
}

test('HMAC Keys', async t => {
  const key = await HMAC.createKey(SECRET).catch(t.abort)

  t.ok(key instanceof CryptoKey, 'generate an HMAC CryptoKey')

  const pem = await HMAC.createKeyPEM(SECRET).catch(t.abort)
  t.expect(typeof pem, 'string', 'generate HMAC key in PEM format')
  t.ok(PEM_PATTERN.test(pem), 'HMAC key is properly encoded in PEM format')

  t.end()
})

shas = new Set(['HS256', 'HS384', 'HS512'])
for (const algorithm of shas.values()) {
  test(`HMAC ${algorithm} Key`, async t => {
    const key = await HMAC.createKey(SECRET, algorithm).catch(t.abort)

    t.ok(key instanceof CryptoKey, `generate a ${algorithm} HMAC CryptoKey`)

    const pem = await HMAC.createKeyPEM(SECRET, algorithm).catch(t.abort)
    t.expect(typeof pem, 'string', `generate ${algorithm} HMAC key in PEM format`)
    t.ok(PEM_PATTERN.test(pem), `${algorithm} HMAC key is properly encoded in PEM format`)

    t.end()
  })
}

test('Default Keypairs (ECDSA P-256)', async t => {
  const { privateKey, publicKey } = await createKeypair().catch(t.abort)

  t.ok(privateKey instanceof CryptoKey, 'generate a private CryptoKey')
  t.ok(publicKey instanceof CryptoKey, 'generate a public CryptoKey')

  const pem = await createKeypairPEM().catch(t.abort)
  t.expect(typeof pem.privateKey, 'string', 'generate private key in PEM format')
  t.expect(typeof pem.publicKey, 'string', 'generate public key in PEM format')
  t.ok(PEM_PATTERN.test(pem.privateKey), 'private key is properly encoded in PEM format')
  t.ok(PEM_PATTERN.test(pem.publicKey), 'public key is properly encoded in PEM format')

  t.end()
})
