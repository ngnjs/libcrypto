<h1 align="center">NGN Cryptography<br/><img src="https://img.shields.io/npm/v/@ngnjs/crypto?label=%40ngnjs/crypto&logo=npm&style=social"/></h1>
<div align="center"><em>A part of the <a href="https://github.com/ngnjs/ngn">NGN</a> ecosystem.</em></div><br/>

Live examples on [codepen](https://codepen.io/coreybutler/pen/mdMwQQb).

The NGN crypto library provides simple cryptographic building blocks:

1. Generate RSA or ECDSA Private/Public Keypairs (PEM)
2. Sign & Verify Content (using PEM keys) - Not yet supported by Deno
3. Encrypt/Decrypt Content (AES)

## Generate PEM Keypairs

NGN crypto can generate RSA or ECDSA (EC) private and public keypairs.

```javascript
// Browser/Deno Runtime
import crypto from 'https://cdn.jsdelivr.net/npm/@ngnjs/crypto'
// Node Runtime
// import crypto from '@ngnjs/crypto'

// RSA Keypairs default to 2048-bit encryption using SHA-256
// The first argument is the bit and the second is the hash algorithm.
const { privateKey, publicKey } = await crypto.generateRSAKeyPair()
const { privateKey, publicKey } = await crypto.generateRSAKeyPair(4096, 'SHA-512')

// This is the same as crypto.generateRSAKeyPair()
const { privateKey, publicKey } = await crypto.generateKeys()

// ECDSA (EC) Keypairs use a named curve, defaulting to P-256
const { privateKey, publicKey } = await crypto.generateECDSAKeyPair()
const { privateKey, publicKey } = await crypto.generateECDSAKeyPair('P-521')

// This is the same as crypto.generateECDSAKeyPair()
const { privateKey, publicKey } = await crypto.generateECKeyPair()
```

Public/Private keys are generated in PEM format.

## Sign & Verify Content

It is possible to sign and verify content using RSA/ECDSA keypairs in the browser and Node.js. Deno does not yet support the proper WebCrypto algorithms for importing keys, but it is on the roadmap. Once Deno adds support, this library will support signing/verifying in Deno.

Signing/verification currently uses RSA keys. ECDSA support may be available in some browsers and newer versions of Node.js (17.0.0+).

```javascript
const { publicKey, privateKey } = await crypto.generateKeys()
const content = 'crypto makes things safe'
const signature = await crypto.sign(privateKey, content)
const verified = await crypto.verify(publicKey, signature, content)
```

In the example above, a private key is used to sign content. This produces a signature, which can be transmitted alongside the content. The receiver of the content uses the signature and their public key to verify the content.

A common use case for signing/verification is API data delivery. The private key is stored on the server, while the public key is delievered to the client. When the client requests data, the server signs the data with the private key, producing a signature. The data is sent as the response body and the signature is usually included as an HTTP response header. When the client receives the response, the body is verified using the public key and the signature. If verification succeeds, the client can be confident the data came from the appropriate server.

Signing/verification relies on distribution of public keys _prior_ to API communication. Public keys are commonly refreshed/delivered to clients once every 30 days (stored in the browser's IndexedDB or localStorage).

## Reversible Encryption/Decryption

The encrypt/decrypt methods provide a way to encrypt text using a shared encryption key.

```javascript
const encryptionKey = 'secret code'
const source = 'crypto makes things hard to read'
const encrypted = await crypto.encrypt(source, encryptionKey)
const decrypted = await crypto.decrypt(encrypted, encryptionKey)
```

Anyone who obtains the encryption key can decrypt data.

This library produces content that contains a salt, iv, and cipher content `${salt}-${iv}-${cipher}`. This library will automatically decrypt tokens in this format, assuming the appropriate encryption key is provided. Other libraries can decrypt tokens by parsing the `salt`, `iv`, and `cipher`, then performing decryption using these parts and the shared encryption key.

## Public Key Encryption/Private Key Decryption

It is possible to encrypt content with a public key and decrypt it with the corresponding private key. This produces/uses RSA-OAEP keys (SHA-256).

```javascript
const { publicKey, privateKey } = await crypto.generateRSAKeyPair()
const source = 'crypto makes things hard to read'
const encrypted = await crypto.encrypt(source, publicKey)
const decrypted = await crypto.decrypt(encrypted, privateKey)
```

Typically this is used to encrypt communications. The client receives the private key while the server stores the public key. The server encrypts data with the public key before sending it to the client. The client decrypts data using the private key.

## Encrypt/Decrypt JSON

These convenience methods help manage encryption of JSON objects.

```javascript
const obj = { example: true }
const encObj = await crypto.encryptJSON(obj, encryptionKey)
const decObj = await crypto.decryptJSON(encObj, encryptionKey)

// Using public/private keys (RSA-OAEP)
const obj = { example: true }
const { publicKey, privateKey } = await crypto.generateRSAKeyPair()
const encObj = await crypto.encryptJSON(obj, publicKey)
const decObj = await crypto.decryptJSON(encObj, privateKey)
```

These methods are lightweight wrappers around `encrypt()` and `decrypt()`.
