<h1 align="center">NGN Cryptography Library<br/><img src="https://img.shields.io/npm/v/@ngnjs/libcrypto?label=%40ngnjs/libcrypto&logo=npm&style=social"/></h1>
<div align="center"><em>A standalone library, but part of the <a href="https://github.com/ngnjs/ngn">NGN</a> ecosystem.</em></div><br/>

Live examples on [codepen](https://codepen.io/coreybutler/pen/mdMwQQb).

The NGN crypto library provides simple cryptographic building blocks:

1. Generate RSA or ECDSA Private/Public Keypairs (PEM)
1. Sign & Verify Content (using PEM keys) - Not yet supported by Deno
1. Encrypt/Decrypt Content (AES)
1. One Time Passwords (HOTP/TOTP)
1. Generate/Verify JSON Web Tokens (JWT)

All keys, signatures, and encrypted outputs are Base64 encoded strings (not hex!). Base64 is approximately 25% more efficient than hex (Base16), so the output will be smaller.

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

It is possible to sign and verify content using RSA/ECDSA keypairs in the browser and Node.js. Deno does not yet support the proper WebCrypto algorithms for importing keys, but it is on their roadmap. Once Deno adds support, this library will support signing/verifying in Deno.

Signing/verification currently uses RSA keys. ECDSA support may be available in some browsers and newer versions of Node.js (17.0.0+).

```javascript
const { publicKey, privateKey } = await crypto.generateKeys()
const content = 'crypto makes things safe'
const signature = await crypto.sign(content, privateKey)
const verified = await crypto.verify(content, signature, publicKey)
```

In the example above, a private key is used to sign content. This produces a signature, which can be transmitted alongside the content. The receiver of the content uses the signature and their public key to verify the content.

A common use case for signing/verification is API data delivery. The private key is stored on the server, while the public key is delievered to the client. When the client requests data, the server signs the data with the private key, producing a signature. The data is sent as the response body and the signature is usually included as an HTTP response header. When the client receives the response, the body is verified using the public key and the signature. If verification succeeds, the client can be confident the data came from the appropriate server.

Signing/verification relies on distribution of public keys _prior_ to API communication. Public keys are commonly refreshed/delivered to clients once every 30 days (stored in the browser's IndexedDB or localStorage).

## Reversible Encryption/Decryption

The encrypt/decrypt methods provide a way to encrypt text using a shared encryption key.

```javascript
const sharedKey = 'secret code'
const source = 'crypto makes things hard to read'
const encrypted = await crypto.encrypt(source, sharedKey)
const decrypted = await crypto.decrypt(encrypted, sharedKey)
```

Anyone who obtains the encryption key can decrypt data.

This library produces content that contains a salt, iv, and cipher content `${salt}${iv}${cipher}`. In older Node.js versions which do not support webcrypto, the cipher content is `${salt}${iv}${authTag}${cipher}` where `authTag` is a 16-bit string produced and consumed by encrypt/decypt.

This library will automatically decrypt tokens in the aforementioned format, assuming the appropriate encryption key is provided. Other libraries can decrypt tokens by parsing the `salt `, `iv `, and `cipher` (and `authTag` when appropriate), then performing decryption using these parts and the shared encryption key.

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

Objects are converted to/from strings automatically. Encryption only works on string values, so conversion is always done automatically whenever an attempt to encrypt an object is detected. Decryption will automatically attempt to parse string content into an object. If parsing fails, the decrypted string is returned. To prevent the decrypt method from auto-parsing a string into an object, pass `false` as the third argument to the `decrypt()` method (as illustrated in the very last line of the following example).

```javascript
const obj = { example: true }
const encObj = await crypto.encrypt(obj, encryptionKey)
const decObj = await crypto.decrypt(encObj, encryptionKey)

// Using public/private keys (RSA-OAEP)
const obj = { example: true }
const { publicKey, privateKey } = await crypto.generateRSAKeyPair()
const encObj = await crypto.encrypt(obj, publicKey)
const decObj = await crypto.decrypt(encObj, privateKey[, false])
```

These methods are lightweight wrappers around `encrypt()` and `decrypt()`.

## One Time Passwords (HOTP, TOTP)

This library can generate HMAC-based OTPs and time-based OTPs. TOTPs are compatible with tools like Google Authenticator (see note).

### HMAC-Based One Time Password (HOTP)

**Syntax:**

`HOTP(secret[, options])`

**Options:** _(defaults are shown)_

```javascript
{
  counter: 0,
  algorithm: 'SHA-1', // Other options: SHA-256, SHA-384, SHA-512
  digits: 6, // Can also be 8
}
```

**Example:**

```javascript
const secret = 'password' // 8 character secret (or 16, 24, 32, etc - must be evenly divisible by 8)
const hotp = crypto.HOTP(secret)
console.log(hotp) // 328482
```

### Time-Based One Time Password (TOTP)

**Syntax:**

`TOTP(secret[, options])`

**Options:** _(defaults are shown)_

```javascript
{
  algorithm: 'SHA-1', // Other options: SHA-256, SHA-384, SHA-512
  digits: 6, // Can also be 8
  seconds: 30,
  timestamp: null // Date.getTime() - used to retrieve old values (instead of seconds)
}
```

**Example:**

```javascript
const secret = 'password' // 8 character secret (or 16, 24, 32, etc - must be evenly divisible by 8)
const totp = crypto.TOTP(secret)
console.log(hotp) // 6 digit code changes every 30 seconds
```

#### Google Authenticator

Google Authenticator uses Base32-encoded 16 character secrets.

To generate a key for Google Authenticator, use this library's base32 encoding:

```javascript
const key = crypto.base32.encode('passwordpassword') // Output: OBQXG43XN5ZGI4DBONZXO33SMQ======
```

To produce a UTF-8 string from a base32 string, use this library's base32 decoding:

```javascript
const text = crypt.base32.decode('OBQXG43XN5ZGI4DBONZXO33SMQ======') // Output: passwordpassword
```

## JSON Web Tokens (JWT)

Easily generate and verify JWTs using HMAC (HS), RSA (RS), and ECDSA (EC) 256-bit, 384-bit, or 512-bit algorithms.

```javascript
const secret = 'secret'
const token = await crypto.JWT.createToken({
  secret,
  issuer: 'acme corp',
  account: 'acct name',
  claims: {
    name: 'John Doe',
    admin: true
  },
  headers: { kid: 'testdata' },
  algorithm: 'HS256'
})

const verified = await crypto.JWT.verifyToken(token, secret)
```

The issuer, account (sub), claims, and headers are all optional.

See [here](https://jwt.io/introduction) for general JWT details.

## Exported Functions

The following methods are importable from this module:

```javascript
import {
  encrypt,
  decrypt,
  encryptionAlgorithm,
  generateKeys,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  generateECKeyPair,
  sign,
  verify,
  HOTP,
  TOTP,
  base32,
  PEM,
  JWT
} from '@ngnjs/libcrypto'
```

Most of these are defined in the examples above. The remainder are documented below:

**encryptionAlgorithm(secret)**

Given a shared encryption key or public/private key (PEM), this method determines which encryption algorithm is used.

**PEM**

This is an object/namespace containing several PEM-specific functions:

1. `isKey(string)`_boolean_
2. `isPrivateKey(string)`_boolean_
3. `isPublicKey(string)`_boolean_
4. `typeOf(string)`_string_ (`RSA` or `EC`)
5. *`extractKey(string, algorithm)`_CryptoKey_
6. *`encode(label, code, type)`_string_ (PEM)
7. *`decode(key)`_ArrayBuffer_
8. *`encodePrivateKey(key, type)`_string_ Encodes a private PEM
9. *`encodePublicKey(key, type)`_string_ Encodes a public PEM
10. *`getDefaultAlgorithm(pem, algorithm, type)`_string_ RSA/RSASSA-PKCS1-v1_5/P-256

All functions marked with `*` are designed primarily for internal use, but are exposed to provide granular control over PEM creation/consumption.

---

## Additional Docs

The code contains comments with syntax documentation for all methods.
