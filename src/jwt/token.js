import { HOUR } from '../lib/base.js'
import { normalizeKey } from '../encoding/pem.js'
import { normalize, SIGNING_ALGORITHMS } from '../lib/algorithms.js'
import { createKeypair, extractKeyType } from '../keys/keypair.js'
import {
  ArrayBufferToString,
  ATOB,
  BTOA,
  StringToArrayBuffer
} from '../encoding/common.js'
import {
  UrlBase64ToBase64,
  UrlBase64ToString,
  BinaryStringToUrlBase64,
  StringToUrlBase64,
  UrlBase64ToBinaryString,
  ArrayBufferToBase64,
  Base64ToArrayBuffer
} from '../encoding/base64.js'
import { base64url } from 'rfc4648'

const encoder = new TextEncoder()

export class JsonWebToken {
  // Registered claims
  #iss                                // OPTIONAL Issuer (StringOrURI)
  #sub                                // OPTIONAL Subject (StringOrURI)
  #aud                                // OPTIONAL Audience (array of StringOrURI)
  #azp                                // OPTIONAL Authorized party (typically 3rd party)
  #exp = new Date().getTime() + HOUR  // Expiration Time
  #nbf = new Date().getTime()         // Not Before date/time
  #iat = new Date().getTime()         // Issued At date/time
  #jti = NANOID(28)                   // JWT ID

  // Private clains
  #claims = {}

  // Additional attributes
  #jwk                                // JSON Web Key(pair)
  #algorithm = 'none'                 // Default algorithm
  #jws                                // JSON web signature

  // Key attributes
  #headers = { typ: 'JWT', alg: 'none' }

  // Parse an existing encoded JWT
  #parse (encodedJwt) {
    const [header, claims, jws] = encodedJwt.split('.')

    // Populate headers
    this.#headers = JSON.parse(ATOB(UrlBase64ToBase64(header)))

    // Apply the algorithm if detected
    this.#algorithm = this.#headers?.alg || 'none'

    // Apply claims
    this.#claims = {}
    for (const [key, value] of Object.entries(JSON.parse(ATOB(UrlBase64ToBase64(claims))))) {
      if (key === 'jti') {
        this.#jti = value
      } else if (this.hasOwnProperty(key)) {
        this[key] = value
      } else {
        this.addClaim(key, value)
      }
    }

    this.#jws = jws
  }

  constructor (cfg = {}) {
    if (typeof cfg === 'string') {
      this.#parse(cfg)
    } else {
      for (const [key, value] of Object.entries(cfg)) {
        this[key] = value
      }
    }
  }

  get azp () { return this.#azp }
  get authorizedparty () { return this.azp }
  set azp (value) { this.#azp = value; }
  set authorizedparty(value) { this.azp = value }
  get sub () { return this.#sub || null }
  get subject () { return this.sub }
  get account () { return this.sub }
  set sub (value) { this.#sub = value }
  set subject (value) { this.sub = value }
  set account (value) { this.sub = value }
  get alg () { return this.#algorithm }
  get algorithm () { return this.alg }
  set alg (value) {
    const old = this.#algorithm.toUpperCase()
    value = value.toUpperCase()

    if (!SIGNING_ALGORITHMS[value]) {
      throw new Error(`invalid algorithm "${value}" - valid options include: ${Object.keys(SIGNING_ALGORITHMS).join(', ')}`)
    }

    if (value !== old) {
      this.#jwk = null
    }

    this.#algorithm = value
  }
  set algorithm (value) { this.alg = value }
  get aud () { return this.#aud || null }
  get audience () { return this.aud }
  set aud (value) { this.#aud = value }
  set audience (value) { this.aud = value }
  get iss () { return this.#iss || null }
  get issuer () { return this.iss }
  set iss (value) { this.#iss = value }
  set issuer (value) { this.iss = value }
  get exp () { return new Date(this.#exp) }
  get expiration () { return this.exp }
  get expire () { return this.exp }
  get notafter () { return this.exp }
  set exp (value) {
    if (!(value instanceof Date)) {
      throw new Error('expiration must be a date object')
    }

    this.#exp = value.getTime()
  }
  set expiration (value) { this.exp = value }
  set expire (value) { this.exp = value }
  set notafter (value) { this.exp = value }
  get nbf () { return this.#nbf }
  get notbefore () { return this.nbf }
  set nbf (value) {
    if (!(value instanceof Date)) {
      throw new Error('notbefore must be a date object')
    }

    selfthis.#nbf = value.getTime()
  }
  set notbefore (value) { this.nbf = value }
  get iat () { return Date.UTC(this.#iat) }
  get issuedat () { return this.iat }
  get issuedate () { return this.iat }
  set iat (value) {
    if (!(value instanceof Date)) {
      throw new Error('issuedat (iat) must be a date object')
    }

    this.#iat = value.getTime()
  }
  set issuedat (value) { this.iat = value }
  set issuedate (value) { this.iat = value }
  get id () { return this.#jti }
  get claims () { return this.#claims }
  set claims (value) {
    if (typeof value !== 'object') {
      throw new Error(`claims must be a key/value object, not ${typeof value}`)
    }

    this.#claims = value
  }

  /**
   * @property {Object}
   * The raw data (i.e. all claims) as an object.
   * @readonly
   */
  get raw () {
    const result = this.#claims
    if (this.#iss) {
      result.iss = this.#iss
    }
    if (this.#sub) {
      result.sub = this.#sub
    }
    if (this.#aud) {
      result.aud = this.#aud
    }
    if (this.#azp) {
      result.azp = this.#azp
    }
    if (this.#exp) {
      result.exp = this.#exp
    }
    if (this.#nbf) {
      result.nbf = this.#nbf
    }
    if (this.#iat) {
      result.iat = this.#iat
    }
    if (this.#jti) {
      result.jti = this.#jti
    }
    return result
  }

  /**
   * @property {Object}
   * All claims, as an object, formatted for JS.
   * This primarily converts dates from an epoch
   * number to a JS date (when applicable).
   * @readonly
   */
  get data () {
    const result = Object.assign({}, this.raw)
    if (result?.exp) {
      result.exp = new Date(result.exp)
    }
    if (result?.nbf) {
      result.nbf = new Date(result.nbf)
    }
    if (result?.iat) {
      result.iat = new Date(result.iat)
    }

    return result
  }

  /**
   * @property {Object}
   * The raw JWT header, as an object.
   * @readonly
   */
  get rawHeader () {
    return Object.assign(this.#headers, { alg: this.#algorithm })
  }

  /**
   * @property {Object}
   * The base64 representation of the JWT header.
   * @readonly
   */
  get header () {
    return StringToUrlBase64(JSON.stringify(this.rawHeader))
  }

  /**
   * The base64 representation of the JWT data.
   * @type {string}
   */
  get payload () {
    return StringToUrlBase64(JSON.stringify(this.raw))
  }

  /**
   * Add a registered, public, or private claim
   * to the JWT.
   * @param {string} name
   * The name of the claim.
   * @param {*} value
   * The value of the claim. This is usually a string,
   * but can be any JSON value.
   */
  addClaim (name, value) {
    this.#claims[name] = value
  }

  /**
   * Remove a claim from the JWT.
   * @param {string} name
   */
  removeClaim (name) {
    delete this.#claims[name]
  }

  /**
   * JSON Web Token Key
   * @returns {Object}
   */
  async jwk () {
    if (this.#algorithm === 'none') {
      return {}
    }

    if (this.#jwk) {
      const key = await normalizeKey(this.#jwk.privateKey)
      return await crypto.subtle.exportKey('jwk', key)
    }

    const algorithm = normalize(this.#algorithm, SIGNING_ALGORITHMS)
    const keypair = await createKeypair(algorithm)

    this.#jwk = keypair

    if (keypair?.privateKey) {
      return await crypto.subtle.exportKey('jwk', keypair.privateKey)
    }

    return null
  }

  async verificationKey () {
    if (!this.#jwk) {
      await this.jwk()
    }

    return await crypto.subtle.exportKey('jwk', this.#jwk.publicKey)
  }

  async signingKey () {
    if (!this.#jwk) {
      await this.jwk()
    }

    return await crypto.subtle.exportKey('jwk', this.#jwk.privateKey)
  }

  /**
   * JSON Web (Token) Signature
   * @param {boolean} [renew=false]
   * Optionally renew the JSON web signature.
   * @returns {string}
   * The base64 signature of the token.
   */
  async jws (renew = false) {
    if (this.#jws && !renew) {
      return this.#jws
    }

    // Add the key ID to the header
    this.#headers.kid = await this.fingerprint()

    const cfg = SIGNING_ALGORITHMS[this.#algorithm]
    const jwk = await this.jwk()
    const data = `${this.header}.${this.payload}`
    const [keytype] = extractKeyType(this.#algorithm)
    const key = await crypto.subtle.importKey('jwk', jwk, keytype, true, ['sign'])

    if (/^[R|P]S[0-9]+/.test(this.#algorithm)) {
      cfg.saltLength = saltLength(key)

      if (cfg.saltLength !== SIGNING_ALGORITHMS[this.#algorithm].saltLength) {
        throw new Error(`Invalid signing key: ${this.#algorithm} expected a salt length of ${SIGNING_ALGORITHMS[this.#algorithm].saltLength} but received ${cfg.saltLength}`)
      }
    }

    const signature = await crypto.subtle.sign(
      cfg,
      key,
      encoder.encode(data)
    )

    const xxx = await crypto.subtle.importKey(
      'jwk',
      await this.verificationKey(),
      cfg,
      false,
      ['verify']
    )//.catch(e => console.log(',.,.,.>>>', e))
    console.log({xxx})
    console.log({
      cfg,
      xxx,
      signature,
      value: encoder.encode(`${this.header}.${this.payload}`)
    })

    this.#jws = BinaryStringToUrlBase64(ArrayBufferToString(new Uint8Array(signature)))

    // const xsig = new Uint8Array(StringToArrayBuffer(UrlBase64ToBinaryString(signature)))
    const xsig = new Uint8Array(StringToArrayBuffer(UrlBase64ToBinaryString(this.#jws))).buffer

    console.log({
      signature,
      xsig,
      s: new Uint8Array(signature) == new Uint8Array(xsig),
      cfg
    })

    const rr = await crypto.subtle.verify(
      cfg,
      xxx,
      xsig,
      // signature,
      encoder.encode(`${this.header}.${this.payload}`)
    )
    console.log({rr})

    console.log({
      raw: signature,
      uint8a: new Uint8Array(signature),
      ab: ArrayBufferToString(new Uint8Array(signature)),
      b64url: this.#jws
    })

    return this.#jws
  }

  /**
   * The fingerprint is the `kid` value of the header,
   * which is a unique ID associated with the JSON Web
   * Token Key.
   * @returns {string}
   * The base64 ID of the JWK (JSON Web Token Key)
   */
  async fingerprint () {
    const jwk = await this.jwk()
    const publicKey = `{"crv":"${jwk.crv}","kty","${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`
    const algorithm = normalize(this.#algorithm)
    const hash = await crypto.subtle.digest({ name: algorithm.hash.name }, encoder.encode(publicKey))

    return BinaryStringToUrlBase64(ArrayBufferToString(hash))
  }

  /**
   * The string representation of the JWT.
   * @returns {string}
   * The base64 string representation of the JWT
   */
  async toString () {
    return `${this.header}.${this.payload}.${await this.jws()}`
  }

  /**
   * Verify the token against a JSON Web (Token) Key
   * @param {object|CryptoKey} jwk
   * The key, as either a JSON object or the CryptoKey imported from a JWK.
   * @returns {boolean}
   */
  async verify (jwk) {
    let algorithm = normalize(jwk?.algorithm || this.#algorithm)

    if (!(jwk instanceof CryptoKey)) {
      jwk = await crypto.subtle.importKey(
        'jwk',
        jwk,
        algorithm,
        false,
        ['verify']
      )
    }

    const signature = await this.jws()
    console.log('\n\n\n---------------------\n\n\n')
    console.log({
      raw: StringToArrayBuffer(UrlBase64ToBinaryString(signature)),
      x: new Uint8Array(StringToArrayBuffer(UrlBase64ToBinaryString(signature))).buffer,
      uint8a: new Uint8Array(StringToArrayBuffer(UrlBase64ToBinaryString(signature))),
      ab: UrlBase64ToBinaryString(signature),
      b64url: signature
    })
    console.log({
      prfix: `${this.header}.${this.payload}`,
      binstring: UrlBase64ToBinaryString(BTOA(StringToArrayBuffer(`${this.header}.${this.payload}`)))
    })
    // console.log(StringToArrayBuffer(signature))
    // console.log({ signature, decoded: UrlBase64ToString(signature)})

    // const x = s => Base64ToArrayBuffer(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))

    // const rr = await crypto.subtle.verify(
    //   algorithm,
    //   jwk,
    //   base64url.parse(signature, { loose: true }),
    //   encoder.encode(`${this.header}.${this.payload}`)
    // )
    // console.log({ rr })

    const xxx = await crypto.subtle.importKey(
      'jwk',
      await this.verificationKey(),
      algorithm,
      false,
      ['verify']
    )//.catch(e => console.log(',.,.,.>>>', e))
    console.log({ xxx, algorithm })
    const xsig = new Uint8Array(StringToArrayBuffer(UrlBase64ToBinaryString(signature))).buffer
    console.log({siggy: new Uint8Array(xsig)})
    const rrr = await crypto.subtle.verify(
      algorithm,
      xxx,
      xsig,
      // StringToArrayBuffer(UrlBase64ToBinaryString(signature)),
      // signature,
      encoder.encode(`${this.header}.${this.payload}`)
    )
    console.log({ rrr })

    const r = await crypto.subtle.verify(
      algorithm,
      jwk,
      // Base64 URL parse
      x(signature),
      // StringToArrayBuffer(UrlBase64ToBinaryString(signature)),
      encoder.encode(`${this.header}.${this.payload}`)
      // StringToArrayBuffer(UrlBase64ToBinaryString(BTOA(StringToArrayBuffer(`${this.header}.${this.payload}`))))
      // StringToArrayBuffer(UrlBase64ToBinaryString(`${this.header}.${this.payload}`))
      // encoder.encode(UrlBase64ToBinaryString(BTOA(StringToArrayBuffer(`${this.header}.${this.payload}`))))
      // BTOA(`${this.header}.${this.payload}`).buffer
      // StringToArrayBuffer(UrlBase64ToBinaryString(`${this.header}.${this.payload}`))
    )
    console.log(r)

    return r
  }
}



function NANOID (size = 21) {
  if (typeof size === 'string') {
    size = isNaN(size) ? 21 : parseInt(size, 10)
  }

  const bytes = crypto.getRandomValues(new Uint8Array(size))
  let id = ''
  while (size--) {
    const n = 63 & bytes[size]
    id += n < 36 ? n.toString(36) : n < 62 ? (n - 26).toString(36).toUpperCase() : n < 63 ? '_' : '-'
  }

  return id
}
