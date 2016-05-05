/**
 * Module dependecies
 */

var _ = require('lodash')
var jwa = require('jwa')
var jsrsasign = require('jsrsasign')
var validUrl = require('valid-url')
var base64url = require('base64url')

/**
 * Constructor
 */

function JWT (payload, header, signature) {
  this.initializePayload(payload)
  this.initializeHeader(header)
  this.signature = signature
}

/**
 * Traverse
 */

function traverse (keys, schema, source, target, operation, options) {
  if (source) {
    keys.forEach(function (key) {
      var descriptor = schema[key]
      if (!descriptor) { throw new Error(key + ' is not recognized') }
      operation(key, descriptor, source, target, options)
    })
  }
}

JWT.traverse = traverse

/**
 * Assign Valid
 */

function assignValid (key, descriptor, source, target, options) {
  // read the source value
  var value = source[descriptor.from] || source[key]

  // set the default value
  if (!value && typeof descriptor.default !== 'undefined') {
    value = (typeof descriptor.default === 'function')
      ? descriptor.default()
      : descriptor.default
  }

  // ensure a required value is present
  assertPresence(key, value, descriptor)

  // verify and assign
  if (value) {
    assertFormat(key, value, descriptor)
    assertEnumerated(key, value, descriptor)
    target[key] = value
  }
}

JWT.assignValid = assignValid

/**
 * Assert Presence
 */

function assertPresence (key, value, descriptor) {
  if (descriptor.required && !value) {
    throw new Error(key + ' is a required value')
  } else {
    return true
  }
}

JWT.assertPresence = assertPresence

/**
 * Assert Format
 */

function assertFormat (key, value, descriptor) {
  var fn = JWT.formats[descriptor.format]

  if (!fn) {
    throw new Error(
      descriptor.format + ' is not a recognized format'
    )
  }

  if (!fn(value)) {
    throw new Error(
      key + ' must conform to ' + descriptor.format + ' format'
    )
  }

  return true
}

JWT.assertFormat = assertFormat

/**
 * Assert Enumerated
 */

function assertEnumerated (key, value, descriptor) {
  var enumeration = descriptor.enum
  if (enumeration && enumeration.indexOf(value) === -1) {
    throw new Error(key + ' must be an enumerated value')
  } else {
    return true
  }
}

JWT.assertEnumerated = assertEnumerated

/**
 * Initialize header
 */

JWT.prototype.initializeHeader = function (header) {
  // skip initialization where possible
  if (!header && this.header) { return }

  var keys = this.constructor.headers
  var schema = this.constructor.registeredHeaders
  var source = header
  var target = this.header = {}
  var operation = JWT.assignValid
  var options = {}

  // define the instance header and compute base64url
  JWT.traverse(keys, schema, source, target, operation, options)
  this.headerB64u = base64url(JSON.stringify(target))
}

/**
 * Initialize payload
 */

JWT.prototype.initializePayload = function (payload) {
  var keys = this.constructor.claims
  var schema = this.constructor.registeredClaims
  var source = payload
  var target = this.payload = {}
  var operation = JWT.assignValid
  var options = {}

  JWT.traverse(keys, schema, source, target, operation, options)
}

/**
 * Supported algorithms
 */

JWT.algorithms = [
  'none',
  'HS256',
  'RS256',
  'ES256'
]

/**
 * Registered headers
 */

JWT.registeredHeaders = {
  alg: { format: 'StringOrURI', required: true, enum: _.clone(JWT.algorithms, true) },
  typ: { format: 'String', default: 'JWT' },
  cty: { format: 'String', enum: ['JWT'] },
  jku: { format: 'URI' },
  jwk: { format: 'JWK' },
  kid: { format: 'String' },
  x5u: { format: 'URI' },
  x5c: { format: 'CertificateOrChain' },
  x5t: { format: 'CertificateThumbprint' },
  crit: { format: 'ParameterList' }
}

/**
 * Registered claims
 */

JWT.registeredClaims = {
  iss: { format: 'StringOrURI' },
  sub: { format: 'StringOrURI' },
  aud: { format: 'StringOrURI*' },
  exp: { format: 'IntDate' },
  nbf: { format: 'IntDate' },
  iat: { format: 'IntDate' },
  jti: { format: 'CaseSensitiveString' }
}

/**
 * Default selected headers and claims
 */

JWT.headers = Object.keys(JWT.registeredHeaders)
JWT.claims = Object.keys(JWT.registeredClaims)

/**
 * Formats
 */

JWT.formats = {
  'StringOrURI': function (value) {
    // it has to be a string
    if (typeof value !== 'string') {
      return false
    }

    // if the string contains `:`, it must be a valid uri
    if (value.indexOf(':') !== -1 && !validUrl.isWebUri(value)) {
      return false
    }

    return true
  },

  'String': function (value) {
    return value && typeof value === 'string'
  },

  'String*': function (values) {
    // must be an array
    if (!Array.isArray(values)) {
      return false
    }

    // must contain only strings
    var notStrings = values.some(function (value) {
      return (typeof value !== 'string')
    })

    if (notStrings) {
      return false
    }

    return true
  },

  'IntDate': function (value) {
    return !isNaN(value) && parseInt(value, 10) === value
  },

  'URI': function (value) {
    return Boolean(validUrl.isWebUri(value))
  }

}

/**
 * Define
 */

function F () {}

JWT.define = function (spec) {
  var superClass = this

  // constructor should invoke the superclass
  var subClass = function () {
    superClass.apply(this, arguments)
  }

  // optimize the prototype chain
  F.prototype = superClass.prototype
  subClass.prototype = new F()

  // reference the correct constructor
  subClass.prototype.constructor = subClass

  // reference the parent class
  subClass.super = superClass

  // make the static methods available
  // available to be called from subClass
  _.extend(subClass, superClass)

  // we need to deep copy these objects so
  // changes don't affect the superclass
  // TODO:
  // 1. test for deep copy
  // 2. do it as part of previous step
  subClass.registeredHeaders = _.clone(superClass.registeredHeaders, true)
  subClass.registeredClaims = _.clone(superClass.registeredClaims, true)

  // customize registered headers and claims
  // TODO:
  // can this and the header/claims sets be done in one step with deep copy?
  _.extend(subClass.registeredHeaders, spec.registeredHeaders)
  _.extend(subClass.registeredClaims, spec.registeredClaims)

  // override default header and claim sets
  if (spec.headers) { subClass.headers = spec.headers }
  if (spec.claims) { subClass.claims = spec.claims }

  // assign default header
  // this must be done after registeredHeaders are copied
  // and the set of headers is defined
  if (spec.header) {
    subClass.prototype.initializeHeader(spec.header)
  }

  return subClass
}

/**
 * Encode
 */

JWT.prototype.encode = function (secret) {
  // JWT Spec requires valid payload, header and supported algortitm
  // If this method is invoked on an instance, all of these properties
  // should be pre-validated by the constructor.

  // initialize the components
  var headerB64u = this.headerB64u
  var payloadB64u = base64url(JSON.stringify(this.payload))
  var input = headerB64u + '.' + payloadB64u
  var algorithm = this.header.alg
  var signature

  // Plaintext
  if (algorithm === 'none') {
    signature = ''

  // JWE
  } else if (this.header.enc) {
    // make a JWE

  // JWS
  } else {
    this.signature = signature = jwa(algorithm).sign(input, secret)
  }

  return input + '.' + signature
}

/**
 * Assert JWT
 *
 * This covers the inclusion of dots requirement in Draft IETF OAuth
 * JWT 18 Section 7, as well as the number of components requirements
 * Draft IETF JOSE JWS 23 Section 5.2 and ...
 * and JWE.
 */

JWT.extractComponents = function (token) {
  var components = token.split('.')

  if ([3, 5].indexOf(components.length) === -1) {
    throw new Error('Malformed JWT')
  }

  return components
}

/**
 * Decodes (and verifies if appropriate) the JWT string and returns a JWT object
 * instance.
 * @method decode
 * @param token {String} JSON Web Token string
 * @param secret {String|Object}
 * @param [noVerify=false] {Boolean} Optional flag to skip verification (useful
 *   when first extracting the issuer to instantiate an OIDC client, and later
 *   verifying). Defaults to `false`.
 * @return {JWT} A parsed JWT object
 */
JWT.decode = function (token, secret, noVerify) {
  var Jwt = this
  var components, header, payload, signature

  try {
    // extract serialized values
    components = JWT.extractComponents(token)

    // decode/parse header
    header = JSON.parse(base64url.decode(components[0]))

    // plaintext JWT
    // Note: if noVerify=true, a JWS is treated as a plaintext JWT
    // (not currently supporting JWE situation)
    if (header.alg === 'none' || noVerify) {
      payload = JSON.parse(base64url.decode(components[1]))
      signature = components[2] // ''

    // JWE
    } else if (header.enc) {
      if (header.cty) { // nested
      } else { // not nested
      }

    // it's a JWS (and noVerify=false)
    } else {
      signature = components[2]
      var verified = false

      // If the secret is a string, use JWA to verify signature

      if (typeof secret === 'string') {
        var verifier = jwa(header.alg)
        var input = components[0] + '.' + components[1]

        verified = verifier.verify(input, signature, secret)

      // If the secret is a JWK object, use jsjws
      } else if (typeof secret === 'object' && secret.n && secret.e) {
        // We want to use a JWK that we're going to pull from our auth
        // server's JWK set uri. This is to avoid having to configure
        // the public key, which makes using the lib easier in the first
        // place and also simplifies things if and when the issuer rotates
        // keypairs.
        //
        // The native crypto package can only handle a PEM representation
        // of an RSA public key, not the raw hex encoded modulus and exponent
        // parameters.
        //
        // We could be calling a function in jsrsasign and bypass the redundant
        // JWT decoding that jsjws will do here. But that function isn't
        // exposed in the node version of jsrsasign so we can't access it.
        //
        // Using jsjws is stopgap until there's a cleaner way.
        var hN = base64url.decode(secret.n, 'hex')
        var hE = base64url.decode(secret.e, 'hex')
        var pubkey = jsrsasign.KEYUTIL.getKey({ n: hN, e: hE })

        verified = jsrsasign.jws.JWS.verify(token, pubkey)
      }

      if (!verified) {
        return null
      } else {
        payload = JSON.parse(base64url.decode(components[1]))
      }
    }

    return new Jwt(payload, header, signature)
  } catch (e) {
    return e
  }
}

/**
 * Exports
 */

module.exports = JWT
