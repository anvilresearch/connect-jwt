/**
 * Module dependencies
 */

var JWT = require('./JWT');


/**
 * Expires
 */

function expires (duration) {
  var fromNow = {
    day:   (1000 * 60 * 60 * 24),
    week:  (1000 * 60 * 60 * 24 * 7),
    month: (1000 * 60 * 60 * 24 * 30)
  };

  return function () {
    return Date.now() + fromNow[duration];
  };
}


/**
 * ID Token
 */

var IDToken = JWT.define({

  // default header
  header: {
    alg: 'RS256'
  },

  // permitted headers
  headers: [
    'alg'
  ],

  // modify header schema
  registeredHeaders: {
    alg:   { format: 'StringOrURI', required: true, enum: ['RS256'] }
  },

  // permitted claims
  claims: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'acr', 'at_hash'],

  // modify payload schema
  registeredClaims: {
    iss:      { format: 'StringOrURI', required: true },
    sub:      { format: 'StringOrURI', required: true },
    aud:      { format: 'StringOrURI', required: true },
    exp:      { format: 'IntDate',     required: true, default: expires('day')  },
    iat:      { format: 'IntDate',     required: true, default: Date.now },
    nonce:    { format: 'String' },
    acr:      { format: 'String' },
    at_hash:  { format: 'String' }
  }

});


/**
 * Exports
 */

module.exports = IDToken;
