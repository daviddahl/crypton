/* Crypton Client, Copyright 2015 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

// SJCL Crypto module
var _sjcl = {};

crypton.crypto._sjcl = _sjcl;

/**!
 * ### cipherOptions
 * Sets AES mode to GCM, necessary for SJCL
 */
_sjcl.cipherOptions = {
  mode: 'gcm'
};

/**!
 * ### paranoia
 * Tells SJCL how strict to be about PRNG readiness
 */
_sjcl.paranoia = 6;

/**!
 * ### collectorsStarted
 * Internal flag to know if startCollectors has been called
 */
_sjcl.collectorsStarted = false;

/**!
 * ### startCollectors
 * Start sjcl.random listeners for adding to entropy pool
 */
_sjcl.startCollectors = function () {
  _sjcl.random.startCollectors();
  _sjcl.collectorsStarted = true;
};

/**!
 * ### randomBytes(nbytes)
 * Generate `nbytes` bytes of random data
 *
 * @param {Number} nbytes
 * @return {Array} bitArray
 */
function randomBytes (nbytes) {
  if (!nbytes) {
    throw new Error('randomBytes requires input');
  }

  if (parseInt(nbytes, 10) !== nbytes) {
    throw new Error('randomBytes requires integer input');
  }

  if (nbytes < 4) {
    throw new Error('randomBytes cannot return less than 4 bytes');
  }

  if (nbytes % 4 !== 0) {
    throw new Error('randomBytes requires input as multiple of 4');
  }

  // sjcl's words are 4 bytes (32 bits)
  var nwords = nbytes / 4;
  return _sjcl.random.randomWords(nwords);
}
_sjcl.randomBytes = randomBytes;


/**!
 * ### randomBits(nbits)
 * Generate `nbits` bits of random data
 *
 * @param {Number} nbits
 * @return {Array} bitArray
 */
_sjcl.randomBits = function (nbits) {
  if (!nbits) {
    throw new Error('randomBits requires input');
  }

  if (parseInt(nbits, 10) !== nbits) {
    throw new Error('randomBits requires integer input');
  }

  if (nbits < 32) {
    throw new Error('randomBits cannot return less than 32 bits');
  }

  if (nbits % 32 !== 0) {
    throw new Error('randomBits requires input as multiple of 32');
  }

  var nbytes = nbits / 8;
  return _sjcl.randomBytes(nbytes);
};

/**!
 * ### mac(key, data)
 * Generate an HMAC using `key` for `data`.
 *
 * @param {String} key
 * @param {String} data
 * @return {String} hmacHex
 */
_sjcl.hmac = function(key, data) {
  var mac = new sjcl.misc.hmac(key);
  return sjcl.codec.hex.fromBits(mac.mac(data));
}

/**!
 * ### fingerprint(pubKey, signKeyPub)
 * Generate a fingerprint for an account or peer.
 *
 * @param {PublicKey} pubKey
 * @param {PublicKey} signKeyPub
 * @return {String} hash
 */
// TODO check inputs
_sjcl.fingerprint = function (pubKey, signKeyPub) {
  var pubKeys = sjcl.bitArray.concat(
    pubKey._point.toBits(),
    signKeyPub._point.toBits()
  );

  return _sjcl.hmac('', pubKeys);
};


_sjcl.init = function init() {
  if (!_sjcl.collectorsStarted) {
    _sjcl.startCollectors();
  }
};

_sjcl.options = {};

_sjcl.SIGN_KEY_BIT_LENGTH = 384;

_sjcl.keypairCurve = _sjcl.options.keypairCurve || 384;

_sjcl.account = {};

_sjcl.wrappedKeys = {};

function generateAllAccountKeys(passphrase, callback) {
  try {
    var hmacKey = randomBytes(32);
    var keypairSalt = randomBytes(32);
    var keypairMacSalt = randomBytes(32);
    var signKeyPrivateMacSalt = randomBytes(32);
    var containerNameHmacKey = randomBytes(32);
    var keypairKey = sjcl.misc.pbkdf2(passphrase, keypairSalt);
    var keypairMacKey = sjcl.misc.pbkdf2(passphrase, keypairMacSalt);
    var signKeyPrivateMacKey = sjcl.misc.pbkdf2(passphrase, signKeyPrivateMacSalt);
    var keypair = sjcl.ecc.elGamal.generateKeys(_sjcl.keypairCurve, _sjcl.paranoia);
    var signingKeys = sjcl.ecc.ecdsa.generateKeys(_sjcl.SIGN_KEY_BIT_LENGTH, _sjcl.paranoia);

    var acctKeys = {
      hmacKey: hmacKey,
      keypairSalt: JSON.stringify(keypairSalt),
      keypairMacSalt: JSON.stringify(keypairMacSalt),
      signKeyPrivateMacSalt: JSON.stringify(signKeyPrivateMacSalt),
      containerNameHmacKey: containerNameHmacKey,
      keypairKey: keypairKey,
      keypairMacKey: keypairMacKey,
      signKeyPrivateMacKey: signKeyPrivateMacKey,
      keypair: keypair,
      signingKeys: signingKeys,
      pubKey: JSON.stringify(keypair.pub.serialize()),
      signKeyPub: JSON.stringify(signingKeys.pub.serialize()),
      signKeyPrivate: signingKeys.sec
    };
    _sjcl.account = acctKeys;

    return callback(null, acctKeys);

  } catch (ex) {
    console.error(ex);
    return callback('Cannot generate account keys!');
  }
}

_sjcl.generateAllAccountKeys = generateAllAccountKeys;

// XXXddahl: Must pass in a selfPeer
function wrapAllAccountKeys(selfPeer, callback) {

  var encryptedHmacKey = selfPeer.encryptAndSign(JSON.stringify(_sjcl.account.hmacKey));
  if (encryptedHmacKey.error) {
    callback(encryptedHmacKey.error, null);
    return;
  }

  _sjcl.wrappedKeys.hmacKeyCiphertext = JSON.stringify(encryptedHmacKey);

  var encryptedContainerNameHmacKey =
    selfPeer.encryptAndSign(JSON.stringify(_sjcl.account.containerNameHmacKey));
  if (encryptedContainerNameHmacKey.error) {
    callback(encryptedContainerNameHmacKey.error, null);
    return;
  }

  _sjcl.wrappedKeys.containerNameHmacKeyCiphertext =
    JSON.stringify(encryptedContainerNameHmacKey);

  // private keys
  // TODO: Check data auth with hmac
  _sjcl.wrappedKeys.keypairCiphertext =
    sjcl.encrypt(_sjcl.account.keypairKey,
                 JSON.stringify(_sjcl.account.keypair.sec.serialize()),
                 _sjcl.cipherOptions);
  _sjcl.wrappedKeys.keypairMac =
    _sjcl.hmac(_sjcl.account.keypairMacKey,
               _sjcl.wrappedKeys.keypairCiphertext);
  _sjcl.wrappedKeys.signKeyPrivateCiphertext =
    sjcl.encrypt(_sjcl.account.keypairKey,
                 JSON.stringify(_sjcl.account.signingKeys.sec.serialize()),
                 _sjcl.cipherOptions);
  _sjcl.wrappedKeys.signKeyPrivateMac =
    _sjcl.hmac(_sjcl.account.signKeyPrivateMacKey,
               _sjcl.wrappedKeys.signKeyPrivateCiphertext);

  // XXXddahl: pass off the account + wrapped keys off to account.save()
  // ... or return _sjcl.wrappedKeys
  callback(null, _sjcl.wrappedKeys);

}

_sjcl.wrapAllAccountKeys = wrapAllAccountKeys;

/**!
 * ### regenerateKeys(data, callback)
 * Reconstruct keys from unraveled data
 *
 * Calls back without error if successful
 *
 * __Throws__ if unsuccessful
 *
 * @param {Function} callback
 */
_sjcl.regenerateKeys = function (data, callback) {
  // XXXdahl: Does the pubKey come from the server in data arg?

  var regeneratedKeys = {};

  // reconstruct secret key
  var exponent = sjcl.bn.fromBits(data.secret.exponent);
  this.secretKey = new sjcl.ecc.elGamal.secretKey(data.secret.curve, sjcl.ecc.curves['c' + data.secret.curve], exponent);

  // reconstruct public key
  var point = sjcl.ecc.curves['c' + data.pubKey.curve].fromBits(data.pubKey.point);
  this.pubKey = new sjcl.ecc.elGamal.publicKey(data.pubKey.curve, point.curve, point);

  // assign the hmac keys to the account
  regeneratedKeys.hmacKey = data.hmacKey;
  regeneratedKeys.containerNameHmacKey = data.containerNameHmacKey;

  // reconstruct the public signing key
  var signPoint =
    sjcl.ecc.curves['c' + data.signKeyPub.curve].fromBits(data.signKeyPub.point);
  this.signKeyPub =
    new sjcl.ecc.ecdsa.publicKey(data.signKeyPub.curve,
                                 signPoint.curve, signPoint);

  // reconstruct the secret signing key
  var signExponent = sjcl.bn.fromBits(data.signKeySecret.exponent);
  this.signKeyPrivate = new sjcl.ecc.ecdsa.secretKey(data.signKeySecret.curve, sjcl.ecc.curves['c' + data.signKeySecret.curve], signExponent);

  // calculate fingerprint for public key
  this.fingerprint = crypton.fingerprint(this.pubKey, this.signKeyPub);

  // recalculate the public points from secret exponents
  // and verify that they match what the server sent us
  var pubKeyHex = sjcl.codec.hex.fromBits(this.pubKey._point.toBits());
  var pubKeyShouldBe = this.secretKey._curve.G.mult(exponent);
  var pubKeyShouldBeHex = sjcl.codec.hex.fromBits(pubKeyShouldBe.toBits());

  if (!_sjcl.constEqual(pubKeyHex, pubKeyShouldBeHex)) {
    return callback('Server provided incorrect public key');
  }

  var signKeyPubHex = sjcl.codec.hex.fromBits(data.signKeyPub._point.toBits());
  var signKeyPubShouldBe = data.signKeyPrivate._curve.G.mult(signExponent);
  var signKeyPubShouldBeHex = sjcl.codec.hex.fromBits(signKeyPubShouldBe.toBits());

  if (!_sjcl.constEqual(signKeyPubHex, signKeyPubShouldBeHex)) {
    return callback('Server provided incorrect public signing key');
  }

  // sometimes the account object is used as a peer
  // to make the code simpler. verifyAndDecrypt checks
  // that the peer it is passed is trusted, or returns
  // an error. if we've gotten this far, we can be sure
  // that the public keys are trustable.
  _sjcl.account.trusted = true;

  callback(null, regeneratedKeys);
};
