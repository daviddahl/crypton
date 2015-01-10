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

// Crypto module abstraction

var crypto = {};

crypton.crypto = crypto;

/**!
 * ### constEqual()
 * Compare two strings in constant time.
 *
 * @param {String} str1
 * @param {String} str2
 * @return {bool} equal
 */
function constEqual (str1, str2) {
  // We only support string comparison, we could support Arrays but
  // they would need to be single char elements or compare multichar
  // elements constantly. Going for simplicity for now.
  // TODO: Consider this ^
  if (typeof str1 !== 'string' || typeof str2 !== 'string') {
    return false;
  }

  var mismatch = str1.length ^ str2.length;
  var len = Math.min(str1.length, str2.length);

  for (var i = 0; i < len; i++) {
    mismatch |= str1.charCodeAt(i) ^ str2.charCodeAt(i);
  }

  return mismatch === 0;
}
crypto.constEqual = constEqual;

// need crypto.hmac function

/**!
 * ### macAndCompare(key, data, otherMac)
 * Generate an HMAC using `key` for `data` and compare it in
 * constant time to `otherMac`.
 *
 * @param {String} key
 * @param {String} data
 * @param {String} otherMac
 * @return {Bool} compare succeeded
 */
crypto.hmacAndCompare = function(key, data, otherMac) {
  var ourMac = crypto.hmac(key, data);
  return crypto.constEqual(ourMac, otherMac);
};
