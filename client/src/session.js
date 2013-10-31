/* Crypton Client, Copyright 2013 SpiderOak, Inc.
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

(function () {

'use strict';

/**!
 * # Session(id)
 *
 * ````
 * var session = new crypton.Session(id);
 * ````
 *
 * @param {Number} id
 */
var Session = crypton.Session = function (id) {
  this.id = id;
  this.peers = [];
  this.events = [];
  this.containers = [];
  this.inbox = new crypton.Inbox(this);

  var that = this;
  this.socket = io.connect(crypton.url(), {
    secure: true
  });

  this.socket.on('message', function (data) {
    that.inbox.poll();
    that.emit('message', {
      messageId: data.messageId
    });
  });
};

/**!
 * ### load(containerName, callback)
 * Retieve container with given platintext `containerName`,
 * either from local cache or server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.load = function (containerName, callback) {
  // check for a locally stored container
  for (var i in this.containers) {
    if (this.containers[i].name == containerName) {
      callback(null, this.containers[i]);
      return;
    }
  }

  // check for a container on the server
  var that = this;
  this.getContainer(containerName, function (err, container) {
    if (err) {
      callback(err);
      return;
    }

    that.containers.push(container);
    callback(null, container);
  });
};

/**!
 * ### create(containerName, callback)
 * Create container with given platintext `containerName`,
 * save it to server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.create = function (containerName, callback) {
  for (var i in this.containers) {
    if (this.containers[i].name == containerName) {
      callback('Container already exists');
      return;
    }
  }

  var sessionKey = crypton.randomBytes(8);
  var hmacKey = crypton.randomBytes(8);
  var sessionKeyCiphertext = sjcl.encrypt(this.account.symkey, JSON.stringify(sessionKey), crypton.cipherOptions);
  var hmacKeyCiphertext = sjcl.encrypt(this.account.symkey, JSON.stringify(hmacKey), crypton.cipherOptions);

  var keyshmac = new sjcl.misc.hmac(crypton.randomBytes(8));
  keyshmac = sjcl.codec.hex.fromBits(keyshmac.encrypt(JSON.stringify(sessionKey) + JSON.stringify(hmacKey)));

  var signature = 'hello'; // TODO sign with private key
  var containerNameHmac = new sjcl.misc.hmac(this.account.containerNameHmacKey);
  containerNameHmac = sjcl.codec.hex.fromBits(containerNameHmac.encrypt(containerName));
  var payloadCiphertext = sjcl.encrypt(hmacKey, JSON.stringify({}), crypton.cipherOptions);

  var that = this;
  new crypton.Transaction(this, function (err, tx) {
    var chunks = [
      {
        type: 'addContainer',
        containerNameHmac: containerNameHmac
      }, {
        type: 'addContainerSessionKey',
        containerNameHmac: containerNameHmac,
        signature: signature
      }, {
        type: 'addContainerSessionKeyShare',
        containerNameHmac: containerNameHmac,
        sessionKeyCiphertext: sessionKeyCiphertext,
        hmacKeyCiphertext: hmacKeyCiphertext
      }, {
        type: 'addContainerRecord',
        containerNameHmac: containerNameHmac,
        payloadCiphertext: payloadCiphertext
      }
    ];

    async.each(chunks, function (chunk, callback) {
      tx.save(chunk, callback);
    }, function (err) {
      // TODO handle err
      if (err) {
        console.log(err);
        return;
      }

      tx.commit(function () {
        var container = new crypton.Container(that);
        container.name = containerName;
        container.sessionKey = sessionKey;
        container.hmacKey = hmacKey;
        that.containers.push(container);
        callback(null, container);
      });
    });
  });
};

/**!
 * ### getContainer(containerName, callback)
 * Retrieve container with given platintext `containerName`
 * specifically from the server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.getContainer = function (containerName, callback) {
  var container = new crypton.Container(this);
  container.name = containerName;
  container.sync(function (err) {
    callback(err, container);
  });
};

/**!
 * ### getPeer(containerName, callback)
 * Retrieve a peer object from the database for given `username`
 *
 * Calls back with peer and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} username
 * @param {Function} callback
 */
Session.prototype.getPeer = function (username, callback) {
  if (this.peers[username]) {
    callback(null, this.peers[username]);
    return;
  }

  var that = this;
  var peer = new crypton.Peer();
  peer.username = username;
  peer.session = this;

  peer.fetch(function (err, peer) {
    if (err) {
      callback(err);
      return;
    }

    that.peers[username] = peer;
    callback(err, peer);
  });
};

/**!
 * ### getSignalingAuthToken(username, serviceID, callback)
 * Get the JWT from the server for use with vLine
 *
 * Calls back with peer and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} username
 * @param {Function} callback
 */
Session.prototype.getSignalingAuthToken = function (username, callback) {
  var that = this;
  // hash the username so we don't reveal it to signaling service:
  var bitArray = sjcl.hash.sha256.hash(username);
  var username_sha256 = sjcl.codec.hex.fromBits(bitArray);

  var url = crypton.url() + '/signaling-token/' +
    username + "/" +
    username_sha256;
  superagent.get(url).set('x-session-identifier', that.id)
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }
    // Success
    var signalingObj = res.body.signalingObj;
    callback(null, signalingObj);
  });
};

/**!
 * ### getUsernameFromHash(hash, callback)
 * Get the username from a sha256 hash of the username
 *
 * Calls back with hash and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} hash
 * @param {Function} callback
 */
Session.prototype.getUsernameFromHash = function (hash, callback) {
  var that = this;

  var url = crypton.url() + '/username-from-hash/' + hash;
  superagent.get(url).set('x-session-identifier', that.id)
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }
    // Success
    var hashObj = res.body;
    callback(null, hashObj);
  });
};

/**!
 * ### on(eventName, listener)
 * Set `listener` to be called anytime `eventName` is emitted
 *
 * @param {String} eventName
 * @param {Function} listener
 */
// TODO allow multiple listeners
Session.prototype.on = function (eventName, listener) {
  this.events[eventName] = listener;
};

/**!
 * ### emit(eventName, data)
 * Call listener for `eventName`, passing it `data` as an argument
 *
 * @param {String} eventName
 * @param {Object} data
 */
// TODO allow multiple listeners
Session.prototype.emit = function (eventName, data) {
  this.events[eventName] && this.events[eventName](data);
};

})();
