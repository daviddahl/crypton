/* Crypton Server, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Server.
 *
 * Crypton Server is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Server is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Server.  If not, see <http://www.gnu.org/licenses/>.
*/

'use strict';

var connect = require('./').connect;

/**!
 * ### saveAccount(account, callback)
 * Create account and base_keyring rows with data
 * and add account row with base_keyring_id
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} account
 * @param {Function} callback
 */
exports.saveAccount = function saveAccount(account, callback) {
  var requiredFields = [
    'username',
    'sha256Username',
    'keypairCiphertext',
    'keypairSalt',
    'pubKey',
    'symKeyCiphertext',
    'containerNameHmacKeyCiphertext',
    'hmacKeyCiphertext',
    'challengeKeySalt',
    'challengeKeyHash'
  ];

  for (var i in requiredFields) {
    if (!account[requiredFields[i]]) {
      callback('Missing field: ' + requiredFields[i]);
      return;
    }
  }

  connect(function (client, done) {
    client.query('begin');

    var accountQuery = {
      text:
        "insert into account (username, sha256_username, base_keyring_id) " +
        "values ($1, $2, nextval('version_identifier')) " +
        "returning account_id, base_keyring_id",
      values: [
        account.username,
        account.sha256Username
      ]
    };

    client.query(accountQuery, function (err, result) {
      if (err) {
        client.query('rollback');
        done();

        if (err.code === '23505') {
          callback('Username already taken.');
        } else {
          console.log('Unhandled database error: ' + err);
          callback('Database error.');
        }

        return;
      }

      var keyringQuery = {
        text:
          "insert into base_keyring (" +
          "  base_keyring_id, account_id," +
          "  keypair, keypair_salt, pubkey, symkey," +
          "  container_name_hmac_key," +
          "  hmac_key, challenge_key_salt, challenge_key_hash" +
          ") values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        values: [
          result.rows[0].base_keyring_id,
          result.rows[0].account_id,
          account.keypairCiphertext,
          account.keypairSalt,
          account.pubKey,
          account.symKeyCiphertext,
          account.containerNameHmacKeyCiphertext,
          account.hmacKeyCiphertext,
          account.challengeKeySalt,
          account.challengeKeyHash
        ]
      };

      client.query(keyringQuery, function (err) {
        if (err) {
          client.query('rollback');
          done();

          if (err.code === '23514') {
            callback('Invalid keyring data.');
          } else {
            console.log('Unhandled database error: ' + err);
            callback('Database error.');
          }

          return;
        }

        client.query('commit', function () {
          done();
          callback();
        });
      });
    });
  });
};

/**!
 * ### getAccount(username, callback)
 * Retrieve account and base_keyring rows for given `username`
 *
 * Calls back with account object and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} username
 * @param {Function} callback
 */
exports.getAccount = function getAccount(username, callback) {
  connect(function (client, done) {
    var accountQuery = {
      text:
        "select username, " +
        "sha256_username, " +
        "account.account_id, base_keyring_id, " +
        "challenge_key_hash, challenge_key_salt, " +
        "keypair, keypair_salt, " +
        "pubkey, symkey, " +
        "container_name_hmac_key, hmac_key " +
        "from account left join base_keyring using (base_keyring_id) " +
        "where username=$1",
      values: [
        username
      ]
    };

    client.query(accountQuery, function (err, result) {
      done();

      if (err) {
        console.log('Unhandled database error: ' + err);
        callback('Database error.');
        return;
      }
      if (!result.rows.length) {
        callback('Account not found.');
        return;
      }

      callback(null, {
        username: result.rows[0].username,
        sha256Username: result.rows[0].sha256_username,
        accountId: result.rows[0].account_id,
        keyringId: result.rows[0].base_keyring_id,
        keypairSalt: JSON.parse(result.rows[0].keypair_salt.toString()),
        keypairCiphertext: JSON.parse(result.rows[0].keypair.toString()),
        pubKey: JSON.parse(result.rows[0].pubkey.toString()),
        symKeyCiphertext: JSON.parse(result.rows[0].symkey.toString()),
        challengeKeySalt: JSON.parse(result.rows[0].challenge_key_salt.toString()),
        challengeKeyHash: result.rows[0].challenge_key_hash.toString(),
        containerNameHmacKeyCiphertext: JSON.parse(result.rows[0].container_name_hmac_key.toString()),
        hmacKeyCiphertext: JSON.parse(result.rows[0].hmac_key.toString())
      });
    });
  });
};

exports.getAccountBySha256Username =
function getAccountBySha256Username(sha256Hash, callback) {
  connect(function (client, done) {
    var accountQuery = {
      text:
        "select account.account_id, " +
        "account.username, account.sha256_username, base_keyring_id, " +
        "challenge_key_hash, challenge_key_salt, " +
        "keypair, keypair_salt, " +
        "pubkey, symkey, " +
        "container_name_hmac_key, hmac_key " +
        "from account left join base_keyring using (base_keyring_id) " +
        "where account.sha256_username=$1",
      values: [
        sha256Hash
      ]
    };

    client.query(accountQuery, function (err, result) {
      done();

      if (err) {
        console.log('Unhandled database error: ' + err);
        callback('Database error.');
        return;
      }
      if (!result.rows.length) {
        callback('Account not found.');
        return;
      }

      callback(null, {
        username: result.rows[0].username,
        sha256Username: result.rows[0].sha256_username,
        accountId: result.rows[0].account_id,
        keyringId: result.rows[0].base_keyring_id,
        keypairSalt: JSON.parse(result.rows[0].keypair_salt.toString()),
        keypairCiphertext: JSON.parse(result.rows[0].keypair.toString()),
        pubKey: JSON.parse(result.rows[0].pubkey.toString()),
        symKeyCiphertext: JSON.parse(result.rows[0].symkey.toString()),
        challengeKeySalt: JSON.parse(result.rows[0].challenge_key_salt.toString()),
        challengeKeyHash: result.rows[0].challenge_key_hash.toString(),
        containerNameHmacKeyCiphertext: JSON.parse(result.rows[0].container_name_hmac_key.toString()),
        hmacKeyCiphertext: JSON.parse(result.rows[0].hmac_key.toString())
      });
    });
  });
}

/**!
 * ### getAccountById(accountId, callback)
 * Retrieve account and base_keyring rows for given `id`
 *
 * Calls back with account object and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Number} accountId
 * @param {Function} callback
 */
exports.getAccountById = function getAccountById(accountId, callback) {
  connect(function (client, done) {
    var accountQuery = {
      text:
        "select account.account_id, " +
        "account.username, account.sha256_username, base_keyring_id, " +
        "challenge_key_hash, challenge_key_salt, " +
        "keypair, keypair_salt, " +
        "pubkey, symkey, " +
        "container_name_hmac_key, hmac_key " +
        "from account left join base_keyring using (base_keyring_id) " +
        "where account.account_id=$1",
      values: [
        accountId
      ]
    };

    client.query(accountQuery, function (err, result) {
      done();

      if (err) {
        console.log('Unhandled database error: ' + err);
        callback('Database error.');
        return;
      }
      if (!result.rows.length) {
        callback('Account not found.');
        return;
      }

      callback(null, {
        username: result.rows[0].username,
        sha256Username: result.rows[0].sha256_username,
        accountId: result.rows[0].account_id,
        keyringId: result.rows[0].base_keyring_id,
        keypairSalt: JSON.parse(result.rows[0].keypair_salt.toString()),
        keypairCiphertext: JSON.parse(result.rows[0].keypair.toString()),
        pubKey: JSON.parse(result.rows[0].pubkey.toString()),
        symKeyCiphertext: JSON.parse(result.rows[0].symkey.toString()),
        challengeKeySalt: JSON.parse(result.rows[0].challenge_key_salt.toString()),
        challengeKeyHash: result.rows[0].challenge_key_hash.toString(),
        containerNameHmacKeyCiphertext: JSON.parse(result.rows[0].container_name_hmac_key.toString()),
        hmacKeyCiphertext: JSON.parse(result.rows[0].hmac_key.toString())
      });
    });
  });
};

/**
 * ### saveMessage(options, callback)
 * Add row to message table for given `options.toAccount`
 *
 * Calls back with message id and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} options
 * @param {Function} callback
 */
exports.saveMessage = function (options, callback) {
  connect(function (client, done) {
    var messageQuery = {
      text:
        "insert into message " +
        "(to_account_id, from_account_id, " +
        "header_ciphertext, payload_ciphertext) " +
        "values ($1, $2, $3, $4) " +
        "returning message_id",
      values: [
        options.toAccount,
        options.fromAccount,
        options.headers,
        options.body
      ]
    };

    client.query(messageQuery, function (err, result) {
      done();

      if (err) {
        console.log('Unhandled database error: ' + err);
        callback('Database error.');
        return;
      }

      callback(null, result.rows[0].message_id);
    });
  });
};
