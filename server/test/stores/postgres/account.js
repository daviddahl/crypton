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

var assert = require('assert');
var crypton = {};
crypton.account = require('../../../lib/stores/postgres/account');

describe('Postgres driver', function () {
  describe('Account', function () {
    var newAccount = {
      username: 'testuser',
      sha256Username: 'FAKEHASHDATA',
      keypairCiphertext: { "keypair": "ciphertext" },
      keypairSalt: '[1,2,3]',
      pubKey: { "pubkey": "ciphertext" },
      symKeyCiphertext: '[1,2,3]',
      containerNameHmacKeyCiphertext: { "containerNameHmacKey": "ciphertext" },
      hmacKeyCiphertext: { "hmacKey": "ciphertext" },
      challengeKeySalt: '[1,2,3]',
      challengeKeyHash: 'bcrypt hash'
    };

    var expectedAccount = {
      username: 'testuser',
      sha256Username: 'FAKEHASHDATA',
      accountId: 4,
      keyringId: 5,
      keypairSalt: [ 1, 2, 3 ],
      keypairCiphertext: { keypair: 'ciphertext' },
      pubKey: { pubkey: 'ciphertext' },
      symKeyCiphertext: [ 1, 2, 3 ],
      challengeKeySalt: [ 1, 2, 3 ],
      challengeKeyHash: 'bcrypt hash',
      containerNameHmacKeyCiphertext: { containerNameHmacKey: 'ciphertext' },
      hmacKeyCiphertext: { hmacKey: 'ciphertext' }
    }

    describe('saveAccount', function () {
      it('inserts rows for account and keyring', function (done) {
        crypton.account.saveAccount(newAccount, function (err) {
          if (err) {
            throw err;
          }

          crypton.account.getAccount(newAccount.username, function (err, account) {
            assert.equal(err, null);
            assert.deepEqual(account, expectedAccount);
            done();
          });
        });
      });

      it('returns an error if username is taken', function (done) {
        crypton.account.saveAccount(newAccount, function (err) {
          assert.equal(err, 'Username already taken.');
          done();
        });
      });
    });

    describe('getAccount', function () {
      it('returns account info and keyring', function (done) {
        crypton.account.getAccount(newAccount.username, function (err, account) {
          assert.equal(err, null);
          assert.deepEqual(account, expectedAccount);
          done();
        });
      });

      it('returns an error if account not found', function (done) {
        crypton.account.getAccount('derp', function (err) {
          assert.equal(err, 'Account not found.');
          done();
        });
      });
    });
  });
});
