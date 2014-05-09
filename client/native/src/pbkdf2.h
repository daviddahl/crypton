/* Crypton Client, Copyright 2014 SpiderOak, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "gcrypt.h"
#include "gpg-error.h"

struct masterKey {
  unsigned char key[32];
  unsigned char salt[16];
};

struct wrappedKeyItem {
  char ciphertext; // XXXddahl length??
  unsigned int iv; // char or int? see above...
  unsigned char name[16];
};

struct wrappedKeyRing {
  wrappedKeyItem encryptionPubKey;
  wrappedKeyItem encryptionPrivKey;
  wrappedKeyItem signingPubKey;
  wrappedKeyItem signingPrivKey;
  wrappedKeyItem hmacKey;
}; // XXXddahl: still working this out...

int generateKeyFromPassword(const char* passphrase, struct masterKey* key);

int wrapKeyData(char* keyRingItem, struct masterKey key);
