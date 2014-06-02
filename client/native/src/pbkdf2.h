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

#include "base64.h"
#include "dbg.h"

#include "gcrypt.h"
#include "gpg-error.h"

struct keyItem {
  char* key;
  unsigned char* salt;
  unsigned char* name;
};

struct wrappedKeyItem {
  char* ciphertext;
  unsigned int* iv;
  unsigned char* name;
}; /* XXX: Need to add a TAG property */

struct wrappedKeyRing {
  struct wrappedKeyItem masterKey;
  struct keyItem encryptionPubKey;
  struct wrappedKeyItem encryptionPrivKey;
  struct keyItem signingPubKey;
  struct wrappedKeyItem signingPrivKey;
  struct wrappedKeyItem hmacKey;
};

int generateKeyFromPassword(char* passphrase, struct keyItem* key);

int wrapKeyItem(char* privateKey, struct keyItem key, 
		unsigned char* name, struct wrappedKeyItem* out);
