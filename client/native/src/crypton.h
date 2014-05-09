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

#ifndef CRYPTON_H
#define CRYPTON_H

#include <stdio.h>
#include <stdlib.h>

#include "gcrypt.h"
#include "gpg-error.h"

#include "pbkdf2.h"
#include "elgamal.h"

/* 
 * This header file includes the public interface for native crypton
 * PBKDF2:
 * int generateKeyFromPassword(const char* passphrase, struct masterKey* key);
 * 
 * ElGamal keygen:
 * 
 * ElGamal session key wrapping:
 *
 * ECDSA signing keypair gen: 
 * 
 * HMAC symkey gen:
 * 
 * HMAC:
 * 
 * ECC session sym keygen:
 *
 * SRP operations:
 * CalculateM2();
 * 
 * SJCL formatting functions
 * const char* base64EncodeMasterKey(struct masterKey* key);
 */

int initGcrypt();

/* SEE this on disabling hardware features: 
 *  https://www.gnupg.org/documentation/manuals/gcrypt/Hardware-features.html#Hardware-features 
 */

#endif /* CRYPTON_H */
