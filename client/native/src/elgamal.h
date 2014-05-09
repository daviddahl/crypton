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

#ifndef CRYPTON_ELGAMAL_H
#define CRYPTON_ELGAMAL_H

#include <stdio.h>
#include <stdlib.h>

#include "gcrypt.h"
#include "gpg-error.h"

void check_error(gcry_error_t err);
void print_sexp(gcry_sexp_t exp);

#endif /* CRYPTON_ELGAMAL_H */
