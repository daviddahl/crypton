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

// XXXddahl: still converting this code example to do what we need...

#define TAM_DADO 20
#define ALG "elg"
#define BITS "256"
#define PADDING "raw"

#define GCRYPT_NO_DEPRECATED

#include "gcrypt.h"

#include <stdio.h>
#include <stdlib.h>

#include "elgamal.h"

void check_error(gcry_error_t err)
{
  if (err) {
    fprintf (stderr, "Failure: %s/%s\n", gcry_strsource (err), gcry_strerror (err));
    exit(1);
  }
}

void print_sexp(gcry_sexp_t exp)
{
  char *str;
  size_t size = 2000;
  int i;

  str = (char *) malloc(sizeof(char)*size);

  size = gcry_sexp_sprint(exp, GCRYSEXP_FMT_ADVANCED, str, 2000);
  printf("size = %Zi\n", size);
  for(i = 0; i < size; i++)
    printf("%c", str[i]);
  printf("\n");

  free(str);
}

int main(void)
{
  const char *version;
  gcry_sexp_t pubk, seck, par, enc_data, dec_data, to_dec_func, raw_data, raw_enc_data, gkey;
  unsigned char *dado;
  int i;
  size_t errorff;
  gcry_error_t ret;

  version = gcry_check_version(NULL);
  printf("Using libgcrypt version %s\n", version);

  /*
   * Initialize libgcrypt
   */
  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
  gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  /*
   * Create a data block to be encrypted
   */

  dado = (unsigned char*) malloc(sizeof(char)*TAM_DADO);

  printf("Creating data block:.\n");
  for(i = 0; i < TAM_DADO; i++)
    {
      dado[i] = (unsigned char) i;
      printf("[%X]", dado[i]);
    }
  printf("\n");
  fflush(stdout);

  /*
   * Generate keys
   */

  ret = gcry_sexp_build(&gkey, &errorff, "(genkey (%s (nbits %s)))", ALG, BITS);
  check_error(ret);

  printf("S-expression of keys:\n");
  print_sexp(gkey);
  printf("Generating key pair....\n");

  ret = gcry_pk_genkey(&par, gkey);
  check_error(ret);
  printf("Keys generated!\nThe key pair is:\n");
  print_sexp(par);

  pubk = gcry_sexp_find_token(par, "public-key", 0);
  seck = gcry_sexp_find_token(par, "private-key", 0);

  printf("Public key:\n");
  print_sexp(pubk);

  printf("Private key:\n");
  print_sexp(seck);

  /*
   * Preparing data for encrypting
   */

  printf("S-expression to encrypt:\n");
	
  ret = gcry_sexp_build(&raw_data, &errorff, "(data (flags %s) (value %b))", PADDING, TAM_DADO, dado);
  check_error(ret);
  print_sexp(raw_data);

  /*
   * Encrypting data
   */
  printf("Encrypting data.....\n");
  ret = gcry_pk_encrypt(&enc_data, raw_data, pubk);
  check_error(ret);
  printf("Encryption finished!\n");

  printf("Encrypted data:\n");
  print_sexp(enc_data);

  /*
   * Decrypting data
   */
  printf("Isolating encrypted data:\n");
  raw_enc_data = gcry_sexp_find_token(enc_data, ALG, 0);
  print_sexp(raw_enc_data);

  ret = gcry_sexp_build(&to_dec_func, &errorff, "(enc-val (flags %s) %S)", PADDING, raw_enc_data);
  check_error(ret);
  printf("S-expression to decrypt:\n");
  print_sexp(to_dec_func);
	
  printf("Decrypting data...\n");
  ret = gcry_pk_decrypt(&dec_data, to_dec_func, seck);
  check_error(ret);
  printf("Decryption finished!\n");
  print_sexp(dec_data);

  /*
   * Free memory
   */
  printf("Freeing memory.\n");
  fflush(stdout);
  gcry_sexp_release(par);
  gcry_sexp_release(gkey);
  gcry_sexp_release(seck);
  gcry_sexp_release(pubk);
  gcry_sexp_release(raw_data);
  gcry_sexp_release(raw_enc_data);
  gcry_sexp_release(to_dec_func);
  gcry_sexp_release(enc_data);
  gcry_sexp_release(dec_data);

  gcry_control(GCRYCTL_TERM_SECMEM);

  printf("Done!\n");
  fflush(stdout);
  free(dado);

  return 0;
}
