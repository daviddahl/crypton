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

#define SIZE 20
#define ALG "elg"
#define BITS "256"
#define PADDING "raw"

#define GCRYPT_NO_DEPRECATED

#include "gcrypt.h"

#include <stdio.h>
#include <stdlib.h>

#include "elgamal.h"
#include "base64.h"

int generateElgKeypair(gcry_sexp_t keypair, gcry_sexp_t elgamal_sexp) {
  gcry_error_t result;
  size_t errorff;
  
  result = gcry_sexp_build(&keypair, &errorff, "(genkey (%s (nbits %s)))", ALG, BITS);
  if (result != 0) {
    fprintf(stderr, "s-exp build failure: %s/%s\n", 
	    gcry_strsource (result), gcry_strerror (result));
    return 1;
  }

  result = gcry_pk_genkey(&keypair, elgamal_sexp);
  if (result != 0) {
    fprintf(stderr, "genkey failure: %s/%s\n", 
	    gcry_strsource (result), gcry_strerror (result));
    return 1;
  }
  
  return 0;
}

gcry_sexp_t getElgPubKey(gcry_sexp_t keypair) {
  gcry_sexp_t pubkey;
  pubkey = gcry_sexp_find_token(keypair, "public-key", 0);
  return pubkey; /* May be NULL if not found */
}

gcry_sexp_t getElgPrivKey(gcry_sexp_t keypair) {
  gcry_sexp_t privkey;

  privkey = gcry_sexp_find_token(keypair, "private-key", 0);

  return privkey; /* May be NULL if not found */
}

char* getRawWrappedKey(gcry_sexp_t wrappedKey) {
  char *rawKey;
  size_t size 2000; /* ??? what size here? */
  int i;
  
  rawKey = (char *) malloc(sizeof(char)*size);

  size = gcry_sexp_sprint(exp, GCRYSEXP_FMT_ADVANCED, rawKey, 2000);

  printf("size = %Zi\n", size);
  for(i = 0; i < size; i++) {
    printf("%c", rawKey[i]);
  }
  printf("\n");

  return rawKey;
}

int wrapSymKeyWithElgPubKey(gcry_sexp_t pubkey, 
			    unsigned char* symKey, char* b64wrappedKey) {
  gcry_error_t result;
  size_t errorff;
  gcry_sexp_t symKeySexp;
  gcry_sexp_t wrappedSymKey;

  result = gcry_sexp_build(&symKeySexp, &errorff, 
			   "(data (flags %s) (value %b))", 
			   PADDING, SIZE, symKey);
  if (result != 0) {
    fprintf (stderr, "failure creating symKeySexp: %s/%s\n", 
	     gcry_strsource (err), gcry_strerror (err));
  }
  
  result = gcry_pk_encrypt(&wrappedSymKey, symKeySexp, pubkey);
  if (result != 0) {
    fprintf (stderr, "failure wrapping symKey: %s/%s\n", 
	     gcry_strsource (err), gcry_strerror (err));
  }
  
  /* convert the wrapped key to char*  */
  b64wrappedKey = base64(wrappedSymKey, strlen(wrappedSymKey), 0);
  /* XXXddahl: check return value of base64 */
  return 0;
}

/*   
   Symmetric Encryption methods
*/

struct elgCiphertext {
  char wrappedKey[64];
  int keyIv[16];
  char* cipherText;
  int cipherTextIv[16];
};

int generateSymKey(void* symKey) {
  unsigned char _symKey[32];
  gcry_randomize(_symKey, sizeof(_symKey), GCRY_STRONG_RANDOM);
  if (!symKey) {
    return 1
  }
  fprintf (stderr, "symKey: %s\n", _symKey);
  symKey = _symKey;
  return 0;
}

int encryptDataWithElgPK(char* data, elgCiphertext* cipherText) {
  /* 
     1. Generate AES symKey
     2. encrypt data with symKey
     3. wrap symKey
     4. return struct containing wrappedKey, IV, ciphertext    
   */
  int result;
  void* symKey;
  result = generateSymKey(symKey);
  if (!result) {
    printf (stderr, "symKey generation failed\n");
    return 1;
  }
  
  


  return 0;
}

int decryptDataWithElgPK() {

}

/* 
   sign() and verify() will be in ecdsa.c 
*/

/* 
   encryptAndSign(), verifyAndDecrypt(), 
   generateKeyRing()  will be in crypton.c

*/



/* -------------ORIGINAL EXAMPLE ------------------------------ */

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
  unsigned char *data;
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

  data = (unsigned char*) malloc(sizeof(char)*SIZE);

  printf("Creating data block:.\n");
  for(i = 0; i < SIZE; i++)
    {
      data[i] = (unsigned char) i;
      printf("[%X]", data[i]);
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
	
  ret = gcry_sexp_build(&raw_data, &errorff, 
			"(data (flags %s) (value %b))", 
			PADDING, SIZE, data);
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
  free(data);

  return 0;
}
