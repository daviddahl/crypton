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

/* 

   clang pbkdf2.c -I /var/opt/lib -I /var/opt/include -lgcrypt -lgpg-error -o pbkdf
 
*/

#include "pbkdf2.h"

#define GCRY_CIPHER GCRY_CIPHER_RIJNDAEL256
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CTR /* XXXdahl: should be using GCM mode!!! doesn't work with AES 256 :( */
#define RNDM_BYTES_LENGTH 32
#define SALT_LENGTH 16
#define PBKDF2_KEYSIZE_OCTETS 32
#define HASH_ITERATIONS 10000
#define PBKDF2_KEYSIZE_BITS (PBKDF2_KEYSIZE_OCTETS * 8) 

int generateKeyFromPassword(char* passphrase, struct keyItem* item)
{
  int i; 
  unsigned char* salt = gcry_random_bytes(SALT_LENGTH, GCRY_STRONG_RANDOM);
  char* keyBuffer;
  keyBuffer  = malloc(sizeof(char) * PBKDF2_KEYSIZE_BITS);
  size_t keySize = PBKDF2_KEYSIZE_OCTETS;
  gpg_error_t err; 
  unsigned long iterations = HASH_ITERATIONS;

  err = gcry_kdf_derive(passphrase, strlen(passphrase), 
			GCRY_KDF_PBKDF2, GCRY_MD_SHA256, 
	                salt, SALT_LENGTH, 
			iterations, keySize, keyBuffer);
  if (err) {
    printf("Error generating key from password. Error no: %d and message: %s\n ", 
	   err, 
	   gcry_strerror(err));
    return 1;
  }

  printf("Key: \n");        
  printf("%s\n", keyBuffer);
  item->key = keyBuffer;
  item->salt = salt;
  item->name = (unsigned char*)"masterKey";

  return 0;
}

/* Wrap a keyitem with a key  */
int wrapKeyItem (char* privateKey, struct keyItem key, 
		 unsigned char* name, struct wrappedKeyItem* out)
{
  size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
  size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
  size_t privateKeyLength = strlen(privateKey) + 1;
  char *encBuffer = malloc(privateKeyLength);
  size_t encBufferLength = strlen(privateKey) + 1;
  gcry_error_t err = 0;
  
  // Create a handle
  gcry_cipher_hd_t handle = NULL;
  err = gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_CIPHER_MODE, 0);
  if (err) {
    printf("GCM algo %d, gcry_cipher_open failed: %s\n",
	   GCRY_CIPHER, gpg_strerror (err));
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    free(encBuffer);
    return 1;
  }
  // Set the key
  err = gcry_cipher_setkey(handle,
			   key.key,
			   keyLength);
  if (err) {
    printf("gcry_cipher_setkey failed.");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    free(encBuffer);
    return 1;
  }
  
  // set the IV
  unsigned int *iv;
  iv = gcry_random_bytes(RNDM_BYTES_LENGTH, GCRY_STRONG_RANDOM);
  err = gcry_cipher_setiv(handle, iv, blkLength);
  
  if (err) {
    printf("gcry_cipher_setiv failed.");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    free(encBuffer);
    return 1;
  }

  // Do encrypt
  err = gcry_cipher_encrypt(handle, encBuffer, 
                            privateKeyLength, privateKey, 
			    privateKeyLength);
  if (err) {
    printf("gcry_cipher_encrypt failed.");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    free(encBuffer);
    return 1;
  }

  printf("encBuffer: %s\n ", encBuffer);
  out->ciphertext = encBuffer;
  out->iv = iv;
  out->name = name;

  // Free memory
  gcry_cipher_close(handle);
  free(encBuffer);
  
  return 0;
}

/* 
   The test below does:

   1. generates a key from a password via PBKDF wioth 10000 iterations
   2. encrypts the derived key data with itself (the key)
   3. returns (via an outparm) a struct holding the wrapped key, IV and name of the key
   
   ### TODO: 
   1. utility function that converts the ciphertext and related data in the wrappedKeyItem struct to base64 that JS can consume
   2. make sure the key data can be converted to an SJCL 'byteArray'

 */
int main()
{
  char* pass = "password";
  struct keyItem masterKey;
  int err; 

  err = generateKeyFromPassword(pass, &masterKey);

  if (err) {
    printf("error: %u\n", err);
  }

  printf("key: %s\n", masterKey.key);
  printf("salt:  %d\n", (int)masterKey.salt);

  unsigned char* name;
  name = (unsigned char*)"myWrappedMasterKey";
  struct wrappedKeyItem wrappedKey;
  
  // Encrpt keyring item
  err = wrapKeyItem(masterKey.key, masterKey, name, &wrappedKey);
  
  if (err) {
    printf("error: %u\n", err);
  }

  return 0;
}
