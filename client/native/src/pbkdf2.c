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

/* clang crypton_pbkdf2.c -I /var/opt/lib -I /var/opt/include -lgcrypt -lgpg-error -o pbkdf */

#include "pbkdf2.h"

#define GCRY_CIPHER GCRY_CIPHER_RIJNDAEL256 // Are we doing GCM CTR? 
#define GCRY_CIPHER_MODE GCRY_CIPHER_MODE_CTR

int generateKeyFromPassword(const char* passphrase, struct masterKey* mk)
{
  int i; 
  void *pwd;
  void *salt;
  salt = (unsigned int*)gcry_random_bytes(16, GCRY_STRONG_RANDOM);
  unsigned char keyBuffer[32];
  size_t saltLen = 16;
  size_t keySize = 32;
  gpg_error_t err; 
  unsigned long iterations = 1024; 

  err = gcry_kdf_derive(passphrase, strlen(passphrase), 
			GCRY_KDF_PBKDF2, GCRY_MD_SHA256, 
			salt, strlen(salt), 
			iterations, keySize, keyBuffer);
  if(err != 0) {
    printf("Error generating key from password!\n");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    return 1;
  }
  printf("Key: \n");        
  printf("%s\n", keyBuffer);
  return 0;
}

/* Wrap the full keyring with the derived master key  */
int wrapKeyData (char* keyRingItem, struct masterKey mk) // keyRing may have to be a struct here
{
  size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
  size_t blkLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER);
  size_t keyRingItemLength = strlen(keyRingItem) + 1; // string plus termination
  char *encBuffer = malloc(keyRingItemLength);
  char *outBuffer = malloc(keyRingItemLength);
  gcry_error_t err = 0;
  
  // Create a handle
  gcry_cipher_hd_t handle;
  err = gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_CIPHER_MODE, 0);
  if (!handle) {
    printf("GCM-CTR algo %d, gcry_cipher_open failed: %s\n",
	   GCRY_CIPHER, gpg_strerror (err));
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    return 1;
  }
  // Set the key
  err = gcry_cipher_setkey(handle,
			   mk.key,
			   sizeof (mk.key));
  if (err) {
    printf("gcry_cipher_setkey failed.");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    return 1;
  }
  
  // set the IV
  void *iv;
  iv = (unsigned int*)gcry_random_bytes(16, GCRY_STRONG_RANDOM);
  err = gcry_cipher_setiv(handle, iv, blkLength);
  
  if (err) {
    printf("gcry_cipher_setiv failed.");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    return 1;
  }

  // Do encrypt
  err = gcry_cipher_encrypt(handle, encBuffer, 
                            keyRingItemLength, keyRingItem, 
			    keyRingItemLength);
  if (err) {
    printf("gcry_cipher_encrypt failed.");
    printf("Error no: %d and message: %s\n ", err, gcry_strerror(err));
    return 1;
  }

  printf("outBuffer: %s\n ", outBuffer);
  // XXXddahl: Need to add a outparam arg struct to save the ciphertext + iv
 
  // Free memory
  gcry_cipher_close(handle);
  free(encBuffer);
  free(outBuffer);
  
  return 0;
}

int main()
{
  /*
   * Initialize gcrypt
   */
  /* gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN); */
  /* gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); */
  /* gcry_control(GCRYCTL_RESUME_SECMEM_WARN); */
  /* gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM); */
  /* gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0); */

  const char* pass = "my-password-is-long";
  struct masterKey mk;
  generateKeyFromPassword(pass, &mk);
  printf("key: %s\n", mk.key);
  printf("salt:  %s\n", mk.salt);
  
  // Encrpt keyring item
  wrapKeyData(mk.key, mk);

  // In practice we will iterate through the keyring and re-build a new struct for each key, creating a ciphertext struct for each item in the keyring  

  return 0;
}
