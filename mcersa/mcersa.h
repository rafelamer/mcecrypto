/**************************************************************************************
* Filename:   mcersa.h
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2023
* Disclaimer: This code is presented "as is" and it has been written to
*             implement the RSA and ECC encryption and decryption algorithm for
*             educational purposes and should not be used in contexts that
*             need cryptographically secure implementation
*
* License:    This library  is free software; you can redistribute it and/or
*             modify it under the terms of either:
*
*             1 the GNU Lesser General Public License as published by the Free
*               Software Foundation; either version 3 of the License, or (at your
*               option) any later version.
*
*             or
*
*             2 the GNU General Public License as published by the Free Software
*               Foundation; either version 2 of the License, or (at your option)
*               any later version.
*
*	      See https://www.gnu.org/licenses/
***************************************************************************************/
#ifndef H_MCERSA_H_
#define H_MCERSA_H_ 1

#include <mceutils.h>

#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define freePrivateRSAKey(r) free_RSA_PrivateKey(&(r))
#define freePublicRSAKey(r) free_RSA_PublicKey(&(r))
#define SIGNATURE_RSA_OK 0
#define SIGNATURE_RSA_ERROR -1
#define SIGNATURE_RSA_BAD -2
#define SIGNATURE_RSA_OPEN_FILE_ERROR -3
#define SIGNATURE_RSA_FILE_NOT_FOUND -4
#define SIGNATURE_RSA_WRITE_FILE_ERROR -5
#define SIGNATURE_RSA_PRIVATE_KEY_ERROR -6
#define SIGNATURE_RSA_PUBLIC_KEY_ERROR -7

#define ENCRYPTION_RSA_OK 0
#define ENCRYPTION_RSA_ERROR -1
#define ENCRYPTION_RSA_PUBLIC_KEY_ERROR -2
#define ENCRYPTION_RSA_PRIVATE_KEY_ERROR -3
#define ENCRYPTION_RSA_FILE_NOT_FOUND -4
#define ENCRYPTION_RSA_OPEN_FILE_ERROR -5
#define ENCRYPTION_RSA_WRITE_FILE_ERROR -6

typedef struct {
	BigInteger n;			// Modulo
	BigInteger ek;		// Encryption key
} public_rsa_key;
typedef public_rsa_key *PublicRSAKey;

typedef struct {
	PublicRSAKey pub;
	BigInteger p;			  // Prime p
	BigInteger q;			  // Prime q
	BigInteger dk;			// Decryption key
	BigInteger kp;			// dk mod (p - 1)
	BigInteger kq;			// dk mod (q - 1)
	BigInteger c2;			// q^(-1) mod (p)
} private_rsa_key;
typedef private_rsa_key *PrivateRSAKey;

/*
  RSA keys
 */
PrivateRSAKey initRSAPrivateKey();
PublicRSAKey initRSAPublicKey();
PrivateRSAKey generateRSAPrivateKey(size_t bits);
void free_RSA_PrivateKey(PrivateRSAKey * r);
void free_RSA_PublicKey(PublicRSAKey * r);
void printRSAPrivateKey(PrivateRSAKey r);
void printRSAPublicKey(PublicRSAKey r);

/*
  Encrypt and decrypt BigIntegers
*/
BigInteger publicEncryptRSA(PublicRSAKey rsa, BigInteger m);
BigInteger privateDecryptRSA(PrivateRSAKey rsa, BigInteger c);
BigInteger publicEncryptOAEPRSA(PublicRSAKey rsa, BigInteger m);
BigInteger privateDecryptOAEPRSA(PrivateRSAKey rsa, BigInteger c);
BigInteger privateEncryptOAEPRSA(PrivateRSAKey rsa, BigInteger m);
BigInteger publicDecryptOAEPRSA(PublicRSAKey rsa, BigInteger c);

/*
  RSA files
 */
int stWriteRSAEncryptionOI(Stack st);
int stReadOptionalRSAEncryptionOI(Stack st);
PrivateRSAKey readPrivateRSAKeyFromFile(const char *filename);
uint8_t writePrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa);
PrivateRSAKey readEncryptedPrivateRSAKeyFromFile(const char *filename);
uint8_t writeEncryptedPrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa);
PublicRSAKey readPublicRSAKeyFromFile(const char *filename);
uint8_t writePublicRSAKeyToFile(const char *filename, PublicRSAKey rsa);
int generateAndSavePairRSAKeys(int bits, char *filename, int aes);

/*
	Encrypt and decrypt files
 */
int encryptFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii);
int decryptFileWithRSA(char *infile, char *keyfile);

/*
  Signatures
*/
int signStackRSA(Stack st, PrivateRSAKey rsa, const char *filename, uint8_t mode);
int verifyAndExtractStackRSA(Stack st, PublicRSAKey rsa, uint8_t mode);
int signFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii);
int verifyAndExtractSignedFileWithRSA(char *infile, char *keyfile);

#endif				/* H_MCERSA_H_ */
