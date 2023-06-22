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

#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define freeZeroData(s,n) spFreeZeroData((char **)(&(s)),(n));
#define freePrivateRSAKey(r) spFreeRSAPrivateKey(&(r))
#define freePublicRSAKey(r) spFreeRSAPublicKey(&(r))

typedef struct {
	BigInteger n;			// Modulo
	BigInteger ek;		// Encryption key
} public_rsa_key;
typedef public_rsa_key *PublicRSAKey;

typedef struct {
	PublicRSAKey pub;
	BigInteger p;			// Prime p
	BigInteger q;			// Prime q
	BigInteger dk;			// Decryption key
	BigInteger kp;			// dk mod (p - 1)
	BigInteger kq;			// dk mod (q - 1)
	BigInteger c2;			// q^(-1) mod (p)
} private_rsa_key;
typedef private_rsa_key *PrivateRSAKey;

/*
  RSA
 */
PrivateRSAKey bdInitRSAPrivateKey();
PublicRSAKey bdInitRSAPublicKey();
PrivateRSAKey genRSAPrivateKey(size_t bits);
void spFreeRSAPrivateKey(PrivateRSAKey * r);
void spFreeRSAPublicKey(PublicRSAKey * r);
void spPrintRSAPrivateKey(PrivateRSAKey r);
void spPrintRSAPublicKey(PublicRSAKey r);

/*
  RSA files
 */
unsigned char *readFile(const char *filename, size_t * len);
PrivateRSAKey bdReadPrivateRSAKeyFromFile(const char *filename);
uint8_t bdWritePrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa);
PrivateRSAKey bdReadEncryptedPrivateRSAKeyFromFile(const char *filename);
uint8_t bdWriteEncryptedPrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa);
PublicRSAKey bdReadPublicRSAKeyFromFile(const char *filename);
uint8_t bdWritePublicRSAKeyToFile(const char *filename, PublicRSAKey rsa);
int generatePairRSAKeys(int bits, char *filename, int aes);

/*
  Encrypt and decrypt Big Digits
*/
BD publicEncryptRSA(PublicRSAKey rsa, BD m);
BD privateDecryptRSA(PrivateRSAKey rsa, BD c);
BD publicEncryptOAEPRSA(PublicRSAKey rsa, BD m);
BD privateDecryptOAEPRSA(PrivateRSAKey rsa, BD c);
BD privateEncryptOAEPRSA(PrivateRSAKey rsa, BD m);
BD publicDecryptOAEPRSA(PublicRSAKey rsa, BD c);

/*
  Encrypt and decrypt Stack with AES
 */
#define STACKCOMPRESS 1
#define STACKENCODE   2
#define STACKSALT     4
#define ENCRYPTION_OK 0
#define ENCRYPTION_FILE_NOT_FOUND -1
#define ENCRYPTION_WRONG_PASSWORD -2
#define ENCRYPTION_ERROR -3
#define ENCRYPTION_OPEN_FILE_ERROR -4
#define ENCRYPTION_PASSWORD_SHORT -5
#define ENCRYPTION_PUBLIC_KEY_ERROR -6
#define ENCRYPTION_PRIVATE_KEY_ERROR -7
#define ENCRYPTION_WRITE_FILE_ERROR -8
#define SIGNATURE_OK 0
#define SIGNATURE_ERROR -1
#define SIGNATURE_BAD -2
#define SIGNATURE_OPEN_FILE_ERROR -3
#define SIGNATURE_FILE_NOT_FOUND -4

/*
	Encrypt and decrypt files
 */
int encryptFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii);
int decryptFileWithRSA(char *infile, char *outfile, char *keyfile);

/*
  Signatures
*/
int signStackRSA(Stack st,PrivateRSAKey rsa,char *filename,uint8_t mode);
int verifyAndExtractStackRSA(Stack st,PublicRSAKey rsa,uint8_t mode);
int signFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii);
int verifyAndExtractSignedFileWithRSA(char *infile,char *keyfile);

/*
  Usefull for debugging
 */
#define SAVEDEBUG(file,data,length) do {                                \
  int _fd_;                                                             \
  if ((_fd_ = open(file,O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR|S_IWUSR)) < 0) \
  {                                                                     \
    printf("Error opening the file %s\n",file);                         \
    goto final;                                                         \
  }                                                                     \
  if ((write(_fd_,data,length) != length))                              \
  {                                                                     \
    printf("Error writing the file %s\n",file);			                    \
    goto final;                                                         \
  }                                                                     \
  close(_fd_);                                                          \
  } while (0);

#endif				/* H_MCERSA_H_ */
