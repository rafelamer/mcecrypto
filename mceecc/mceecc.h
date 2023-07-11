/**************************************************************************************
* Filename:   mceecc.h
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
#ifndef H_MCEECC_H_
#define H_MCEECC_H_ 1

#include <mceutils.h>

#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#define freePrivateECCKey(r) free_ECC_PrivateKey(&(r))
#define freePublicECCKey(r) free_ECC_PublicKey(&(r))
#define SIGNATURE_ECC_OK 0
#define SIGNATURE_ECC_ERROR -1
#define SIGNATURE_ECC_BAD -2
#define SIGNATURE_ECC_OPEN_FILE_ERROR -3
#define SIGNATURE_ECC_FILE_NOT_FOUND -4
#define SIGNATURE_ECC_WRITE_FILE_ERROR -5
#define SIGNATURE_ECC_PRIVATE_KEY_ERROR -6
#define SIGNATURE_ECC_PUBLIC_KEY_ERROR -7

#define ENCRYPTION_ECC_OK 0
#define ENCRYPTION_ECC_ERROR -1
#define ENCRYPTION_ECC_PUBLIC_KEY_ERROR -2
#define ENCRYPTION_ECC_PRIVATE_KEY_ERROR -3
#define ENCRYPTION_ECC_FILE_NOT_FOUND -4
#define ENCRYPTION_ECC_OPEN_FILE_ERROR -5
#define ENCRYPTION_ECC_WRITE_FILE_ERROR -6

typedef struct {
	EllipticCurve ec;
    EllipticCurvePoint P;
} public_ecc_key;
typedef public_ecc_key *PublicECCKey;

typedef struct {
	EllipticCurve ec;
    BigInteger private;
    EllipticCurvePoint P;
} private_ecc_key;
typedef private_ecc_key *PrivateECCKey;

/*
    Basic ECC functions
*/
PrivateECCKey initECCPrivateKey();
PublicECCKey initECCPublicKey();
PrivateECCKey generateECCPrivateKey(EllipticCurve ec);
void printECCPrivateKey(PrivateECCKey key);
void printECCPublicKey(PublicECCKey key);
void free_ECC_PrivateKey(PrivateECCKey *key);
void free_ECC_PublicKey(PublicECCKey *key);

/*
  ECC files
 */
int stWriteECCEncryptionOI(Stack st);
int stReadECCEncryptionOI(Stack st);
int stWriteECCEncryptionCurveOI(Stack st, EllipticCurve ec);
EllipticCurve stReadECCEncryptionCurveOI(Stack st, EllipticCurves ecs);
PrivateECCKey readPrivateECCKeyFromStack(Stack st, EllipticCurves ecs);
Stack writePrivateECCKeyToStack(PrivateECCKey key);
uint8_t writePrivateECCKeyToFile(const char *filename, PrivateECCKey key);
PrivateECCKey readPrivateECCKeyFromFile(const char *filename, EllipticCurves ecs);
PublicECCKey publicECCKeyFromPrivate(PrivateECCKey key);
Stack writePublicECCKeyToStack(PublicECCKey key);
uint8_t writePublicECCKeyToFile(const char *filename, PublicECCKey key);
PublicECCKey readPublicECCKeyFromStack(Stack st, EllipticCurves ecs);
PublicECCKey readPublicECCKeyFromFile(const char *filename, EllipticCurves ecs);
uint8_t writeEncryptedPrivateECCKeyToFile(const char *filename, PrivateECCKey key);
PrivateECCKey readEncryptedPrivateECCKeyFromFile(const char *filename, EllipticCurves ecs);
int generateAndSavePairECCKeys(char *filename, EllipticCurve ec, int aes);

/*
  Signatures
*/
int signStackECC(Stack st, PrivateECCKey key, const char *filename, uint8_t mode);
int signFileWithECC(char *infile, char **outfile, char *keyfile, EllipticCurves ecs, int ascii);
int verifyAndExtractStackECC(Stack st, PublicECCKey key, uint8_t mode);
int verifyAndExtractSignedFileWithECC(char *infile, char *keyfile, EllipticCurves ecs);


#endif				/* H_MCEECC_H_ */
