/**************************************************************************************
* Filename:   eccfiles.c
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
#include <mceecc.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

static const unsigned char beccpk[] = "-----BEGIN ECC PRIVATE KEY-----";
static const unsigned char eeccpk[] = "-----END ECC PRIVATE KEY-----";
static const unsigned char beccpubk[] = "-----BEGIN ECC PUBLIC KEY-----";
static const unsigned char eeccpubk[] = "-----END ECC PUBLIC KEY-----";

static unsigned char eccEncryption[] = {0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};

#define OIDECCENCRYPTIONLENGTH 9
#define READ_BI_FROM_STACK(n)     n = stReadBigInteger(st, &error);  \
    if ((n == NULL) || (error != 0))                                 \
        goto final;

#define WRITEERROR     { \
     close(fd);          \
     unlink(filename);   \
     goto final;         \
  }

static unsigned char *clear_ecc_private_info(const unsigned char *string)
{
	unsigned char *begin, *end;
	size_t i;

	if ((begin = (unsigned char *)strstr((char *)string,(char *)beccpk)) == NULL)
		return NULL;

	begin += strlen((char *)beccpk);
	while (*begin == '\n')
		begin++;

	if (strncmp((char *)begin, "Proc-Type: 4,ENCRYPTED", 22) != 0)
		return NULL;
	begin += 22;
	while (*begin == '\n')
		begin++;

	if (strncmp((char *)begin, "DEK-Info: AES-256-CBC", 22) != 0)
		return NULL;
	begin += 22;

	if ((end = (unsigned char *)strstr((char *)begin,(char *)eeccpk)) == NULL)
		return NULL;
	*end = '\0';

	while (*begin == '\n')
		begin++;
	return begin;
}

int stWriteECCEncryptionOI(Stack st)
{
    if ((OIDECCENCRYPTIONLENGTH + st->used) > st->alloc)
		if (! stExpandStackInSize(st, 1024))
			return 0;
	memmove(st->data + OIDECCENCRYPTIONLENGTH, st->data, st->used);
	memcpy(st->data, eccEncryption, OIDECCENCRYPTIONLENGTH);
	st->used += OIDECCENCRYPTIONLENGTH;
	return 1;
}

int stReadECCEncryptionOI(Stack st)
{
    if (memcmp(st->read, eccEncryption, OIDECCENCRYPTIONLENGTH) != 0)
		return 0;
	st->read += OIDECCENCRYPTIONLENGTH;
	return 1;
}

int stWriteECCEncryptionCurveOI(Stack st, EllipticCurve ec)
{
    if ((ec->oidlen + st->used) > st->alloc)
		if (! stExpandStackInSize(st, 1024))
			return 0;
    memmove(st->data + ec->oidlen, st->data, st->used);
	memcpy(st->data, ec->oid, ec->oidlen);
	st->used += ec->oidlen;
	return 1;
}


static Stack writePrivateECCKeyToStack(PrivateECCKey key)
{
	Stack st, aux;

	st = aux = NULL;
	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;
    if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;
	/*
	   Sequence of integers
	 */
    if (! stWriteBigInteger(st, key->P->y))
		goto final;
    if (! stWriteBigInteger(st, key->P->x))
		goto final;
	if (! stWriteBigInteger(st, key->private))
		goto final;

	/*
	   Length of integers and sequence
	 */
	if (! stWriteStartSequence(st))
		goto final;
	
	/*
	   Length and OCTET STRING
	 */
	if (! stWriteStartOctetString(st))
		goto final;
	
    /*
        Object identifiers of the curve and eccEncryption
    */
    if (! stWriteECCEncryptionCurveOI(aux,key->ec))
        goto final;
    if (! stWriteECCEncryptionOI(aux))
        goto final;
    if (! stWriteStartSequence(aux))
		goto final;   
    if (! stAddContentsFromStack(st,aux))
        goto final;
    freeStack(aux);
    if (! stWriteStartSequence(st))
		goto final;

	return st;

 final:
	freeStack(st);
    freeStack(aux);
	return NULL;
}


uint8_t writePrivateECCKeyToFile(const char *filename, PrivateECCKey key)
{
    Stack st;
	uint8_t r;
	unsigned char *b64data;

    r = 0;
	st = NULL;
	b64data = NULL;
	if ((st = writePrivateECCKeyToStack(key)) == NULL)
		goto final;
    
    size_t outlen;
	int fd;
	if ((b64data = b64_encode(st->data, st->used, &outlen)) == NULL)
		goto final;

    if ((fd = open("test.der", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
		goto final;
    if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;

    /*
	   Write to a file
	 */
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
		goto final;

	size_t t;
	t = strlen((char *)beccpk);
	if (write(fd, beccpk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	if (write(fd, b64data, outlen) != outlen)
		WRITEERROR;
	t = strlen((char *)eeccpk);
	if (write(fd, eeccpk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	close(fd);
	r = 1;

 final:
	freeString(b64data);
	freeStack(st);
	return r;
}

/*
EllipticCurve stReadECCEncryptionCurveOI(Stack st)
{
    size_t length;
    int error;


}

PrivateECCKey readPrivateECCKeyFromFile(const char *filename);
uint8_t writePrivateECCKeyToFile(const char *filename, PrivateRSAKey rsa);
PrivateRSAKey readEncryptedPrivateECCKeyFromFile(const char *filename);
uint8_t writeEncryptedPrivateECCKeyToFile(const char *filename, PrivateRSAKey rsa);
PublicRSAKey readPublicECCKeyFromFile(const char *filename);
uint8_t writePublicECCKeyToFile(const char *filename, PublicRSAKey rsa);
int generateAndSavePairECCKeys(int bits, char *filename, int aes);

*/