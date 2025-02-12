/**************************************************************************************
* Filename:   eccfiles.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2025
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

static const unsigned char beccpk[] = "-----BEGIN EC PRIVATE KEY-----";
static const unsigned char eeccpk[] = "-----END EC PRIVATE KEY-----";
static const unsigned char beccpubk[] = "-----BEGIN EC PUBLIC KEY-----";
static const unsigned char eeccpubk[] = "-----END EC PUBLIC KEY-----";

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

	if (strncmp((char *)begin, "DEK-Info: AES-256-CBC", 21) != 0)
		return NULL;
	begin += 21;

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

EllipticCurve stReadECCEncryptionCurveOI(Stack st, EllipticCurves ecs)
{
	EllipticCurve ec;
	unsigned char b;
	uint8_t oid[11];

	b = *(st->read);
	if (b != 0x06)
		return NULL;
	b = *(st->read + 1);
	memcpy(oid,st->read,b + 2);
	st->read += b + 2;
	for (int i = 0;i < NISTCURVES - 1;i++)
	{
		ec = ecs[i];
		if (memcmp(oid,ec->oid,ec->oidlen) == 0)
			return ec;
	}
	return NULL;
}

EllipticCurve findEllipticCurveFronName(unsigned char *name, EllipticCurves ecs)
{
	EllipticCurve ec;
	for (int i = 0;i < NISTCURVES - 1;i++)
	{
		ec = ecs[i];
		if (memcmp(name,ec->name,strlen(ec->name)) == 0)
			return ec;
	}
	return NULL;
}

PrivateECCKey readPrivateECCKeyFromStack(Stack st, EllipticCurves ecs)
{
	PrivateECCKey key;
	EllipticCurve ec;
	BigInteger x, y;
	key = NULL;
	ec = NULL;
	x = y = NULL;
	
	/*
	   Initialize the key variable
	 */
	if ((key = initECCPrivateKey()) == NULL)
		goto final;

	/*
	   Read the initial sequence data from the stack
	 */
	size_t length;
	int error;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	if (length != stBytesRemaining(st))
		goto final;

	/*
		Read the Object Identifiers 
	*/
	if (! stReadECCEncryptionOI(st))
		goto final;
	if ((ec = stReadECCEncryptionCurveOI(st,ecs)) == NULL)
		goto final;
	key->ec = ec;

	/*
		Read the Big Integers
	*/
	length = stReadStartOctetStringAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	READ_BI_FROM_STACK(key->private);
	READ_BI_FROM_STACK(x);
	READ_BI_FROM_STACK(y);

	if ((key->P = initEllipticCurvePoint(x, y, key->ec)) == NULL)
		goto final;
	x = y = NULL;

	return key;

final:
	freePrivateECCKey(key);
	freeBigInteger(x);
	freeBigInteger(y);
	return NULL;
}

Stack writePrivateECCKeyToStack(PrivateECCKey key)
{
	Stack st;

	st = NULL;
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
    if (! stWriteECCEncryptionCurveOI(st,key->ec))
        goto final;
    if (! stWriteECCEncryptionOI(st))
        goto final;
    if (! stWriteStartSequence(st))
		goto final;   

	return st;

 final:
	freeStack(st);
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

PrivateECCKey readPrivateECCKeyFromFile(const char *filename, EllipticCurves ecs)
{
	unsigned char *str, *begin, *der;
	size_t len, outlen, alloc;
	Stack st;
	PrivateECCKey key;
	int ok;

	key = NULL;
	st = NULL;
	str = der = NULL;
	ok = 0;
	if ((str = readFileBinaryMode(filename, &len, &alloc)) == NULL)
		return NULL;
	if (len == 0)
		goto final;

	/*
	   Clear begin and end comments
	 */
	if ((begin = clearCcommentsInText(str,beccpk,eeccpk)) == NULL)
		goto final;
	len = strlen((char *)begin);

	/*
	   Decode the data with base64
	   Initialize the stack and copy data
	 */
	if ((der = b64_decode((unsigned char *)begin, len, &outlen)) == NULL)
		goto final;

	if ((st = stInitStackWithSize(outlen + 512)) == NULL)
		goto final;
	memcpy(st->data, der, outlen);
	st->used = outlen;

	if ((key = readPrivateECCKeyFromStack(st,ecs)) == NULL)
		goto final;

	ok = 1;

final:
	if (!ok)
	{
		freePrivateECCKey(key);
		key = NULL;
	}
	freeStack(st);
	freeString(str);
	freeString(der);
	return key;
}

PublicECCKey publicECCKeyFromPrivate(PrivateECCKey key)
{
	PublicECCKey pkey;
	BigInteger x, y;
	pkey = NULL;
	x = y = NULL;

	if ((pkey = initECCPublicKey()) == NULL)
		goto final;
	pkey->ec = key->ec;
	if ((x = cloneBigInteger(key->P->x)) == NULL)
        goto final;
    if ((y = cloneBigInteger(key->P->y)) == NULL)
        goto final;
    if ((pkey->P = initEllipticCurvePoint(x, y, key->ec)) == NULL)
        goto final;
	x = y = NULL;
	
	return pkey;

final:
	freePublicECCKey(pkey);
	freeBigInteger(x);
	freeBigInteger(y);
	return NULL;
}

Stack writePublicECCKeyToStack(PublicECCKey key)
{
	Stack st;

	st = NULL;
	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;

	/*
	   Sequence of integers
	 */
    if (! stWriteBigInteger(st, key->P->y))
		goto final;
    if (! stWriteBigInteger(st, key->P->x))
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
    if (! stWriteECCEncryptionCurveOI(st,key->ec))
        goto final;
    if (! stWriteECCEncryptionOI(st))
        goto final;
    if (! stWriteStartSequence(st))
		goto final;   

	return st;

 final:
	freeStack(st);
	return NULL;
}

uint8_t writePublicECCKeyToFile(const char *filename, PublicECCKey key)
{
    Stack st;
	uint8_t r;
	unsigned char *b64data;

    r = 0;
	st = NULL;
	b64data = NULL;
	if ((st = writePublicECCKeyToStack(key)) == NULL)
		goto final;
    
    size_t outlen;
	int fd;
	if ((b64data = b64_encode(st->data, st->used, &outlen)) == NULL)
		goto final;

    /*
	   Write to a file
	 */
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
		goto final;

	size_t t;
	t = strlen((char *)beccpubk);
	if (write(fd, beccpubk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	if (write(fd, b64data, outlen) != outlen)
		WRITEERROR;
	t = strlen((char *)eeccpubk);
	if (write(fd, eeccpubk, t) != t)
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

PublicECCKey readPublicECCKeyFromStack(Stack st, EllipticCurves ecs)
{
	PublicECCKey key;
	EllipticCurve ec;
	BigInteger x, y;
	key = NULL;
	ec = NULL;
	x = y = NULL;
	
	/*
	   Initialize the key variable
	 */
	if ((key = initECCPublicKey()) == NULL)
		goto final;

	/*
	   Read the initial sequence data from the stack
	 */
	size_t length;
	int error;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	if (length != stBytesRemaining(st))
		goto final;

	/*
		Read the Object Identifiers 
	*/
	if (! stReadECCEncryptionOI(st))
		goto final;
	if ((ec = stReadECCEncryptionCurveOI(st,ecs)) == NULL)
		goto final;
	key->ec = ec;

	/*
		Read the Big Integers
	*/
	length = stReadStartOctetStringAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	READ_BI_FROM_STACK(x);
	READ_BI_FROM_STACK(y);

	if ((key->P = initEllipticCurvePoint(x, y, key->ec)) == NULL)
		goto final;
	x = y = NULL;

	return key;

final:
	freePublicECCKey(key);
	freeBigInteger(x);
	freeBigInteger(y);
	return NULL;
}

PublicECCKey readPublicECCKeyFromFile(const char *filename, EllipticCurves ecs)
{
	unsigned char *str, *begin, *der;
	size_t len, outlen, alloc;
	Stack st;
	PublicECCKey key;
	int ok;

	key = NULL;
	st = NULL;
	str = der = NULL;
	ok = 0;
	if ((str = readFileBinaryMode(filename, &len, &alloc)) == NULL)
		return NULL;
	if (len == 0)
		goto final;

	/*
	   Clear begin and end comments
	 */
	if ((begin = clearCcommentsInText(str,beccpubk,eeccpubk)) == NULL)
		goto final;
	len = strlen((char *)begin);

	/*
	   Decode the data with base64
	   Initialize the stack and copy data
	 */
	if ((der = b64_decode((unsigned char *)begin, len, &outlen)) == NULL)
		goto final;

	if ((st = stInitStackWithSize(outlen + 512)) == NULL)
		goto final;
	memcpy(st->data, der, outlen);
	st->used = outlen;

	if ((key = readPublicECCKeyFromStack(st,ecs)) == NULL)
		goto final;

	ok = 1;

final:
	if (!ok)
	{
		freePublicECCKey(key);
		key = NULL;
	}
	freeStack(st);
	freeString(str);
	freeString(der);
	return key;
}

uint8_t writeEncryptedPrivateECCKeyToFile(const char *filename, PrivateECCKey key)
{
	Stack st;
	unsigned char salt[SALTLEN];
	const char enc[] = "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC";
	uint8_t ret;

	ret = 0;
	if ((st = writePrivateECCKeyToStack(key)) == NULL)
		goto final;

	if (encryptStackAES(st, NULL, 0, STACKENCODE, KDFARGON2) != ENCRYPTION_AES_OK)
		goto final;

	/*
	   Write to a file
	 */
	int fd;
	size_t t;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
		goto final;

	t = strlen((char *)beccpk);
	if (write(fd, beccpk, t) != t)
		WRITEERROR;
	t = strlen(enc);
	if (write(fd, enc, t) != t)
		WRITEERROR;
	if (write(fd, "\n\n", 2) != 2)
		WRITEERROR;
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	t = strlen((char *)eeccpk);
	if (write(fd, eeccpk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	close(fd);
	ret = 1;

 final:
	freeStack(st);
	return ret;
}

PrivateECCKey readEncryptedPrivateECCKeyFromFile(const char *filename, EllipticCurves ecs)
{
	unsigned char *begin, *text;
	size_t nbytes, alloc;
	Stack st;
	PrivateECCKey key;
	int ok;

	key = NULL;
	st = NULL;
	text = NULL;
	ok = 0;
	if ((text = readFileBinaryMode(filename, &nbytes, &alloc)) == NULL)
		goto final;
	if (nbytes == 0)
		goto final;

	if ((begin = clear_ecc_private_info(text)) == NULL)
		goto final;
	nbytes = strlen((char *)begin);

	if ((st = stInitStackWithSize(nbytes + 512)) == NULL)
		goto final;
	memcpy(st->data, begin, nbytes);
	st->used = nbytes;
	freeString(text);

	if (decryptStackAES(st, NULL, 0, STACKENCODE, KDFARGON2) != ENCRYPTION_AES_OK)
		goto final;

	if ((key = readPrivateECCKeyFromStack(st, ecs)) == NULL)
		goto final;

	ok = 1;

 final:
	if (!ok)
	{
		freePrivateECCKey(key);
		key = NULL;
	}
	freeStack(st);
	freeString(text);
	return key;
}

int generateAndSavePairECCKeys(char *filename, EllipticCurve ec, int aes)
{
	PrivateECCKey key;
	PublicECCKey pkey;
	int ret;
	char *pub, *priv;

	key = NULL;
	pkey = NULL;
	pub = priv = NULL;
	ret = 0;

	if ((key = generateECCPrivateKey(ec)) == NULL)
		goto final;
	if((pub = (char *)calloc(strlen(filename) + 5,sizeof(char))) == NULL)
		goto final;
	if((priv = (char *)calloc(strlen(filename) + 5,sizeof(char))) == NULL)
		goto final;

	sprintf(pub, "%s.pub",filename);
	sprintf(priv, "%s.key",filename);
	
	if ((pkey = publicECCKeyFromPrivate(key)) == NULL)
		goto final;

	if (! writePublicECCKeyToFile(pub, pkey))
		goto final;

	if (aes)
	{
		if (! writeEncryptedPrivateECCKeyToFile(priv, key))
			goto final;
		ret = 1;
		goto final;
	}

	if (! writePrivateECCKeyToFile(priv, key))
		goto final;

	ret = 1;

final:
	freePrivateECCKey(key);
	freePublicECCKey(pkey);
	freeString(pub);
	freeString(priv);
	if (ret == 0)
	{
		unlink(pub);
		unlink(priv);
	}
	return ret;
}




