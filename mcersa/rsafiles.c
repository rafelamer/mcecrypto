/**************************************************************************************
* Filename:   rsafiles.c
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
#include <mcersa.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

static const unsigned char brsapk[] = "-----BEGIN RSA PRIVATE KEY-----";
static const unsigned char ersapk[] = "-----END RSA PRIVATE KEY-----";
static const unsigned char bpk[] = "-----BEGIN PRIVATE KEY-----";
static const unsigned char epk[] = "-----END PRIVATE KEY-----";
static const unsigned char bpubk[] = "-----BEGIN RSA PUBLIC KEY-----";
static const unsigned char epubk[] = "-----END RSA PUBLIC KEY-----";

/*
	The rsaEncription Object Identifier is 1.2.840.113549.1.1.1
*/

static unsigned char rsaEncryption[] = { 0x30, 0x0C, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x00 };

#define OIDRSAENCRYPTIONLENGTH 14
#define READ_BI_FROM_STACK(n)     n = stReadBigInteger(st, &error);  \
    if ((n == NULL) || (error != 0))                                 \
        goto final;

#define WRITEERROR     { \
     close(fd);          \
     unlink(filename);   \
     goto final;         \
  }

static unsigned char *clear_rsa_private_info(const unsigned char *string)
{
	unsigned char *begin, *end;
	size_t i;

	if ((begin = (unsigned char *)strstr((char *)string,(char *)brsapk)) == NULL)
		return NULL;

	begin += strlen((char *)brsapk);
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

	if ((end = (unsigned char *)strstr((char *)begin,(char *)ersapk)) == NULL)
		return NULL;
	*end = '\0';

	while (*begin == '\n')
		begin++;
	return begin;
}

int stWriteRSAEncryptionOI(Stack st)
{
	if ((OIDRSAENCRYPTIONLENGTH + st->used) > st->alloc)
		if (! stExpandStackInSize(st, 1024))
			return 0;
	memmove(st->data + OIDRSAENCRYPTIONLENGTH, st->data, st->used);
	memcpy(st->data, rsaEncryption, OIDRSAENCRYPTIONLENGTH);
	st->used += OIDRSAENCRYPTIONLENGTH;
	return 1;
}

int stReadOptionalRSAEncryptionOI(Stack st)
{
	unsigned char b;

	b = *(st->read);
	if (b != 0x30)
		return 0;
	if (memcmp(st->read, rsaEncryption, OIDRSAENCRYPTIONLENGTH) != 0)
		return 0;
	st->read += OIDRSAENCRYPTIONLENGTH;
	return 1;
}

static Stack writePrivateRSAKeyToStack(PrivateRSAKey rsa)
{
	Stack st;

	st = NULL;
	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;
	/*
	   Sequence of integers
	 */
	if (! stWriteBigInteger(st, rsa->c2))
		goto final;
	if (! stWriteBigInteger(st, rsa->kq))
		goto final;
	if (! stWriteBigInteger(st, rsa->kp))
		goto final;
	if (! stWriteBigInteger(st, rsa->q))
		goto final;
	if (! stWriteBigInteger(st, rsa->p))
		goto final;
	if (! stWriteBigInteger(st, rsa->dk))
		goto final;
	if (! stWriteBigInteger(st, rsa->pub->ek))
		goto final;
	if (! stWriteBigInteger(st, rsa->pub->n))
		goto final;
	
	/*
	   Zero integer
	 */
	if (! stWriteDigit(st, (DIGIT)0))
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
	   Object rsaEncryption identifier
	 */
	if (! stWriteRSAEncryptionOI(st))
		goto final;
	
	/*
	   Zero integer
	 */
	if (!stWriteDigit(st, (DIGIT)0))
		goto final;
	
	/*
	   Total length and sequence
	 */
	if (! stWriteStartSequence(st))
		goto final;

	return st;

 final:
	freeStack(st);
	return NULL;
}

uint8_t writePrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa)
{
	Stack st;
	uint8_t r;
	unsigned char *b64data;

	r = 0;
	st = NULL;
	b64data = NULL;
	if ((st = writePrivateRSAKeyToStack(rsa)) == NULL)
		goto final;

	/*
	   Encode the data with base64
	 */
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
	t = strlen((char *)brsapk);
	if (write(fd, brsapk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	if (write(fd, b64data, outlen) != outlen)
		WRITEERROR;
	t = strlen((char *)ersapk);
	if (write(fd, ersapk, t) != t)
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

uint8_t writeEncryptedPrivateRSAKeyToFile(const char *filename, PrivateRSAKey rsa)
{
	Stack st;
	unsigned char salt[SALTLEN];
	const char enc[] = "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC";
	uint8_t ret;

	ret = 0;
	if ((st = writePrivateRSAKeyToStack(rsa)) == NULL)
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

	t = strlen((char *)brsapk);
	if (write(fd, brsapk, t) != t)
		WRITEERROR;
	t = strlen(enc);
	if (write(fd, enc, t) != t)
		WRITEERROR;
	if (write(fd, "\n\n", 2) != 2)
		WRITEERROR;
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	t = strlen((char *)ersapk);
	if (write(fd, ersapk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	close(fd);
	ret = 1;

 final:
	freeStack(st);
	return ret;
}

static PrivateRSAKey readPrivateRSAKeyFromStack(Stack st)
{
	PrivateRSAKey rsa;
	rsa = NULL;
	/*
	   Initialize the rsa variable
	 */
	if ((rsa = initRSAPrivateKey()) == NULL)
		goto final;

	/*
	   Read the data from the stack
	 */
	size_t length;
	int error;
	DIGIT digit;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	if (length != stBytesRemaining(st))
		goto final;

	digit = stReadDigit(st, &error);
	if ((digit != 0) || (error != 0))
		goto final;

	if (stReadOptionalRSAEncryptionOI(st) == 1)
	{
		length = stReadStartOctetStringAndLength(st, &error);
		if ((length == 0) || (error != 0))
			goto final;

		length = stReadStartSequenceAndLength(st, &error);
		if ((length == 0) || (error != 0))
			goto final;

		digit = stReadDigit(st, &error);
		if ((digit != 0) || (error != 0))
			goto final;
	}
	READ_BI_FROM_STACK(rsa->pub->n);
	READ_BI_FROM_STACK(rsa->pub->ek);
	READ_BI_FROM_STACK(rsa->dk);
	READ_BI_FROM_STACK(rsa->p);
	READ_BI_FROM_STACK(rsa->q);
	READ_BI_FROM_STACK(rsa->kp);
	READ_BI_FROM_STACK(rsa->kq);
	READ_BI_FROM_STACK(rsa->c2);

	return rsa;

 final:
	freePrivateRSAKey(rsa);
	return NULL;
}

PrivateRSAKey readPrivateRSAKeyFromFile(const char *filename)
{
	unsigned char *str, *begin, *der;
	size_t len, outlen, alloc;
	Stack st;
	PrivateRSAKey rsa;
	int ok;

	rsa = NULL;
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

	if ((begin = clearCcommentsInText(str,brsapk,ersapk)) == NULL)
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

	if ((rsa = readPrivateRSAKeyFromStack(st)) == NULL)
		goto final;

	ok = 1;

 final:
	if (!ok)
	{
		freePrivateRSAKey(rsa);
		rsa = NULL;
	}
	freeStack(st);
	freeString(str);
	freeString(der);
	return rsa;
}

PrivateRSAKey readEncryptedPrivateRSAKeyFromFile(const char *filename)
{
	unsigned char *begin, *text;
	size_t nbytes, alloc;
	Stack st;
	PrivateRSAKey rsa;
	int ok;

	rsa = NULL;
	st = NULL;
	text = NULL;
	ok = 0;
	if ((text = readFileBinaryMode(filename, &nbytes, &alloc)) == NULL)
		goto final;
	if (nbytes == 0)
		goto final;

	if ((begin = clear_rsa_private_info(text)) == NULL)
		goto final;
	nbytes = strlen((char *)begin);

	if ((st = stInitStackWithSize(nbytes + 512)) == NULL)
		goto final;
	memcpy(st->data, begin, nbytes);
	st->used = nbytes;
	freeString(text);

	if (decryptStackAES(st, NULL, 0, STACKENCODE, KDFARGON2) != ENCRYPTION_AES_OK)
		goto final;

	if ((rsa = readPrivateRSAKeyFromStack(st)) == NULL)
		goto final;

	ok = 1;

 final:
	if (!ok)
	{
		freePrivateRSAKey(rsa);
		rsa = NULL;
	}
	freeStack(st);
	freeString(text);
	return rsa;
}

PublicRSAKey readPublicRSAKeyFromFile(const char *filename)
{
	unsigned char *str, *begin, *der;
	size_t len, outlen, alloc;
	Stack st;
	PublicRSAKey rsa;

	rsa = NULL;
	st = NULL;
	str = der = NULL;
	if ((str = readFileBinaryMode(filename, &len, &alloc)) == NULL)
		return NULL;
	if (len == 0)
		goto final;

	/*
	   Clear begin and end comments
	 */

	if ((begin = clearCcommentsInText(str,bpubk,epubk)) == NULL)
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
	freeString(der);
	freeString(str);

	if ((rsa = initRSAPublicKey()) == NULL)
		goto final;

	/*
	   Read the data from the stack
	 */
	size_t length;
	int error;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	error = stReadOptionalRSAEncryptionOI(st);

	length = stReadStartBitStringAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	while (*(st->read) != 0x30)
		st->read++;

	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;

	READ_BI_FROM_STACK(rsa->n);
	READ_BI_FROM_STACK(rsa->ek);

	freeStack(st);
	return rsa;

 final:
	freePublicRSAKey(rsa);
	freeString(str);
	freeString(der);
	freeStack(st);
	return NULL;
}

uint8_t writePublicRSAKeyToFile(const char *filename, PublicRSAKey rsa)
{
	unsigned char *b64data;
	uint8_t r;
	Stack st;

	st = NULL;
	b64data = NULL;
	r = 0;
	if ((st = stInitStackWithSize(2048)) == NULL)
		goto final;

	/*
	   Sequence of integers
	 */
	if (! stWriteBigInteger(st, rsa->ek))
		goto final;
	if (! stWriteBigInteger(st, rsa->n))
		goto final;

	/*
	   Length of integers and sequence
	 */
	if (! stWriteStartSequence(st))
		goto final;

	/*
	   Length and BIT STRING
	 */
	if (! stWriteStartBitString(st))
		goto final;

	/*
	   Object rsaEncryption identifier
	 */
	if (! stWriteRSAEncryptionOI(st))
		goto final;

	/*
	   Length of data and SEQUENCE
	 */
	if (! stWriteStartSequence(st))
		goto final;

	/*
	   Encode the data with base64
	 */
	size_t outlen;
	int fd;

	if ((b64data = b64_encode(st->data, st->used, &outlen)) == NULL)
		goto final;

	/*
	   Write to a file
	 */
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
		goto final;

	size_t t;
	t = strlen((char *)bpubk);
	if (write(fd, bpubk, t) != t)
		WRITEERROR;
	if (write(fd, "\n", 1) != 1)
		WRITEERROR;
	if (write(fd, b64data, outlen) != outlen)
		WRITEERROR;
	t = strlen((char *)epubk);
	if (write(fd, epubk, t) != t)
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

int generateAndSavePairRSAKeys(int bits, char *filename, int aes)
{
	PrivateRSAKey rsa;
	int ret;
	char *pub, *priv;

	rsa = NULL;
	pub = priv = NULL;
	ret = 0;

	if ((rsa = generateRSAPrivateKey(bits)) == NULL)
		goto final;
	if((pub = (char *)calloc(strlen(filename) + 5,sizeof(char))) == NULL)
		goto final;
	if((priv = (char *)calloc(strlen(filename) + 5,sizeof(char))) == NULL)
		goto final;

	sprintf(pub, "%s.pub",filename);
	sprintf(priv, "%s.key",filename);
	
	if (! writePublicRSAKeyToFile(pub, rsa->pub))
		goto final;

	if (aes)
	{
		if (! writeEncryptedPrivateRSAKeyToFile(priv, rsa))
			goto final;
		ret = 1;
		goto final;
	}

	if (! writePrivateRSAKeyToFile(priv, rsa))
		goto final;

	ret = 1;

final:
	freePrivateRSAKey(rsa);
	freeString(pub);
	freeString(priv);
	if (ret == 0)
	{
		unlink(pub);
		unlink(priv);
	}
	return ret;
}

