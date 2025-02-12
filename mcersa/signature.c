/**************************************************************************************
 * Filename:   signature.c
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
#include <mcersa.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

static const unsigned char bsigf[] = "-----BEGIN RSA SIGNED FILE-----";
static const unsigned char esigf[] = "-----END RSA SIGNED FILE-----";

#define SHA512_DIGEST_SIZE 512/8 
#define WRITEERROR {                        \
		close(fd);						    \
		unlink(*outfile);					\
		ret = SIGNATURE_RSA_WRITE_FILE_ERROR;   \
		goto final;							\
	}

int signStackRSA(Stack st, PrivateRSAKey rsa, const char *filename, uint8_t mode)
{
	size_t ndigits, nbytes, alloc, usize;
	unsigned char *text;
	unsigned char digest[SHA512_DIGEST_SIZE];
	int ret;
	BigInteger m, c;

	ret = SIGNATURE_RSA_ERROR;
	m = c = NULL;
	text = NULL;
	if ((st == NULL) || (st->data == NULL) || (st->used == 0))
		goto final;
	usize = st->used;
	if (mode & STACKCOMPRESS)
	{
		if ((text = zlib_compress_data(st->data,st->used,&nbytes,&alloc)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
		text = NULL;
	}
	nbytes = st->used;
	/*
		Compute SHA512
	*/
	textToSHA512(st->data,nbytes,digest);

	/*
        Copy the (maybe compressed) data to the variable "text"
    */
	if ((text = (unsigned char *)malloc(nbytes * sizeof(unsigned char))) == NULL)
		goto final;
	memcpy(text,st->data,nbytes);

	/*
		ReInit the stack and write the compressed data and the filename to it
	*/
	if (! stReInitStackWithSize(st, nbytes + 1024))
		goto final;

	if (! stWriteOctetString(st,text,nbytes))
		goto final;
	freeString(text);
	if (! stWriteOctetString(st,(unsigned char *)filename,strlen(filename)))
		goto final;

	/*
		Convert the digest to a Big Integer and encrypt it with the private RSA key
	*/
	ndigits = (SHA512_DIGEST_SIZE + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((m = initBigInteger(ndigits)) == NULL)
		goto final;
	m->used = ndigits;
	memcpy((void *)(m->digits),digest,SHA512_DIGEST_SIZE);

	if ((c = privateEncryptOAEPRSA(rsa, m)) == NULL)
		goto final;
	freeBigInteger(m);

	if (! stWriteBigInteger(st, c))
		goto final;

	if (! stWriteDigit(st, usize))
		goto final;

	if (! stWriteStartSequence(st))
		goto final;

	if (mode & STACKENCODE)
	{
		if ((text = b64_encode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st,text,nbytes,nbytes);
		text = NULL;
	}

	ret = SIGNATURE_RSA_OK;	
 
final:
 	freeString(text);
 	freeBigInteger(m);
 	freeBigInteger(c);
 	return ret;
}

int verifyAndExtractStackRSA(Stack st,PublicRSAKey rsa,uint8_t mode)
{
	size_t nbytes, length, usize;
	unsigned char *text, *s;
	char *filename;
	unsigned char digest[2 * SHA512_DIGEST_SIZE];
	int ret, error;
	BigInteger m, c;

	ret = SIGNATURE_RSA_ERROR;
	m = c = NULL;
	text = s = NULL;
	filename = NULL;
	if ((st == NULL) || (st->data == NULL) || (st->used == 0))
		goto final;

	if (mode & STACKENCODE)
	{
		if ((text = b64_decode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, nbytes);
		text = NULL;
	}

	/*
		Start reading the stack
	*/
	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;
	if (length != stBytesRemaining(st))
		goto final;
	usize = stReadDigit(st,&error);
	if (error != 0)
		goto final;
	if (((c = stReadBigInteger(st, &error)) == NULL) || (error != 0))
		goto final;
	if ((m = publicDecryptOAEPRSA(rsa, c)) == NULL) {
		ret = SIGNATURE_RSA_BAD;
		goto final;
	}
	freeBigInteger(c);

	memcpy(digest, m->digits, SHA512_DIGEST_SIZE);

	/*
		Read the filename
	*/
	if ((s = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
	if ((filename = (char *)malloc((length + 1) * sizeof(char))) == NULL)
		goto final;
	memcpy(filename, s, length);
	filename[length] = '\0';
 	free(s);

	/*
		Read the contents of the file and compute its SHA512 digest
	*/
	if ((text = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;

	textToSHA512(text, length, digest + SHA512_DIGEST_SIZE);
	/*
		Copy the contents of the file to the stack and decompress
	*/
	stSetDataInStack(st, text, length, length);
	text = NULL;

	if (mode & STACKCOMPRESS)
	{
		if ((text = zlib_uncompress_data(st->data, st->used, usize)) == NULL)
			goto final;	
		stSetDataInStack(st, text, usize, usize);
		text = NULL;
	}

	int fd;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0) 
	{
		ret = SIGNATURE_RSA_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
	{
		ret = ENCRYPTION_RSA_WRITE_FILE_ERROR;
		goto final;
	}

	if (strncmp((char *)digest,(char *)digest + SHA512_DIGEST_SIZE,SHA512_DIGEST_SIZE) != 0)
	{
		ret = SIGNATURE_RSA_BAD;
		goto final;
	}


	ret = SIGNATURE_RSA_OK;

final:
 	freeString(text);
 	freeString(filename);
 	freeBigInteger(m);
 	freeBigInteger(c);
 	return ret;
}

int signFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii)
{
	Stack st;
	unsigned char *text;
	size_t nbytes, alloc;
	int ret;
	uint8_t mode;
	PrivateRSAKey rsa;

	st = NULL;
	rsa = NULL;
	ret = SIGNATURE_RSA_ERROR;
	
	if (*outfile == NULL)
	{
		if((*outfile = (char *)calloc(strlen(infile) + 12,sizeof(char))) == NULL)
			goto final;
		if (ascii)
			sprintf(*outfile, "%s.sig.asc", infile);
		else
			sprintf(*outfile, "%s.sig", infile);
	}

	/*
	   Initialize the Stack
	 */
	if ((st = stInitStack()) == NULL)
		goto final;
	
	/*
	   Read the private key file
	 */
	if (((rsa = readPrivateRSAKeyFromFile(keyfile)) == NULL))
	{
		if ((rsa = readEncryptedPrivateRSAKeyFromFile(keyfile)) == NULL)
		{
			ret = SIGNATURE_RSA_PRIVATE_KEY_ERROR;
			goto final;
		}
	}
	
	/*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = SIGNATURE_RSA_FILE_NOT_FOUND;
		goto final;
	}
	stSetDataInStack(st, text, nbytes, alloc);
	text = NULL;

	/*
	   Sign the Stack
	 */
	mode = STACKCOMPRESS;
	if (ascii)
		mode += STACKENCODE;
	if ((ret = signStackRSA(st,rsa,infile,mode)) != SIGNATURE_RSA_OK)
		goto final;

	/*
	   Write the signed file
	 */
	int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
	{
		ret = SIGNATURE_RSA_OPEN_FILE_ERROR;
		goto final;
	}

	if (ascii)
	{
		size_t t;
		t = strlen((char *)bsigf);
		if (write(fd, bsigf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)esigf);
		if (write(fd, esigf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = SIGNATURE_RSA_OK;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	
	ret = SIGNATURE_RSA_OK;
	
final:
	freeStack(st);
	freeString(text);
	freePrivateRSAKey(rsa);
	return ret;
}

int verifyAndExtractSignedFileWithRSA(char *infile,char *keyfile)
{
	Stack st;
	unsigned char *text, *begin;
	size_t nbytes, alloc, len;
	int ret;
	uint8_t mode;
	PublicRSAKey rsa;
	
	st = NULL;
	rsa = NULL;
	ret = SIGNATURE_RSA_ERROR;
	/*
		Read the public key file
	 */
	if ((rsa = readPublicRSAKeyFromFile(keyfile)) == NULL)
	{
		ret = SIGNATURE_RSA_PUBLIC_KEY_ERROR;
		goto final;
	}

	/*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = SIGNATURE_RSA_FILE_NOT_FOUND;
		goto final;
	}
	if ((begin = clearCcommentsInText(text,bsigf,esigf)) != NULL)
	{
		len = strlen((char *)begin);
		if ((st = stInitStackWithSize(len + 128)) == NULL)
			goto final;
		memcpy(st->data, begin, len);
		st->used = len;
		mode = STACKENCODE;
		freeString(text);
	}
	else
	{
		if ((st = stInitStack()) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
		mode = 0;
		text = NULL;
	}
	mode += STACKCOMPRESS;

	/*
		Verify the data in the stack
	*/
	if ((ret = verifyAndExtractStackRSA(st, rsa, mode)) != SIGNATURE_RSA_OK)
		goto final;
	
	ret = SIGNATURE_RSA_OK;
	
final:
	freeStack(st);
	freeString(text);
	freePublicRSAKey(rsa);
	return ret;
}
