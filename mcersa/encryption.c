/**************************************************************************************
 * Filename:   encryption.c
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
#include <fcntl.h>
#include <stdlib.h>

#define WRITEERROR {                            \
		close(fd);						        \
		unlink(*outfile);					    \
		ret =  ENCRYPTION_RSA_WRITE_FILE_ERROR; \
		goto final;			 				    \
	}

static const unsigned char brsaf[] = "-----BEGIN RSA ENCRYPTED FILE-----";
static const unsigned char ersaf[] = "-----END RSA ENCRYPTED FILE-----";

int encryptFileWithRSA(char *infile, char **outfile, char *keyfile, int ascii)
{
	Stack st;
	unsigned char *text;
	size_t ndigits, nbytes, alloc, length;
	int ret;
	uint8_t mode;
	PublicRSAKey rsa;
	unsigned char secret[SECRETLEN];
	BigInteger m, c;

	m = c = NULL;
	st = NULL;
	rsa = NULL;
	ret = ENCRYPTION_RSA_ERROR;
	if (*outfile == NULL)
	{
		if((*outfile = (char *)calloc(strlen(infile) + 8,sizeof(char))) == NULL)
			goto final;
		if (ascii)
			sprintf(*outfile, "%s.asc", infile);
		else
			sprintf(*outfile, "%s.rsa", infile);
	}

	/*
	   Initialize the Stack
	*/
	if ((st = stInitStack()) == NULL)
		goto final;
	
	/*
		Read the public key file
	*/
	if ((rsa = readPublicRSAKeyFromFile(keyfile)) == NULL)
	{
		ret = ENCRYPTION_RSA_PUBLIC_KEY_ERROR;
		goto final;
	}

	/*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_RSA_FILE_NOT_FOUND;
		goto final;
	}
	
	/*
		ReInit the stack and write the data and the filename to it
	*/
	if (! stReInitStackWithSize(st, nbytes + 1024))
		goto final;
	if (! stWriteOctetString(st,text,nbytes))
		goto final;
	freeString(text);
	if (! stWriteOctetString(st,(unsigned char *)(*outfile),strlen(*outfile)))
		goto final;

	/*
		Encrypt the Stack
	*/
	mode = STACKCOMPRESS;
	if (! getRandomSecret(secret))
		goto final;
	
	if (encryptStackAES(st, secret, SECRETLEN, mode, KDFARGON2) != ENCRYPTION_AES_OK)
		goto final;

	/*
		Convert the secret to a Big Integer and write it to the stack
	*/
	ndigits = (SECRETLEN + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((m = initBigInteger(ndigits)) == NULL)
		goto final;
	m->used = ndigits;
	memcpy((void *)(m->digits),secret,SECRETLEN);

	if ((c = publicEncryptOAEPRSA(rsa, m)) == NULL)
		goto final;
	freeBigInteger(m);

	if (! stWriteBigInteger(st, c))
		goto final;

	if (! stWriteStartSequence(st))
		goto final;

	if (ascii)
	{
		if ((text = b64_encode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st,text,nbytes,nbytes);
		text = NULL;
	}

	/*
		Write the encrypted file
	*/
	int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_RSA_OPEN_FILE_ERROR;
		goto final;
	}
	if (ascii) {
		size_t t;
		t = strlen((char *)brsaf);
		if (write(fd, brsaf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)ersaf);
		if (write(fd, ersaf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = ENCRYPTION_RSA_OK;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	
	ret = ENCRYPTION_RSA_OK;
	
final:
	freeStack(st);
	freeString(text);
	freePublicRSAKey(rsa);
	return ret;
}

int decryptFileWithRSA(char *infile, char *keyfile)
{
	Stack st;
	unsigned char *text, *begin, *filename, *s;
	size_t nbytes, alloc, length;
	int ret, error;
	uint8_t mode;
	PrivateRSAKey rsa;
	unsigned char secret[SECRETLEN];
	BigInteger m, c;

	m = c = NULL;
	st = NULL;
	rsa = NULL;
	ret = ENCRYPTION_RSA_ERROR;
	/*
		Read the private key file
	*/
	if (((rsa = readPrivateRSAKeyFromFile(keyfile)) == NULL) &&
	    ((rsa = readEncryptedPrivateRSAKeyFromFile(keyfile)) == NULL))
	{
		ret = ENCRYPTION_RSA_PRIVATE_KEY_ERROR;
		goto final;
	}
	/*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL) {
		ret = ENCRYPTION_RSA_FILE_NOT_FOUND;
		goto final;
	}
	if ((begin = clearCcommentsInText(text,brsaf,ersaf)) != NULL)
	{
		length = strlen((char *)begin);
		if ((st = stInitStackWithSize(length + 128)) == NULL)
			goto final;
		memcpy(st->data, begin, length);
		st->used = length;
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

	/*
		Read the encryption secret
	*/
	if (((c = stReadBigInteger(st, &error)) == NULL) || (error != 0))
		goto final;
	if ((m = privateDecryptOAEPRSA(rsa, c)) == NULL) {
		ret = SIGNATURE_RSA_BAD;
		goto final;
	}
	freeBigInteger(c);
	memcpy(secret, m->digits, SECRETLEN);
	freeBigInteger(m);
	freePrivateRSAKey(rsa);

	/*
		Decrypt the stack
	*/
	if ((ret = decryptStackAES(st, secret, SECRETLEN, STACKCOMPRESS, KDFARGON2)) != ENCRYPTION_AES_OK)
		goto final;

	/*
		Read the filename, the contents of the file and uncompress them	
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

	if ((text = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
	stSetDataInStack(st, text, length, length);
	text = NULL;

	if ((text = zlib_uncompress_data(st->data, st->used, &nbytes, &length)) == NULL)
		goto final;	
	stSetDataInStack(st, text, nbytes, length);
	text = NULL;

	int fd;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_RSA_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used) {
		close(fd);
		unlink(filename);
		ret = ENCRYPTION_RSA_WRITE_FILE_ERROR;
		goto final;
	}
	
	close(fd);
	ret = ENCRYPTION_RSA_OK;
	
final:
	freeStack(st);
	freeString(text);
	return ret;
}

