/**************************************************************************************
 * Filename:   encryption.c
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
#include <fcntl.h>
#include <stdlib.h>

#define WRITEERROR {                            \
		close(fd);						        \
		unlink(*outfile);					    \
		ret =  ENCRYPTION_ECC_WRITE_FILE_ERROR; \
		goto final;							    \
	}

static const unsigned char beccf[] = "-----BEGIN EC ENCRYPTED FILE-----";
static const unsigned char eeccf[] = "-----END EC ENCRYPTED FILE-----";

int encryptFileWithECC(char *infile, char **outfile, char *keyfile, EllipticCurves ecs, int ascii)
{
    Stack st;
	unsigned char *text;
	size_t ndigits, nbytes, nbits, alloc, length, secretlen;
	int ret;
	uint8_t mode;
	PublicECCKey pkey;
	unsigned char *secret;
	BigInteger k, x, y;
    EllipticCurvePoint G, R, S;

    G = R = S = NULL;
	x = y = NULL;
	st = NULL;
	pkey = NULL;
	ret = ENCRYPTION_ECC_ERROR;
    if (*outfile == NULL)
	{
		if((*outfile = (char *)calloc(strlen(infile) + 12,sizeof(char))) == NULL)
			goto final;
		if (ascii)
			sprintf(*outfile, "%s.ecc.asc", infile);
		else
			sprintf(*outfile, "%s.ecc", infile);
	}

    /*
        Read the public key and obtain the point G
    */
    if ((pkey = readPublicECCKeyFromFile(keyfile, ecs)) == NULL)
        goto final;
    if ((x = cloneBigInteger(pkey->ec->Gx)) == NULL)
        goto final;
    if ((y = cloneBigInteger(pkey->ec->Gy)) == NULL)
        goto final;
    if ((G = initEllipticCurvePoint(x, y, pkey->ec)) == NULL)
        goto final;
    x = y = NULL;

    /*
        Select a random integer k with nbits and compute R = kG
    */
    nbits = bitsInBigInteger(pkey->ec->n);
    for(;;)
    {
        int cmp;
        if ((k = randomPositiveBigIntegerWithBits(nbits)) == NULL)
            goto final;
        cmp = compareBigIntegerAbsoluteValues(k,pkey->ec->n);
        if ((R = multiplyEllipticCurvePointByBigInteger(G, k, pkey->ec)) == NULL)
        {
            freeBigInteger(k);
            continue;
        }
        if ((cmp < 0) && (sizeOfBigInteger(R->x) > 0))
            break;
        freeBigInteger(k);
        freeEllipticCurvePoint(R);
    }

    /*
        Compute S = k * P where P is the public key point and generate a secret from S
    */
    if ((S = multiplyEllipticCurvePointByBigInteger(pkey->P, k, pkey->ec)) == NULL)
        goto final;

    secretlen = (S->x->used + S->y->used) * BYTES_PER_DIGIT;
    if ((secret = (unsigned char *)malloc(secretlen * sizeof(unsigned char))) == NULL)
		goto final;
    memcpy(secret,(unsigned char *)(S->x->digits), S->x->used * BYTES_PER_DIGIT);
    memcpy(secret + S->x->used * BYTES_PER_DIGIT,(unsigned char *)(S->y->digits), S->y->used * BYTES_PER_DIGIT);

    /*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_ECC_FILE_NOT_FOUND;
		goto final;
	}

    /*
		Init the stack and write the data and the filename to it
	*/
	if ((st = stInitStackWithSize(nbytes + 1024)) == NULL)
		goto final;
	if (! stWriteOctetString(st,text,nbytes))
		goto final;
	freeString(text);
	if (! stWriteOctetString(st,(unsigned char *)infile,strlen(infile)))
		goto final;

    /*
		Encrypt the Stack
	*/
    mode = STACKCOMPRESS | STACKHMAC;
    if (encryptStackAES(st, secret, secretlen, mode, KDFARGON2) != ENCRYPTION_AES_OK)
		goto final;

    /*
        Add the number R to the stack
    */
    if (! stWriteBigInteger(st, R->y))
		goto final;
    if (! stWriteBigInteger(st, R->x))
		goto final;
    if (! stWriteStartSequence(st))
		goto final;

    /*
        Write the encrypted file
    */
    int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_ECC_OPEN_FILE_ERROR;
		goto final;
	}
    if (ascii)
    {
        if ((text = b64_encode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st,text,nbytes,nbytes);
		text = NULL;

        size_t t;
		t = strlen((char *)beccf);
		if (write(fd, beccf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)eeccf);
		if (write(fd, eeccf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = ENCRYPTION_ECC_OK;
		goto final;
    }
    if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
    close(fd);
    ret = ENCRYPTION_ECC_OK;

final:
    freeStack(st);
    freeBigInteger(k);
    freeBigInteger(x);
    freeBigInteger(y);
    freeEllipticCurvePoint(G);
    freeEllipticCurvePoint(R);
    freeEllipticCurvePoint(S);
    freePublicECCKey(pkey);
    freeString(secret);
    return ret;
}

int decryptFileWithECC(char *infile, char *keyfile, EllipticCurves ecs)
{
    Stack st;
	unsigned char *text, *begin, *secret, *filename, *s;
	size_t nbytes, alloc, length, secretlen;
	int ret, error;
	uint8_t mode;
    unsigned char salt[SALTLEN];
    unsigned char hmacsecret[64];
	PrivateECCKey key;
    EllipticCurvePoint G, R, S;
    BigInteger x, y;

	st = NULL;
	key = NULL;
    x = y = NULL;
    G = R = S = NULL;
	ret = ENCRYPTION_ECC_ERROR;

    /*
	   Initialize the Stack
	 */
	if ((st = stInitStack()) == NULL)
		goto final;

    /*
        Read the private key from the file
    */
    if ((key = readPrivateECCKeyFromFile(keyfile, ecs)) == NULL)
	{
		if ((key = readEncryptedPrivateECCKeyFromFile(keyfile, ecs)) == NULL)
		{
			ret = ENCRYPTION_ECC_PRIVATE_KEY_ERROR;
			goto final;
		}
	}

    /*
        Get the point G from the elliptic curve key->ec
    */
    if ((x = cloneBigInteger(key->ec->Gx)) == NULL)
        goto final;
    if ((y = cloneBigInteger(key->ec->Gy)) == NULL)
        goto final;
    if ((G = initEllipticCurvePoint(x, y, key->ec)) == NULL)
        goto final;
    x = y = NULL;

    /*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_ECC_FILE_NOT_FOUND;
		goto final;
	}

    if ((begin = clearCcommentsInText(text,beccf,eeccf)) != NULL)
	{
		length = strlen((char *)begin);
		if ((st = stInitStackWithSize(length + 128)) == NULL)
			goto final;
		memcpy(st->data, begin, length);
		st->used = length;
        freeString(text);
        if ((text = b64_decode(st->data, st->used, &nbytes)) == NULL)
			goto final;
        stSetDataInStack(st, text, nbytes, nbytes);
		text = NULL;
	}
	else
	{
		if ((st = stInitStack()) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
		mode = 0;
		text = NULL;
	}

    /*
        Get the point R from the stack
    */
    length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;    
	if (length != stBytesRemaining(st))
		goto final;

    if (((x = stReadBigInteger(st, &error)) == NULL) || (error != 0))
		goto final;
    if (((y = stReadBigInteger(st, &error)) == NULL) || (error != 0))
		goto final;
    if ((R = initEllipticCurvePoint(x, y, key->ec)) == NULL)
        goto final;
    x = y = NULL;

    /*
        Compute the point S
    */
    if ((S = multiplyEllipticCurvePointByBigInteger(R, key->private, key->ec)) == NULL)
        goto final;
    secretlen = (S->x->used + S->y->used) * BYTES_PER_DIGIT;
    if ((secret = (unsigned char *)malloc(secretlen * sizeof(unsigned char))) == NULL)
		goto final;
    memcpy(secret,(unsigned char *)(S->x->digits), S->x->used * BYTES_PER_DIGIT);
    memcpy(secret + S->x->used * BYTES_PER_DIGIT,(unsigned char *)(S->y->digits), S->y->used * BYTES_PER_DIGIT);

    /*
		Decrypt the Stack
	*/
    mode = STACKCOMPRESS | STACKHMAC;
    if (decryptStackAES(st, secret, secretlen, mode, KDFARGON2) != ENCRYPTION_AES_OK)
		goto final;
    
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
        Write the file
    */
    if ((text = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
    int fd;
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0) 
	{
		ret = ENCRYPTION_ECC_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, text, length) != length)
	{
		ret = ENCRYPTION_ECC_WRITE_FILE_ERROR;
		goto final;
	}
	close(fd);
	printf("Writing file %s\n",filename);
    ret = ENCRYPTION_ECC_OK;

final:
    freeStack(st);
    freeEllipticCurvePoint(G);
    freeEllipticCurvePoint(R);
    freeEllipticCurvePoint(S);
    freeBigInteger(x);
    freeBigInteger(y);
    freePrivateECCKey(key);
    freeString(text);
    freeString(secret);
    return ret;
}

