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
#include <mceecc.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

static const unsigned char becsigf[] = "-----BEGIN EC SIGNED FILE-----";
static const unsigned char eecsigf[] = "-----END EC SIGNED FILE-----";

#define SHA512_DIGEST_SIZE 512/8
#define SHA256_DIGEST_SIZE 256/8
#define WRITEERROR {                      \
	close(fd);						      \
	unlink(*outfile);					  \
	ret = SIGNATURE_ECC_WRITE_FILE_ERROR; \
	goto final;							  \
	}


int signStackECC(Stack st, PrivateECCKey key, const char *filename, uint8_t mode)
{
    size_t ndigits, nbytes, nbits, alloc, usize;
	unsigned char *text;
	unsigned char digest512[SHA512_DIGEST_SIZE];
    unsigned char digest256[SHA256_DIGEST_SIZE];
    unsigned char seconddigest512[SHA512_DIGEST_SIZE];
    unsigned char seconddigest256[SHA256_DIGEST_SIZE];
	int ret;
	BigInteger z, k, k1, x, y;
    EllipticCurvePoint G, R;

	ret = SIGNATURE_ECC_ERROR;
	z = k = k1 = x = y = z = NULL;
    G = R = NULL;
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
        Select a random integer k with nbits and compute R = kG
    */
    nbits = bitsInBigInteger(key->ec->n);
    for(;;)
    {
        int cmp;
        if ((k = randomPositiveBigIntegerWithBits(nbits)) == NULL)
            goto final;
        cmp = compareBigIntegerAbsoluteValues(k,key->ec->n);
        if ((R = multiplyEllipticCurvePointByBigInteger(G, k, key->ec)) == NULL)
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
		Compute the digest and take the first "nbits" bits
	*/
    if (nbits > 260)
    {
        textToSHA512(st->data,nbytes,digest512);
        textToSHA512(digest512,SHA512_DIGEST_SIZE,seconddigest512);
        if ((z = initBigIntegerFromBinaryData(nbits, seconddigest512, SHA512_DIGEST_SIZE)) == NULL)
            goto final;
    }
    else
    {
        textToSHA256(st->data,nbytes,digest256);
        textToSHA256(digest256,SHA256_DIGEST_SIZE,seconddigest256);
        if ((z = initBigIntegerFromBinaryData(nbits, seconddigest256, SHA256_DIGEST_SIZE)) == NULL)
            goto final;
    }

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
        Compute k^(-1) and the signature r = R->x s = k^(-1) * (z + r * d)
        where d is the private key
    */
    int8_t error;
    if ((k1 = modularInverseOfBigInteger(k, key->ec->n, &error)) == NULL)
        goto final;
    if (error != 0)
        goto final;

    if ((x = multiplyTwoBigIntegers(key->private, R->x)) == NULL)
        goto final;
    if ((y = addBigIntegers(x, z)) == NULL)
        goto final;
    freeBigInteger(x);
    if ((x = multiplyTwoBigIntegers(k1, y)) == NULL)
        goto final;
    if (! normalizeBigIntegerModulus(&x, key->ec->n))
        goto final;

    /*
        Write the signature to the stack
    */   
    if (! stWriteBigInteger(st, x))
		goto final;

    if (! stWriteBigInteger(st, R->x))
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
    
    ret = SIGNATURE_ECC_OK;

final:
    freeBigInteger(z);
    freeBigInteger(k);
    freeBigInteger(k1);
    freeBigInteger(x);
    freeBigInteger(y);
    freeEllipticCurvePoint(G);
    freeEllipticCurvePoint(R);
    return ret;
}

int signFileWithECC(char *infile, char **outfile, char *keyfile, EllipticCurves ecs, int ascii)
{
    Stack st;
	unsigned char *text;
	size_t nbytes, alloc;
	int ret;
	uint8_t mode;
    PrivateECCKey key;
    st = NULL;
    key = NULL;

    ret = SIGNATURE_ECC_ERROR;
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
        Read the private key from the file
    */
    if ((key = readPrivateECCKeyFromFile(keyfile, ecs)) == NULL)
	{
		if ((key = readEncryptedPrivateECCKeyFromFile(keyfile, ecs)) == NULL)
		{
			ret = SIGNATURE_ECC_PRIVATE_KEY_ERROR;
			goto final;
		}
	}

    /*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = SIGNATURE_ECC_FILE_NOT_FOUND;
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
	if ((ret = signStackECC(st, key, infile, mode)) != SIGNATURE_ECC_OK)
		goto final;

    /*
	   Write the signed file
	 */
	int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) < 0)
	{
		ret = SIGNATURE_ECC_OPEN_FILE_ERROR;
		goto final;
	}

	if (ascii)
	{
		size_t t;
		t = strlen((char *)becsigf);
		if (write(fd, becsigf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)eecsigf);
		if (write(fd, eecsigf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = SIGNATURE_ECC_OK;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
    close(fd);
	
	ret = SIGNATURE_ECC_OK;

final:
    freeStack(st);
	freeString(text);
	freePrivateECCKey(key);
	return ret;
}

int verifyAndExtractStackECC(Stack st, PublicECCKey key, uint8_t mode)
{
    size_t nbytes, length, nbits, usize;
    unsigned char *text, *t;
	char *filename;
	int ret, error;
    unsigned char digest512[SHA512_DIGEST_SIZE];
    unsigned char digest256[SHA256_DIGEST_SIZE];
    unsigned char seconddigest512[SHA512_DIGEST_SIZE];
    unsigned char seconddigest256[SHA256_DIGEST_SIZE];
	BigInteger r, s, s1, x, y, z;
    EllipticCurvePoint G, P, Q, R;

	ret = SIGNATURE_ECC_ERROR;
	r = s = x = y = z = NULL;
    G = P = Q = R = NULL;
	text = t = NULL;
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
    if (((r = stReadBigInteger(st, &error)) == NULL) || (error != 0))
		goto final;
    if (((s = stReadBigInteger(st, &error)) == NULL) || (error != 0))
		goto final;

    /*
		Read the filename
	*/
	if ((t = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
    if ((filename = (char *)malloc((length + 1) * sizeof(char))) == NULL)
		goto final;
	memcpy(filename, t, length);
	filename[length] = '\0';
 	free(t);

    /*
		Read the contents of the file and compute the double digest
	*/
	if ((text = stReadOctetString(st, &nbytes, &error)) == NULL)
		goto final;
	if ((nbytes == 0) || (error != 0))
		goto final;

    nbits = bitsInBigInteger(key->ec->n);
    if (nbits > 260)
    {
        textToSHA512(text,nbytes,digest512);
        textToSHA512(digest512,SHA512_DIGEST_SIZE,seconddigest512);
        if ((z = initBigIntegerFromBinaryData(nbits, seconddigest512, SHA512_DIGEST_SIZE)) == NULL)
            goto final;
    }
    else
    {
        textToSHA256(text,nbytes,digest256);
        textToSHA256(digest256,SHA256_DIGEST_SIZE,seconddigest256);
        if ((z = initBigIntegerFromBinaryData(nbits, seconddigest256, SHA256_DIGEST_SIZE)) == NULL)
            goto final;
    }

    /*
        Write the contents of the file
    */
    stSetDataInStack(st, text, nbytes, nbytes);
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
		ret = SIGNATURE_ECC_OPEN_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
	{
		ret = SIGNATURE_ECC_WRITE_FILE_ERROR;
		goto final;
	}

    /*
        Compute the point G
    */
    if ((x = cloneBigInteger(key->ec->Gx)) == NULL)
        goto final;
    if ((y = cloneBigInteger(key->ec->Gy)) == NULL)
        goto final;
    if ((G = initEllipticCurvePoint(x, y, key->ec)) == NULL)
        goto final;
    x = y = NULL;

    /*
        Verify the signature
    */
    int8_t e;
    if ((s1 = modularInverseOfBigInteger(s, key->ec->n, &e)) == NULL)
        goto final;
    if (e != 0)
        goto final;
    
    if ((x = modulusOfProductOfBigInteger(s1, z, key->ec->n)) == NULL)
        goto final;    
    if ((y = modulusOfProductOfBigInteger(s1, r, key->ec->n)) == NULL)
        goto final;

    if ((P = multiplyEllipticCurvePointByBigInteger(G, x, key->ec)) == NULL)
        goto final;
    if ((Q = multiplyEllipticCurvePointByBigInteger(key->P, y, key->ec)) == NULL)
        goto final;
    if ((R = addEllipticCurvePoints(P, Q, key->ec)) == NULL)        
        goto final;

    if (compareBigIntegerAbsoluteValues(r,R->x) == 0)
        ret = SIGNATURE_ECC_OK;
    else
        ret = SIGNATURE_ECC_BAD;

final:
    freeBigInteger(r);
    freeBigInteger(s);
    freeBigInteger(s1);
    freeBigInteger(x);
    freeBigInteger(y);
    freeBigInteger(z);
    freeEllipticCurvePoint(G);
    freeEllipticCurvePoint(P);
    freeEllipticCurvePoint(Q);
    freeEllipticCurvePoint(R);
    return ret;
}

int verifyAndExtractSignedFileWithECC(char *infile, char *keyfile, EllipticCurves ecs)
{
    Stack st;
	unsigned char *text, *begin;
	size_t nbytes, alloc, len;
	int ret;
	uint8_t mode;
    PublicECCKey pkey;
    st = NULL;
    pkey = NULL;

    ret = SIGNATURE_ECC_ERROR;

    /*
        Read the public key
    */
    if ((pkey = readPublicECCKeyFromFile(keyfile, ecs)) == NULL)
        goto final;

    /*
		Read the file and store the data Stack
	*/
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = SIGNATURE_ECC_FILE_NOT_FOUND;
		goto final;
	}

    if ((begin = clearCcommentsInText(text,becsigf,eecsigf)) != NULL)
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
	if ((ret = verifyAndExtractStackECC(st, pkey, mode)) != SIGNATURE_ECC_OK)
		goto final;

    ret = SIGNATURE_ECC_OK;

final:
    freeStack(st);
	freeString(text);
	freePublicECCKey(pkey);
    return ret;
}
