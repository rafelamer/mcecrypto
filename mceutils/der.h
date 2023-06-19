/**************************************************************************************
* Filename:   der.h
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
#ifndef H_DER_H_
#define H_DER_H_ 1

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <limits.h>
#include <bigintegers.h>

#define freeStack(s)   stFreeStack(&(s))

typedef struct {
	size_t used;
	size_t alloc;
	unsigned char *data;
	unsigned char *read;
} data_stack;
typedef data_stack *Stack;

/*
  Operations with strings and files
 */
unsigned char *readFileBinaryMode(const char *filename, size_t * len,size_t * alloc);
int writeFileBinaryMode(const char *filename, unsigned char *data,size_t length);

/*
  Stack for DER
 */
unsigned char *encode_length(size_t value, size_t * len);
Stack stInitStack();
Stack stInitStackWithSize(size_t size);
void stFreeStack(Stack * st);
int stReInitStackWithSize(Stack st, size_t size);
int stExpandStackInSize(Stack st, size_t size);
void stSetDataInStack(Stack st, unsigned char *data, size_t nbytes, size_t alloc);
size_t stReadLength(Stack st, int *error);
size_t stBytesRemaining(Stack st);
DIGIT stReadInteger(Stack st, int *error);
unsigned char *stReadOctetString(Stack st, size_t * length, int *error);
unsigned char *stReadBitString(Stack st, size_t * length, int *error);
size_t stReadStartSequenceAndLength(Stack st, int *error);
size_t stReadStartOctetStringAndLength(Stack st, int *error);
size_t stReadStartBitStringAndLength(Stack st, int *error);
int stReadOptionalRsaEncryptionOI(Stack st);
BigInteger stReadBigInteger(Stack st, int *error);
int stWriteNull(Stack st);
int stWriteLength(Stack st, size_t length);
int stWriteDigit(Stack st, DIGIT digit);
int stWriteOctetString(Stack st, unsigned char *bytes, size_t nbytes);
int stWriteBitString(Stack st, unsigned char *bytes, size_t nbytes);
int stWriteStartSequence(Stack st);
int stWriteStartOctetString(Stack st);
int stWriteStartBitString(Stack st);
int stWriteRsaEncryptionOI(Stack st);
int stWriteBigInteger(Stack st, BigInteger n);

/*
  Base 64 encoding and decoding
 */
unsigned char *b64_encode(const unsigned char *src, size_t len, size_t * out_len);
unsigned char *b64_decode(const unsigned char *src, size_t len, size_t * out_len);

/*
  Operations with files
 */
unsigned char *readFileBinaryMode(const char *filename, size_t * len,size_t * alloc);
int writeFileBinaryMode(const char *filename, unsigned char *data,size_t length);

/*
  Compress and uncompress with zlib
*/
unsigned char *zlib_compress_data(unsigned char *data, size_t insize, size_t * outsize, size_t * alloc);
unsigned char *zlib_uncompress_data(unsigned char *data, size_t insize, size_t * outsize, size_t * alloc);



#endif				/* H_DER_H_ */
