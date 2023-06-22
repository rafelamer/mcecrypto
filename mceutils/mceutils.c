/**************************************************************************************
 * Filename:   der.c
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
#include <bigintegers.h>
#include <mceutils.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <config.h>
#include <sha512.h>
#include <sha256.h>
#include <hmac.h>
#include <aes.h>
#include <memxor.h>
#include <termios.h>

#define HMAC_SHA256_DIGEST_LENGTH 32
#define HMAC_SHA512_DIGEST_LENGTH 64
static const unsigned char baesf[] = "-----BEGIN AES ENCRYPTED FILE-----";
static const unsigned char eaesf[] = "-----END AES ENCRYPTED FILE-----";

#define WRITEERROR {                    	\
		close(fd);							\
		unlink(*outfile);					\
		ret =  ENCRYPTION_WRITE_FILE_ERROR; \
		goto final;						    \
	}


void free_string(char **s)
{
	if (*s == NULL)
		return;
	free(*s);
	*s = NULL;
}

unsigned char *encode_length(size_t value, size_t * len)
{
	unsigned char *r, *aux;
	size_t temp;
	r = NULL;

	if (value < 128)
	{
		*len = 1;
	}
	else
	{
		temp = value;
		*len = 1;
		while (temp > 0)
		{
			*len += 1;
			temp /= 256;
		}
	}
	if (*len > 126)
		goto final;

	if ((r = (unsigned char *)malloc(*len * sizeof(unsigned char))) == NULL)
		goto final;

	if (*len == 1)
	{
		*r = (unsigned char)value;
		return r;
	}
	/*
		We set the first bit to 1
		x80 = 10000000
	*/
	*r = (*len - 1) | 0x80;
	aux = r + *len - 1;
	while (aux > r)
	{
		*aux-- = value % 256;
		value /= 256;
	}
	return r;

final:
	*len = 0;
	return NULL;
}

Stack stInitStack()
{
	Stack st;

	st = NULL;
	if ((st = (Stack) malloc(sizeof(data_stack))) == NULL)
		return NULL;
	st->data = NULL;
	st->alloc = 0;
	st->used = 0;
	st->read = NULL;
	return st;
}

Stack stInitStackWithSize(size_t size)
{
	Stack st;

	st = NULL;
	if ((st = (Stack) malloc(sizeof(data_stack))) == NULL)
		goto final;
	if ((st->data = malloc(size * sizeof(unsigned char))) == NULL)
		goto final;
	st->alloc = size;
	st->used = 0;
	st->read = st->data;
	return st;

final:
	if (st != NULL)
		freeStack(st);
	return NULL;
}

int stReInitStackWithSize(Stack st, size_t size)
{
	free(st->data);
	if ((st->data = malloc(size * sizeof(unsigned char))) == NULL)
		return 0;
	st->alloc = size;
	st->used = 0;
	st->read = st->data;
	return 1;
}

void stFreeStack(Stack * st)
{
	if (*st == NULL)
		return;
	if ((*st)->data != NULL)
	{
		memset((void *)((*st)->data),0,(*st)->used);
		free((*st)->data);
	}
	free(*st);
	*st = NULL;
}

int stExpandStackInSize(Stack st, size_t size)
{
	if (st == NULL)
		return 0;
	if ((st->data == NULL) || (st->alloc == 0))
	{
		if ((st->data =(unsigned char *)malloc(size * sizeof(unsigned char))) == NULL)
			return 0;
	}
	st->alloc += size;
	if ((st->data = (unsigned char *)realloc(st->data, st->alloc * sizeof(unsigned char))) == NULL)
		return 0;
	memset(st->data + st->used, 0, st->alloc - st->used);
	return 1;
}

void stSetDataInStack(Stack st, unsigned char *data, size_t nbytes, size_t alloc)
{
	freeString(st->data);
	st->data = data;
	st->read = st->data;
	st->used = nbytes;
	st->alloc = alloc;
}

size_t stBytesRemaining(Stack st)
{
	return (st->used - (st->read - st->data));
}

size_t stReadLength(Stack st, int *error)
{
	unsigned char b;
	size_t i, n;
	*error = 0;
	b = *(st->read)++;
	if (b & 0x80)
	{
		n = 0;
		/*
			We set the first bit to 0
			0x7F = 01111111
		*/
		b &= 0x7F;
		for (i = 0; i < b; i++)
			n = 256 * n + (size_t) (*(st->read)++);
		if (n == 0)
			*error = 1;
		return n;
	}
	if ((b & 0x7F) == 0)
		*error = 1;
	return (size_t) (b & 0x7F);
}

unsigned long long stReadInteger(Stack st, int *error)
{
	unsigned char b;
	size_t length, i;
	unsigned long long int value;

	*error = 1;
	b = *(st->read);
	if (b != 0x02)
		return 0;
	(st->read)++;

	length = stReadLength(st, error);
	if (length == 0)
		return 0;

	value = 0;
	for (i = 0; i < length; i++)
		value = 256 * value + (size_t) (*(st->read)++);
	*error = 0;
	return value;
}

unsigned char *stReadOctetString(Stack st, size_t * length, int *error)
{
	unsigned char *str;
	unsigned char b;

	str = NULL;
	*error = 1;
	b = *(st->read);
	if (b != 0x04)
		return NULL;
	(st->read)++;

	*length = stReadLength(st, error);
	if (*length == 0)
		return 0;

	if ((str = (unsigned char *)malloc(*length * sizeof(unsigned char))) == NULL)
	{
		*error = 1;
		return NULL;
	}
	memcpy(str, st->read, *length);
	(st->read) += *length;
	*error = 0;
	return str;
}

unsigned char *stReadBitString(Stack st, size_t * length, int *error)
{
	unsigned char b, *str;

	str = NULL;
	*error = 1;
	b = *(st->read);
	if (b != 0x03)
		return NULL;
	(st->read)++;

	*length = stReadLength(st, error);
	if (length == 0)
		return 0;

	if ((str = (unsigned char *)malloc(*length * sizeof(unsigned char))) == NULL)
	{
		*error = 1;
		return NULL;
	}
	memcpy(str, st->read, *length);
	(st->read) += *length;
	*error = 0;
	return str;
}

size_t stReadStartSequenceAndLength(Stack st, int *error)
{
	unsigned char b;
	size_t length;

	*error = 1;
	b = *(st->read);
	if (b != 0x30)
		return 0;
	(st->read)++;

	length = stReadLength(st, error);
	if (length == 0)
		return 0;

	*error = 0;
	return length;
}

size_t stReadStartOctetStringAndLength(Stack st, int *error)
{
	unsigned char b;
	size_t length;

	*error = 1;
	b = *(st->read);
	if (b != 0x04)
		return 0;
	(st->read)++;

	length = stReadLength(st, error);
	if (length == 0)
		return 0;

	*error = 0;
	return length;
}

size_t stReadStartBitStringAndLength(Stack st, int *error)
{
	unsigned char b;
	size_t length;

	*error = 1;
	b = *(st->read);
	if (b != 0x03)
		return 0;
	(st->read)++;

	length = stReadLength(st, error);
	if (length == 0)
		return 0;

	*error = 0;
	return length;
}

BigInteger stReadBigInteger(Stack st, int *error)
{
	unsigned char b, *p, *q;
	size_t length, size;
	BigInteger n;

	*error = 1;
	b = *(st->read);
	if (b != 0x02)
		return NULL;
	(st->read)++;

	length = stReadLength(st, error);
	if (length == 0)
		return NULL;

	size = (length + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((n = initBigInteger(size)) == NULL)
		return NULL;

	p = (unsigned char *)(n->digits);
	q = st->read + length - 1;
	while (q >= st->read)
		*p++ = *q--;

	n->used = size;
	st->read += length;
	return n;
}

int stWriteNull(Stack st)
{
	if (st->read != st->data)
		return -1;
	if ((2 + st->used) > st->alloc)
		if (!stExpandStackInSize(st, 1024))
			return 0;
	if (st->used > 0)
		memmove(st->data + 2, st->data, st->used);
	st->data[0] = 0x05;
	st->data[1] = 0x00;
	st->used += 2;
	return 1;
}

int stWriteLength(Stack st, size_t length)
{
	size_t len;
	unsigned char *b;

	if (st->read != st->data)
		return -1;
	if ((b = encode_length(length, &len)) == NULL)
		return 0;
	if ((len + st->used) > st->alloc)
		if (!stExpandStackInSize(st, len + 1024))
		{
			free(b);
			b = NULL;
			return 0;
		}
	if (st->used > 0)
		memmove(st->data + len, st->data, st->used);
	memcpy(st->data, b, len);
	free(b);
	b = NULL;
	st->used += len;
	return 1;
}

int stWriteInteger(Stack st, unsigned long long integer)
{
	size_t m, lent;
	unsigned long long r;
	unsigned char data[BYTES_PER_DIGIT + 1];
	/*
		Number of significative bytes in integer and how many bytes
		we need to alloc
	*/
	r = integer;
	memset(data, 0, BYTES_PER_DIGIT + 1);
	m = BYTES_PER_DIGIT;
	while (r > 0)
	{
		data[m--] = r % 256;
		r /= 256;
	}
	if ((m != BYTES_PER_DIGIT) && ((data[m + 1] & 0x80) == 0))
		m++;

	lent = BYTES_PER_DIGIT - m + 1;
	/*
		Encode the length alloc
	*/
	size_t lenel;
	unsigned char *el;
	if ((el = encode_length(lent, &lenel)) == NULL)
		return 0;

	/*
		Encode the integer
	*/
	lent += 1 + lenel;
	if ((lent + st->used) > st->alloc)
		if (!stExpandStackInSize(st, lent + 1024))
		{
			free(el);
			el = NULL;
			return 0;
		}
	if (st->used > 0)
		memmove(st->data + lent, st->data, st->used);
	memcpy(st->data + lenel + 1, data + m, BYTES_PER_DIGIT - m + 1);
	memcpy(st->data + 1, el, lenel);
	st->data[0] = 0x02;
	st->used += lent;
	free(el);
	el = NULL;
	return 1;
}

int stWriteOctetString(Stack st, unsigned char *bytes, size_t nbytes)
{
	unsigned char *el;
	size_t lenel, lent;
	if ((el = encode_length(nbytes, &lenel)) == NULL)
	{
		free(el);
		el = NULL;
		return 0;
	}
	lent = 1 + lenel + nbytes;
	if ((lent + st->used) > st->alloc)
		if (!stExpandStackInSize(st, lent + 1024))
		{
			free(el);
			el = NULL;
			return 0;
		}
	if (st->used > 0)
		memmove(st->data + lent, st->data, st->used);
	memcpy(st->data + lenel + 1, bytes, nbytes);
	memcpy(st->data + 1, el, lenel);
	st->data[0] = 0x04;
	st->used += lent;
	free(el);
	el = NULL;
	return 1;
}

int stWriteBitString(Stack st, unsigned char *bytes, size_t nbytes)
{
	unsigned char *el;
	size_t lenel, lent;
	if ((el = encode_length(nbytes, &lenel)) == NULL)
	{
		free(el);
		el = NULL;
		return 0;
	}
	lent = 1 + lenel + nbytes;
	if ((lent + st->used) > st->alloc)
		if (!stExpandStackInSize(st, lent + 1024))
		{
			free(el);
			el = NULL;
			return 0;
		}
	if (st->used > 0)
		memmove(st->data + lent, st->data, st->used);
	memcpy(st->data + lenel + 1, bytes, nbytes);
	memcpy(st->data + 1, el, lenel);
	st->data[0] = 0x03;
	st->used += lent;
	free(el);
	el = NULL;
	return 1;
}

int stWriteStartSequence(Stack st)
{
	unsigned char *el;
	size_t lenel;

	if (st->used == 0)
		return 0;
	if ((el = encode_length(st->used, &lenel)) == NULL)
		return 0;

	if ((1 + lenel + st->used) > st->alloc)
		if (!stExpandStackInSize(st, lenel + 1024))
		{
			free(el);
			el = NULL;
			return 0;
		}
	memmove(st->data + lenel + 1, st->data, st->used);
	memcpy(st->data + 1, el, lenel);
	st->data[0] = 0x30;
	st->used += lenel + 1;
	free(el);
	el = NULL;
	return 1;
}

int stWriteStartOctetString(Stack st)
{
	unsigned char *el;
	size_t lenel;

	if (st->used == 0)
		return 0;
	if ((el = encode_length(st->used, &lenel)) == NULL)
		return 0;

	if ((1 + lenel + st->used) > st->alloc)
		if (!stExpandStackInSize(st, lenel + 1024))
		{
			free(el);
			el = NULL;
			return 0;
		}
	memmove(st->data + lenel + 1, st->data, st->used);
	memcpy(st->data + 1, el, lenel);
	st->data[0] = 0x04;
	st->used += lenel + 1;
	free(el);
	el = NULL;
	return 1;
}

int stWriteStartBitString(Stack st)
{
	unsigned char *el;
	size_t lenel;

	if (st->used == 0)
		return 0;
	if ((el = encode_length(st->used, &lenel)) == NULL)
		return 0;

	if ((1 + lenel + st->used) > st->alloc)
		if (!stExpandStackInSize(st, lenel + 1024))
		{
			free(el);
			el = NULL;
			return 0;
		}
	memmove(st->data + lenel + 1, st->data, st->used);
	memcpy(st->data + 1, el, lenel);
	st->data[0] = 0x03;
	st->used += lenel + 1;
	free(el);
	el = NULL;
	return 1;
}

int stWriteBigInteger(Stack st, BigInteger n)
{
	size_t lenel, bytes, tbytes;
	unsigned char *el, *p, *q, *last;
	int ret;

	ret = 0;
	el = NULL;
	bytes = bytesInBigInteger(n);
	tbytes = bytes;

	if (tbytes == 0)
		tbytes = 1;

	/*
		The eigth bit of the last byte can't be one
		The last byte i n->digits is stored as the first byte
		in the encoding
	*/

	if (byteOfBigIntegerAtPosition(n, bytes - 1) & 0x80)
		tbytes += 1;

	if ((el = encode_length(tbytes, &lenel)) == NULL)
		goto final;

	if ((1 + lenel + tbytes + st->used) > st->alloc)
		if (!stExpandStackInSize(st, 1 + lenel + tbytes + 1024))
			goto final;

	if (st->used > 0)
		memmove(st->data + 1 + lenel + tbytes, st->data, st->used);
	st->data[0] = 2;
	memcpy(st->data + 1, el, lenel);

	/*
		p points to the begin of bytes in n
		last points to the most significative byte of n
		q points to the moved data minus one
	*/
	p = (unsigned char *)(n->digits);
	last = p + bytes - 1;
	q = st->data + lenel + tbytes;
	while (p <= last)
		*q-- = *p++;
	if (tbytes > bytes)
		*q = 0x00;
	st->used += 1 + lenel + tbytes;
	ret = 1;

final:
	if (el != NULL)
		free(el);
	return ret;
}

unsigned char *readFileBinaryMode(const char *filename, size_t * len, size_t * alloc)
/*
  Reads the contents of the file and returns it in a vector of unsiged chars. The size
  of the file, i.e., the numbers of bytes read is stored in *len.
*/
{
	int fd;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return NULL;

	unsigned char *str;
	unsigned char buffer[4096];
	int n;

	str = NULL;
	*alloc = 4096;
	*len = 0;
	if ((str = (unsigned char *)calloc(*alloc,sizeof(unsigned char))) == NULL)
		return NULL;

	while ((n = read(fd, buffer, 4096)) > 0)
	{
		if ((*alloc - *len) < n)
		{
			*alloc += (*alloc * 4) / 3;
			if ((str = (unsigned char *)realloc(str,*alloc * sizeof(unsigned char))) == NULL)
				return NULL;
		}
		memcpy(str + *len, buffer, n);
		*len += n;
	}
	close(fd);
	if (n < 0)
	{
		free(str);
		str = NULL;
		*len = 0;
		*alloc = 0;
		return NULL;
	}
	return str;
}

int writeFileBinaryMode(const char *filename, unsigned char *data, size_t length)
{
	int fd;

	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
		return 0;

	if (write(fd, data, length) != length)
	{
		close(fd);
		unlink(filename);
		return 0;
	}
	close(fd);
	return 1;
}

/*
	Compress and uncompress with zlib
*/

#define ZLIBCHUNK 16384

#define CALL_ZLIB_DEFLATE(x)  unsigned char out[ZLIBCHUNK];							          \
	st.avail_in = (x) * sizeof(unsigned char);												  \
	st.next_in = (Bytef *)p;																  \
	insize -= (x);																			  \
	flush = (insize == 0) ? Z_FINISH : Z_NO_FLUSH;											  \
	do																						  \
	{																						  \
		size_t have;																		  \
		st.avail_out = ZLIBCHUNK;															  \
		st.next_out = (Bytef *)out;															  \
		ret = deflate(&st,flush);															  \
		if ((ret != Z_OK) && (ret != Z_STREAM_END))											  \
		{																					  \
			deflateEnd(&st);																  \
			free(str);																		  \
			*alloc = 0;																		  \
			*outsize = 0;																	  \
			return NULL;									  								  \
		}																					  \
		have = ZLIBCHUNK - st.avail_out;													  \
		if ((*alloc - *outsize) < have)														  \
		{																					  \
			*alloc += ZLIBCHUNK;															  \
			if ((str = (unsigned char *)realloc(str,*alloc * sizeof(unsigned char))) == NULL) \
				return NULL;												  				  \
		}										 											  \
		memcpy(str + *outsize,out,have);													  \
		*outsize += have;																	  \
	} while (st.avail_out == 0);															  \
	p += (x);

#define CALL_ZLIB_INFLATE(x)  unsigned char out[ZLIBCHUNK];							          \
	st.avail_in = (x) * sizeof(unsigned char);												  \
	st.next_in = (Bytef *)p;																  \
	insize -= (x);																			  \
	do																						  \
	{																						  \
		size_t have;																		  \
		st.avail_out = ZLIBCHUNK;															  \
		st.next_out = (Bytef *)out;															  \
		ret = inflate(&st,Z_NO_FLUSH);														  \
		if ((ret != Z_OK)  && (ret != Z_STREAM_END))										  \
		{																				      \
			inflateEnd(&st);																  \
			free(str);																		  \
			*alloc = 0;																		  \
			*outsize = 0;																	  \
			return NULL;																	  \
		}																					  \
		have = ZLIBCHUNK - st.avail_out;													  \
		if ((*alloc - *outsize) < have)														  \
		{																					  \
			*alloc += ZLIBCHUNK;															  \
			if ((str = (unsigned char *)realloc(str,*alloc * sizeof(unsigned char))) == NULL) \
				return NULL;															      \
		}																					  \
		memcpy(str + *outsize,out,have);													  \
		*outsize += have;																	  \
	} while (st.avail_out == 0);															  \
	p += (x);

/*
  Compress and uncompress with zlib
*/
unsigned char *zlib_compress_data(unsigned char *data, size_t insize, size_t * outsize, size_t * alloc)
{
	z_stream st;
	unsigned char *str, *p;
	int flush, ret;

	*outsize = 0;
	*alloc = 0;
	if (insize == 0)
		return NULL;

	st.zalloc = Z_NULL;
	st.zfree = Z_NULL;
	st.opaque = Z_NULL;
	if (deflateInit(&st, Z_BEST_COMPRESSION) != Z_OK)
		return NULL;

	*alloc = 2 * ZLIBCHUNK;
	if ((str =
	     (unsigned char *)calloc(*alloc, sizeof(unsigned char))) == NULL)
		return NULL;

	p = data;
	while (insize > ZLIBCHUNK)
	{
		CALL_ZLIB_DEFLATE(ZLIBCHUNK);
	}
	if (insize > 0)
	{
		CALL_ZLIB_DEFLATE(insize);
	}
	deflateEnd(&st);
	return str;
}

unsigned char *zlib_uncompress_data(unsigned char *data, size_t insize, size_t * outsize, size_t * alloc)
{
	z_stream st;
	unsigned char *str, *p;
	int ret;

	*outsize = 0;
	*alloc = 0;
	if (insize == 0)
		return NULL;

	st.zalloc = Z_NULL;
	st.zfree = Z_NULL;
	st.opaque = Z_NULL;
	if (inflateInit(&st) != Z_OK)
		return NULL;

	*alloc = ZLIBCHUNK;
	if ((str =
	     (unsigned char *)calloc(*alloc, sizeof(unsigned char))) == NULL)
		return NULL;

	p = data;
	while (insize > ZLIBCHUNK)
	{
		CALL_ZLIB_INFLATE(ZLIBCHUNK);
	}
	if (insize > 0)
	{
		CALL_ZLIB_INFLATE(insize);
	}
	inflateEnd(&st);
	return str;
}

/*
  Text to SHA256 or SHA512
 */
void textToSHA256(unsigned char *text, size_t len, unsigned char *sha)
{
	struct sha256_ctx ctx;

	sha256_init_ctx(&ctx);
	sha256_process_bytes((unsigned char *)text, len, &ctx);
	sha256_finish_ctx(&ctx, sha);
}

void textToSHA512(unsigned char *text, size_t len, unsigned char *sha)
{
	struct sha512_ctx ctx;

	sha512_init_ctx(&ctx);
	sha512_process_bytes((unsigned char *)text, len, &ctx);
	sha512_finish_ctx(&ctx, sha);
}

void printBytesInHexadecimal(unsigned char *text, size_t len)
{
	size_t i;
	const char *hex = "0123456789abcdef";
	unsigned char *pin = text;
	for (i=0;i < len;i++)
	{
		printf("%c",hex[(*pin >> 4)&0xF]);
        printf("%c",hex[(*pin++)&0xF]);
	}
	printf("\n");
}

/*
  Text to HMAC256 or HMAC512
 */
int textToHMAC256(unsigned char *text, size_t tlen, unsigned char *key, size_t klen, unsigned char *hmac)
{
	if (hmac_sha256(key, klen, text, tlen, hmac) != 0)
		return 0;
	return 1;
}

int textToHMAC512(unsigned char *text, size_t tlen, unsigned char *key, size_t klen, unsigned char *hmac)
{
	if (hmac_sha512(key, klen, text, tlen, hmac) != 0)
		return 0;
	return 1;
}

/*
  Password-Based Key Derivation Function
 */
int pbkdf2_hmac_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, uint8_t *derived_key, size_t key_len) 
{
    if (password == NULL || salt == NULL || derived_key == NULL)
        return 0;

    if (password_len == 0 || salt_len == 0 || key_len == 0)
        return 0;

    uint8_t work[HMAC_SHA256_DIGEST_LENGTH];
	uint8_t md1[HMAC_SHA256_DIGEST_LENGTH];
    uint8_t block[4];
	uint8_t *fsalt, *pos;
	size_t use_len;
	int ret = 0;
	pos = derived_key;
	fsalt = NULL;
	memset(block, 0, 4);
    block[3] = 1;

	if ((fsalt = (uint8_t *)malloc(salt_len + 4)) == NULL)
		goto final;
	memcpy(fsalt, salt, salt_len);

	while (key_len > 0)
	{
		memcpy(fsalt + salt_len, block, 4);
		if (hmac_sha256(password, password_len, fsalt, salt_len + 4, work) != 0)
			goto final;
		memcpy(md1, work, HMAC_SHA256_DIGEST_LENGTH);

		for (size_t i = 1; i < iterations; i++) 
		{
			if (hmac_sha256(password, password_len, md1, HMAC_SHA256_DIGEST_LENGTH, md1) != 0)
				goto final;
			memxor(work,md1,HMAC_SHA256_DIGEST_LENGTH);
		}
		use_len = (key_len < HMAC_SHA256_DIGEST_LENGTH) ? key_len : HMAC_SHA256_DIGEST_LENGTH;
        memcpy(pos, work, use_len);
		key_len -= use_len;
        pos += use_len;
		for (size_t i = 4; i > 0; i--) 
            if (++block[i - 1] != 0)
                break;
	}
	ret = 1;

final:
	freeString(fsalt);
	return ret;
}

int pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len,
                       uint32_t iterations, uint8_t *derived_key, size_t key_len) 
{
    if (password == NULL || salt == NULL || derived_key == NULL)
        return 0;

    if (password_len == 0 || salt_len == 0 || key_len == 0)
        return 0;

    uint8_t work[HMAC_SHA512_DIGEST_LENGTH];
	uint8_t md1[HMAC_SHA512_DIGEST_LENGTH];
    uint8_t block[4];
	uint8_t *fsalt, *pos;
	size_t use_len;
	int ret = 0;
	pos = derived_key;
	fsalt = NULL;
	memset(block, 0, 4);
    block[3] = 1;

	if ((fsalt = (uint8_t *)malloc(salt_len + 4)) == NULL)
		goto final;
	memcpy(fsalt, salt, salt_len);

	while (key_len > 0)
	{
		memcpy(fsalt + salt_len, block, 4);
		if (hmac_sha512(password, password_len, fsalt, salt_len + 4, work) != 0)
			goto final;
		memcpy(md1, work, HMAC_SHA512_DIGEST_LENGTH);

		for (size_t i = 1; i < iterations; i++) 
		{
			if (hmac_sha512(password, password_len, md1, HMAC_SHA512_DIGEST_LENGTH, md1) != 0)
				goto final;
			memxor(work,md1,HMAC_SHA512_DIGEST_LENGTH);
		}
		use_len = (key_len < HMAC_SHA512_DIGEST_LENGTH) ? key_len : HMAC_SHA512_DIGEST_LENGTH;
        memcpy(pos, work, use_len);
		key_len -= use_len;
        pos += use_len;
		for (size_t i = 4; i > 0; i--) 
            if (++block[i - 1] != 0)
                break;
	}
	ret = 1;

final:
	freeString(fsalt);
	return ret;
}

/*
  Encryption and decryption of Stack with AES
*/
char *getPassword(const char *text)
{
	char *password;
	char c;
	static struct termios oldt, newt;
	size_t alloc_size, str_size;

	printf("%s", text);
	alloc_size = PASSALLOCSIZE;
	str_size = 0;
	if ((password = (char *)calloc(alloc_size,sizeof(char))) == NULL)
		return NULL;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);

	while (((c = getchar()) != '\n') && (c != EOF))
	{
		if (str_size == alloc_size)
		{
			alloc_size += PASSALLOCSIZE;
		 	if ((password = (char *)realloc(password,alloc_size * sizeof(char))) == NULL)
				return NULL;
		}
		password[str_size++] = c;
	}
	if (str_size == alloc_size)
	{
		alloc_size += PASSALLOCSIZE;
		if ((password = (char *)realloc(password,alloc_size * sizeof(char))) == NULL)
			return NULL;
	}
	password[str_size] = '\0';
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	printf("\n");
	return password;
}

char *getAndVerifyPassphrase(unsigned int msize)
{
	char *p1, *p2;
	p1 = p2 = NULL;

	p1 = getPassword("Enter the encryption passphrase: ");
	p2 = getPassword("Verifying. Enter the encryption passphrase again: ");

	if ((strlen(p1) != strlen(p2)) || (memcmp(p1, p2, strlen(p1)) != 0))
		goto errorVerify;
	if (strlen(p1) < msize)
		goto errorTooShort;

	freeString(p2);
	return p1;

errorVerify:
	freeString(p1);
	freeString(p2);
	fprintf(stderr, "The two passphrases does not coincide. Try again\n");
	return NULL;

errorTooShort:
	freeString(p1);
	freeString(p2);
	fprintf(stderr,"Passphrase too short. It must have at least %u characters\n",msize);
	return NULL;
}

uint8_t getRandomSalt(unsigned char *salt)
{
	FILE *fp;
	unsigned char bs[16];
	size_t i;
	static const unsigned char map[17] = "0123456789ABCDEF";

	if ((fp = fopen("/dev/urandom", "r")) == NULL)
		return 0;
	if (fread(bs, sizeof(unsigned char), 16, fp) != 16)
	{
		fclose(fp);
		return 0;
	}
	fclose(fp);
	for (i = 0; i < 16; i++)
	{
		salt[2 * i] = map[(bs[i] >> 4) & 0x0f];
		salt[2 * i + 1] = map[(bs[i]) & 0x0f];
	}
	salt[32] = '\0';
	return 1;
}

int encryptStackAES(Stack st, uint8_t mode)
{
	char *passphrase;
	size_t nblocks, nbytes, alloc;
	unsigned char *text;
	size_t lbc;
	uint8_t keys[64];
	unsigned int key_schedule[60];
	unsigned char salt[48];
	int ret;

	passphrase = NULL;
	text = NULL;
	ret = ENCRYPTION_AES_ERROR;
	if ((st == NULL) || (st->data == NULL) || (st->used == 0))
		goto final;

	/*
		Get the passphrase and random salt
	*/
	if ((passphrase = getAndVerifyPassphrase(10)) == NULL)
	{
		ret = ENCRYPTION_AES_WRONG_PASSWORD;
		goto final;
	}
	if (! getRandomSalt(salt))
		goto final;

	/*
		Derive the key and the iv from the password
	*/
	if (! pbkdf2_hmac_sha512(passphrase, strlen(passphrase), salt, strlen((char *)salt), 128000, keys, 64))
		goto final;

	/*
		Compress
	*/
	if (mode & STACKCOMPRESS)
	{
		if ((text = zlib_compress_data(st->data, st->used, &nbytes, &alloc)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, alloc);
	}

	/*
		Encryption process
		lbc is the length of the data before encrypt
	*/
	lbc = st->used;
	memset(st->data + st->used, 0, st->alloc - st->used);
	nblocks = (st->used + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
	if (st->alloc < nblocks * AES_BLOCK_SIZE)
	{
		size_t add = nblocks * AES_BLOCK_SIZE - st->alloc + 128;
		if (!stExpandStackInSize(st, add))
			goto final;
	}

	/*
		Encrypt
	*/
	aes_key_setup(keys, key_schedule, 256);
	if ((text = (unsigned char *)malloc(nblocks * AES_BLOCK_SIZE * sizeof(unsigned char))) == NULL)
		goto final;
	if (!aes_encrypt_cbc(st->data, nblocks * AES_BLOCK_SIZE, text, key_schedule, 256, keys + 32))
		goto final;
	memset(keys, 0, 64);

	if (! stReInitStackWithSize(st, nblocks * AES_BLOCK_SIZE + 1024))
		goto final;
	if (! stWriteOctetString(st, text, nblocks * AES_BLOCK_SIZE))
		goto final;
	if (! stWriteOctetString(st, salt, strlen((char *)salt)))
		goto final;
	if (!stWriteStartSequence(st))
		goto final;
	freeString(text);

	/*
		Encode to Base64
	*/
	if (mode & STACKENCODE)
	{
		if ((text = b64_encode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, nbytes);
		text = NULL;
	}
	ret = ENCRYPTION_AES_OK;

final:
	freeString(passphrase);
	return ret;
}

int decryptStackAES(Stack st, uint8_t mode)
{
	char *passphrase;
	size_t nbytes, nblocks, length;
	unsigned char *text, *s;
	unsigned int key_schedule[60];
	int ret, error;
	uint8_t keys[64];
	size_t lbc;
	unsigned char salt[48];
	passphrase = NULL;
	text = s = NULL;
	ret = ENCRYPTION_AES_ERROR;
	
	if ((st->data == NULL) || (st->used == 0))
		goto final;

	/*
		Get the passphrase
	*/
	if ((passphrase = getAndVerifyPassphrase(10)) == NULL)
	{
		ret = ENCRYPTION_AES_WRONG_PASSWORD;
		goto final;
	}

	/*
		Decode from Base64
	*/
	if (mode & STACKENCODE)
	{
		if ((text = b64_decode(st->data, st->used, &nbytes)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, nbytes);
		text = NULL;
	}

	/*
		Start reading the Stack
	*/
	length = stReadStartSequenceAndLength(st, &error);
	if ((length == 0) || (error != 0))
		goto final;
	if (length != stBytesRemaining(st))
		goto final;

	if ((s = stReadOctetString(st, &length, &error)) == NULL)
		goto final;	
	if ((length != 32) || (error != 0))
		goto final;
	memcpy(salt, s, 32);
	salt[32] = '\0';
	freeString(s);

	/*
		Derive the key and the iv from the password
	*/
	if (! pbkdf2_hmac_sha512(passphrase, strlen(passphrase), salt, strlen((char *)salt), 128000, keys, 64))
		goto final;
	
	/*
		Decrypt
	*/
	if (((lbc = stReadInteger(st, &error)) == 0) || (error != 0))
		goto final;

	if ((text = stReadOctetString(st, &length, &error)) == NULL)
		goto final;
	if ((length == 0) || (error != 0))
		goto final;
	stSetDataInStack(st, text, length, length);
	nblocks = st->used / AES_BLOCK_SIZE;
	if ((text = (unsigned char *)malloc(nblocks * AES_BLOCK_SIZE * sizeof(unsigned char))) == NULL)
		goto final;
	aes_key_setup(keys, key_schedule, 256);
	aes_decrypt_cbc(st->data, nblocks * AES_BLOCK_SIZE, text, key_schedule, 256, keys + 32);
	stSetDataInStack(st, text, lbc, nblocks * AES_BLOCK_SIZE);

	/*
		Uncompress
	*/
	if (mode & STACKCOMPRESS)
	{
		if ((text = zlib_uncompress_data(st->data, st->used, &nbytes, &length)) == NULL)
			goto final;
		stSetDataInStack(st, text, nbytes, length);
	}

	ret = ENCRYPTION_AES_OK;

final:
	freeString(passphrase);
	freeString(s);
	return ret;
}

int encryptFileWithAES(char *infile, char **outfile, int ascii)
{
	Stack st;
	unsigned char *text;
	unsigned char salt[48];
	size_t nbytes, alloc;
	int ret;
	uint8_t mode;

	st = NULL;
	ret = ENCRYPTION_AES_ERROR;
	if (infile == NULL)
	{
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	if (*outfile == NULL)
	{
		if((*outfile = (char *)calloc(strlen(infile) + 8,sizeof(char))) == NULL)
			goto final;
		if (ascii)
			sprintf(*outfile, "%s.asc", infile);
		else
			sprintf(*outfile, "%s.aes", infile);
	}

	/*
	   Initialize the Stack
	 */
	if ((st = stInitStack()) == NULL)
		goto final;
	
	/*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	stSetDataInStack(st, text, nbytes, alloc);
	text = NULL;
	
	/*
	   Encrypt the Stack
	 */
	mode = STACKCOMPRESS;
	if (ascii)
		mode += STACKENCODE;

	ret = encryptStackAES(st, mode);
	if (ret != ENCRYPTION_AES_OK)
		goto final;

	/*
	   Write the encrypted file
	 */
	int fd;
	if ((fd = open(*outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_WRITE_FILE_ERROR;
		goto final;
	}
	if (ascii)
	{
		size_t t;
		t = strlen((char *)baesf);
		if (write(fd, baesf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)eaesf);
		if (write(fd, eaesf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = ENCRYPTION_AES_OK;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;

	ret = ENCRYPTION_AES_OK;

final:
	freeStack(st);
	freeString(text);
	return ret;
}

int decryptFileWithAES(char *infile, char *outfile)
{
	Stack st;
	unsigned char *text, *begin;
	unsigned char salt[48];
	size_t nbytes, alloc, len;
	int ret;
	uint8_t mode;

	st = NULL;
	ret = ENCRYPTION_AES_ERROR;

	/*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode(infile, &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_FILE_NOT_FOUND;
		goto final;
	}
	/*
		Clear comments	
	*/
	if ((begin = clearCcommentsInText(text,baesf,eaesf)) != NULL)
	{
		len = strlen((char *)begin);
		if ((st = stInitStackWithSize(len + 512)) == NULL)
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

	/*
		Decrypt
	*/
	mode += STACKCOMPRESS;
	if ((ret = decryptStackAES(st, mode)) != ENCRYPTION_AES_OK)
		goto final;

	/*
		Write the outpuf file
	*/
	int fd;
	if ((fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_WRITE_FILE_ERROR;
		goto final;
	}
	if (write(fd, st->data, st->used) != st->used)
	{
		close(fd);
		unlink(outfile);
		goto final;
	}

	close(fd);
	ret = ENCRYPTION_AES_OK;

 final:
	freeStack(st);
	freeString(text);
	return ret;
}

/*
	Clear comments
*/
unsigned char *clearCcommentsInText(unsigned char *string,const unsigned char *begin,const unsigned char *end)
{
	unsigned char *p, *q;

	p = q = NULL;
	if ((p = (unsigned char *)strstr((char *)string,(char *)begin)) != NULL) {
		p += strlen((char *)begin);
		while (*p == '\n')
			p++;
		if ((q = (unsigned char *)strstr((char *)p,(char *)end)) == NULL)
			return NULL;
		*q = '\0';
		return p;
	}
	return NULL;
}

