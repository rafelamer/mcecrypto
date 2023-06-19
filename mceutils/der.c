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
#include <der.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

static unsigned char rsaEncryption[] =
{ 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48,
	0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00
};

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
		if ((st->data =
				 (unsigned char *)malloc(size * sizeof(unsigned char))) ==
				NULL)
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

int stReadOptionalRsaEncryptionOI(Stack st)
{
	unsigned char b;

	b = *(st->read);
	if (b != 0x30)
		return 0;
	if (memcmp(st->read, rsaEncryption, 15) != 0)
		return 0;
	st->read += 15;
	return 1;
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

int stWriteRsaEncryptionOI(Stack st)
{
	if ((15 + st->used) > st->alloc)
		if (!stExpandStackInSize(st, 1024))
			return 0;
	memmove(st->data + 15, st->data, st->used);
	memcpy(st->data, rsaEncryption, 15);
	st->used += 15;
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

