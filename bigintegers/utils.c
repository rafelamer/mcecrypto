/**************************************************************************************
* Filename:   utils.c
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
#include <string.h>

static const char *spDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

void free_string(char **s)
{
	if (*s == NULL)
		return;
	free(*s);
	*s = NULL;
}

int digitIsPowerOfTwo(DIGIT m, size_t * power)
/*
  Returns 1 if m is a power of 2
	0 otherwise
  If m = 2^p, then we set *power = p
*/
{
	if ((m == 0) || ((m & (m - 1)) != 0))
		return 0;

	size_t i;
	for (i = 0; i < BITS_PER_DIGIT; i++)
	{
		if (m == (((DIGIT) 1) << i))
		{
			*power = i;
			return 1;
		}
	}
	return 0;
}

BigInteger initBigInteger(size_t alloc)
{
	BigInteger n;
	if ((n = (BigInteger) malloc(sizeof(big_integer))) == NULL)
		return NULL;
	if ((n->digits = (DIGIT *)calloc(alloc,sizeof(DIGIT))) == NULL) {
		free(n);
		return NULL;
	}
	n->used = 0;
	n->alloc = alloc;
	n->sign = 0;
	return n;
}

BigInteger initWithLongInt(DIGIT m,int8_t s)
{
	BigInteger n;
	if ((n = initBigInteger(8)) == NULL)
		return NULL;
	n->used = 1;
	n->digits[0] = m;
	n->sign = s;
	return n;
}

BigInteger cloneBigInteger(BigInteger n)
{
	BigInteger m;
	if ((m = initBigInteger(n->used)) == NULL)
		return NULL;
	m->used = n->used;
	m->alloc = n->used;
	m->sign = n->sign;
	memcpy(m->digits,n->digits,n->used * sizeof(DIGIT));
	return m;
}

BigInteger clonePartOfBigInteger(BigInteger n,size_t pos,size_t len)
{
	BigInteger m;
	if (pos > n->used)
		return NULL;
	if (len > pos + 1)
		len = pos + 1;		
	if ((m = initBigInteger(len + 8)) == NULL)
		return NULL;
	memcpy(m->digits,n->digits + pos + 1 - len,len * sizeof(DIGIT));
	m->used = len;
	return m;
}

int copyBigIntegerTo(BigInteger n, BigInteger m)
{
	size_t i;
	if (m->alloc < n->used)
		if (! increaseSizeOfBigInteger(m, n->used - m->alloc))
			return 0;
	m->used = n->used;
	m->sign = n->sign;
	memcpy(m->digits,n->digits,n->used * sizeof(DIGIT));
	return 1;
}

size_t sizeOfBigInteger(BigInteger n)
{
	size_t k = n->used;
	while (k--)
	{
		if (n->digits[k] != 0)
			return (++k);
	}
	return 0;
}

size_t bitsInBigInteger(BigInteger n)
{
	size_t i;
	size_t ndigits;
	DIGIT mask;

	if ((n == NULL) || n->used == 0)
		return 0;
	if ((ndigits = sizeOfBigInteger(n)) == 0)
		return 0;

	for (i = 0, mask = HIGHESTBITMASK; mask > 0; mask >>= 1, i++)
	{
		if (n->digits[ndigits - 1] & mask)
			break;
	}
	return ndigits * BITS_PER_DIGIT - i;
}

size_t numberOfLowerBitsZeroBigInteger(BigInteger n)
/*
  Return the initial bits equals to zero in n, i.e.,
  the exponent of the greatest power of 2 that divides n

  If n == 0, return 0
*/
{
	size_t i, bits;
	DIGIT m, mask;

	if ((n == NULL) || n->used == 0)
		return 0;

	i = 0;
	while ((i < n->used) && (n->digits[i] == 0))
		i++;
	bits = i * BITS_PER_DIGIT;
	m = n->digits[i];
	for (i = 0, mask = 1; mask > 0; mask <<= 1, i++)
		if (m & mask)
			break;
	return bits + i;
}

int8_t bitOfBigIntegerAtPosition(BigInteger n,DIGIT bit)
/* 
	Returns value 1 or 0 of bit n (0..nbits-1); or -1 if out of range 
*/
{
	size_t idigit, to_get;
	DIGIT mask;

	idigit = bit / BITS_PER_DIGIT;
	if (idigit >= n->used)
		return -1;

	/* Set mask */
	to_get = bit % BITS_PER_DIGIT;
	mask = (DIGIT) 1 << to_get;
	return ((n->digits[idigit] & mask) ? 1 : 0);
}
void cleanUpBigInteger(BigInteger n)
{
	n->used = sizeOfBigInteger(n);
	memset(n->digits + n->used, 0, (n->alloc - n->used) * sizeof(DIGIT));
}

int compareBigIntegerAbsoluteValues(BigInteger n1,BigInteger n2)
{
	size_t m1, m2, i;
	m1 = sizeOfBigInteger(n1);
	m2 = sizeOfBigInteger(n2);
	if (m1 > m2)
		return 1;
	if (m2 > m1)
		return -1;

	/* m1 == m2 */
	for (i = 0; i < m1; i++)
	{
		DIGIT x1, x2;
		x1 = n1->digits[m1 - i - 1];
		x2 = n2->digits[m1 - i - 1];
		if (x1 > x2)
			return 1;
		if (x1 < x2)
			return -1;
	}
	return 0;
}

int compareBigIntegerAbsoluteValuesAtPosition(BigInteger n1,BigInteger n2,DIGIT pos)
/* 
	Compares the absolute values of n1 and B^pos * n2
*/
{
	cleanUpBigInteger(n1);
	cleanUpBigInteger(n2);
	size_t m1, m2, i;
	m1 = sizeOfBigInteger(n1);
	m2 = sizeOfBigInteger(n2);
	if (m1 > m2 + pos)
		return 1;
	if (m2 + pos > m1)
		return -1;	

	/* m1 = m2 + pos */
	for (i = 0; i < m2; i++)
	{
		DIGIT x1, x2;
		x1 = n1->digits[m1 - i - 1];
		x2 = n2->digits[m2 - i -1];
		if (x1 > x2)
			return 1;
		if (x1 < x2)
			return -1;	
	}
	for(i = 0; i < pos;i++)
		if (n1->digits[i] > 0)
			return 1;
	return 0;
}

int compareBigIntegerAbsoluteValueWithDigitAtPos(BigInteger n, DIGIT m, DIGIT pos)
/*
Compares the absolute values of n and m * B^pos
*/
{
	size_t m1, i;
	m1 = sizeOfBigInteger(n);
	if (m == 0)
	{
		if (m1 > 0)
			return 1;
		return 0;
	}
	if (m1 > pos)
		return 1;
	if (pos < m1)
		return -1;
	if(m > n->digits[pos])
		return -1;
	if(m < n->digits[pos])
		return 1;
	for(i = pos;i > 0;i--)
	{
		if (n->digits[i - 1] > 0)
			return 1;
	}
	return 0;
}
			
void setZeroBigInteger(BigInteger n)
{
	memset(n->digits, 0, n->alloc * sizeof(DIGIT));
	n->used = 0;
	n->sign = 1;
}

int isOneBigInteger(BigInteger n)
{
	if (n->sign != 1)
		return 0;
	if (sizeOfBigInteger(n) > 1)
		return 0;
	if (n->digits[0] != (DIGIT) 1)
		return 0;
	return 1;
}

int isMinusOneBigInteger(BigInteger n)
{
	if (n->sign != -1)
		return 0;
	if (sizeOfBigInteger(n) > 1)
		return 0;
	if (n->digits[0] != (DIGIT) 1)
		return 0;
	return 1;
}

void testSignAndZero(BigInteger n)
{
	if (n->sign == 0) 
		n->sign = 1;
}

int increaseSizeOfBigInteger(BigInteger n,size_t s)
{
	if ((n->digits = (DIGIT *)realloc(n->digits,(n->alloc + s) * sizeof(DIGIT))) == NULL)
		return 0;
	n->alloc += s;
	cleanUpBigInteger(n);
	return 1;
}

void free_big_integer(BigInteger *n)
{
	if (*n != NULL)
	{
		if ((*n)->digits != NULL)
			free((*n)->digits);
		free(*n);
	}
	*n = NULL;
}

char *stringFromFile(const char *filename, int8_t *sign)
{
	FILE *fp;
	if ((fp = fopen(filename, "r")) == NULL)
		return NULL;
	int c;
	/*
		Discard initial spaces
	*/
	do
	{
		c = getc(fp);
	}
	while (isspace(c));
	/*
		Sign
	*/
	*sign = 1;
	if (c == '+')
	{
		*sign = 1;
		c = getc(fp);
	} else if (c == '-')
	{
		*sign = -1;
		c = getc(fp);
	}
	/*
		Discard more spaces
	*/
	while (isspace(c))
		c = getc(fp);
	/*
		Dircard initial zeros
	*/
	while (c == '0')
		c = getc(fp);
	/*
		Read discarding non-digits
	*/
	char *str;
	size_t alloc_size, str_size;
	alloc_size = 256;
	str_size = 0;
	if ((str = (char *)calloc(alloc_size,sizeof(char))) == NULL)
		return NULL;

	while (c != EOF)
	{
		if (!isdigit(c))
		{
			c = getc(fp);
			continue;
		}
		if (str_size == alloc_size)
		{
			alloc_size = alloc_size * 3 / 2;
			if ((str = (char *)realloc(str,alloc_size * sizeof(char))) == NULL)
				return NULL;
		}
		str[str_size++] = c;
		c = getc(fp);
	}
	fclose(fp);
	if (str_size == alloc_size)
	{
		alloc_size += 1;
		if ((str = (char *)realloc(str,alloc_size * sizeof(char))) == NULL)
			return NULL;
	}
	str[str_size] = '\0';
	return str;
}

BigInteger bigIntegerFromString(const char *s, int8_t base, int8_t sign)
{
	BigInteger n;
	size_t i;
	DIGIT j;
	size_t nchars;

	nchars = strlen(s);
	if ((n = initBigInteger(ALLOCSIZE)) == NULL)
		goto final;

	n->sign = sign;
	for (i = 0; i < nchars; i++)
	{
		char ch = s[i];
		if (ch == 32)
			continue;
		for (j = 0; j < base; j++)
			if (spDigits[j] == ch)
				break;
		if (! multiplyBigIntegerByDigit(n,base))
			goto final;
		if (! addDigitToBigInteger(n, j, 0))
			goto final;
	}
	return n;

final:
	freeBigInteger(n);
	return NULL;
}

BigInteger readBigIntegerFromFile(const char *filename)
{
	char *s;
	int8_t sign;
	BigInteger n;
	if ((s = stringFromFile(filename, &sign)) == NULL)
		return NULL;
	n = bigIntegerFromString(s, 10, sign);
	freeString(s);
	return n;
}

void reverseString(char *s, size_t len)
{
	char *p, *q, t;
	p = s;
	q = s + (len - 1);
	while (q > p)
	{
		t = *q;
		*q-- = *p;
		*p++ = t;
	}
}

BigInteger partOfBigInteger(BigInteger n,DIGIT begin,DIGIT length)
/*
  Return an auxiliary pointer to a part of a BigInteger
*/
{
	BigInteger r;

	if (begin + length > n->used)
		return NULL;
	
	if ((r = (BigInteger) malloc(sizeof(big_integer))) == NULL)
		return NULL;

	r->used = length;
	r->digits = (DIGIT *) (n->digits + begin);
	r->sign = 1;
	r->alloc = 0;
	return r;
}


char *bigIntegerToString(BigInteger n, DIGIT base)
{
	BigInteger aux;
	char *s;
	DIGIT r;

	if ((base < 2) || (base > 64))
		return NULL;

	if (sizeOfBigInteger(n) == 0)
	{
		if ((s = (char *)calloc(2,sizeof(char))) == NULL)
			return NULL;
		s[0] = '0';
		s[1] = '\0';
		return s;
	}
	size_t allocSize = 1024;
	size_t strSize = 0;

	
	if ((s = (char *)calloc(allocSize,sizeof(char))) == NULL)
		return NULL;
	if ((aux = cloneBigInteger(n)) == NULL)
		return NULL;

	while (sizeOfBigInteger(aux) > 0)
	{
		if (divideBigIntegerByDigit(aux, base, &r) < 0)
		{
			freeString(s);
			return NULL;
		}
		if (strSize == allocSize)
		{
			allocSize = allocSize * 3 / 2;
			if ((s = (char *)realloc(s,allocSize * sizeof(char))) == NULL)
				return NULL;
		}
		s[strSize++] = spDigits[r];
	}

	if ((allocSize - strSize) < 2)
	{
		allocSize += 2;
		if ((s = (char *)realloc(s,allocSize * sizeof(char))) == NULL)
			return NULL;
	}

	if (n->sign == -1)
		s[strSize++] = '-';
	s[strSize] = '\0';
	reverseString(s, strSize);
	freeString(aux);
	return s;
}

char *digitToString(DIGIT n, DIGIT base)
{
	char *s;
	DIGIT r;

	if ((base < 2) || (base > 64))
		return NULL;

	if (n == 0)
	{
		if ((s = (char *)calloc(2,sizeof(char))) == NULL)
			return NULL;
		s[0] = '0';
		s[1] = '\0';
		return s;
	}
	size_t allocSize = 1024;
	size_t strSize = 0;

	if ((s = (char *)calloc(allocSize,sizeof(char))) == NULL)
		return NULL;

	while (n > 0)
	{
		r = n % base;
		n = n / 2;
		if (strSize == allocSize)
		{
			allocSize = allocSize * 3 / 2;
			if ((s = (char *)realloc(s,allocSize * sizeof(char))) == NULL)
				return NULL;
		}
		s[strSize++] = spDigits[r];
	}

	if ((allocSize - strSize) < 1)
	{
		allocSize += 1;
		if ((s = (char *)realloc(s,allocSize * sizeof(char))) == NULL)
			return NULL;
	}
	s[strSize] = '\0';
	reverseString(s, strSize);
	return s;
}

BigInteger randomPositiveBigInteger(DIGIT ndigits)
{
	BigInteger n;
	FILE *fp;

	if ((n = initBigInteger(ndigits)) == NULL)
		return NULL;

	if ((fp = fopen("/dev/urandom", "r")) == NULL)
	{
		freeBigInteger(n);
		return NULL;
	}
	if (fread(n->digits, sizeof(unsigned char), ndigits * BYTES_PER_DIGIT, fp) != ndigits * BYTES_PER_DIGIT)
	{
		freeBigInteger(n);
		fclose(fp);
		return NULL;
	}
	n->used = ndigits;
	n->sign = 1;
	fclose(fp);
	return n;
}

BigInteger randomPositiveBigIntegerWithBits(DIGIT bits)
{
	DIGIT nbytes = bits / BITS_PER_DIGIT;
	DIGIT r;
	BigInteger n;
	if (nbytes * BITS_PER_DIGIT < bits)
		nbytes++;
	if ((n = randomPositiveBigInteger(nbytes)) == NULL)
		return NULL;
	if ((r = bits % BITS_PER_DIGIT) > 0)
	{
		DIGIT mask = ((DIGIT) 1 << r) - 1;
		n->digits[n->used - 1] &= mask;
	}
	cleanUpBigInteger(n);
	return n;
}

uint8_t randomizeBigInteger(BigInteger n)
{
	FILE *fp;
	if ((fp = fopen("/dev/urandom", "r")) == NULL)
		return 0;
	if (fread(n->digits, sizeof(unsigned char), n->used * BYTES_PER_DIGIT, fp) != n->used * BYTES_PER_DIGIT)
	{
		fclose(fp);
		return 0;
	}
	return 1;
}

void printBigIntegerInDecimal(BigInteger n)
{
	char *s;
	s = bigIntegerToString(n, 10);
	printf("%s\n", s);
	freeString(s);
}

void printBigInteger(BigInteger n)
{
	char *s;
	s = bigIntegerToString(n, 10);
	printf("%s\n", s);
	freeString(s);
}

void printBigIntegerInBase(BigInteger n,DIGIT b)
{
	char *s;
	s = bigIntegerToString(n, b);
	printf("%s\n", s);
	freeString(s);
}

void printDigitInBase(DIGIT n, DIGIT base)
{
	char *s;
	s = digitToString(n, base);
	printf("%s", s);
	freeString(s);
}

void printDigitsOfBigInteger(BigInteger n)
{
	size_t i;
	for (i = 0; i < n->used; i++)
		printf("%lu ",n->digits[i]);
	printf("\n");
}