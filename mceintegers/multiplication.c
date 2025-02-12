/**************************************************************************************
* Filename:   multiplication.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2025
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA encryption and decryption algorithm for 
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
#include <mceintegers.h>

int multiplyBigIntegerByDigit(BigInteger n, DIGIT m)
/*
  Computes n = n * m
  If necessary expands n
*/
{
	DIGIT t = 0;
	DOUBLEDIGIT p;
	size_t i = 0;
	size_t d = n->used;
	if (m == 0)
	{
		setZeroBigInteger(n);
		return 1;
	}
	while (i < d)
	{
		p = DD(m) * DD(n->digits[i]) + DD(t);
		n->digits[i] = LOHALF(p);
		t = HIHALF(p);
		i++;
	}
	if (t == 0)
		return 1;
	if (n->used == n->alloc)
		if (! increaseSizeOfBigInteger(n,ALLOCSIZE))
			return 0;
	n->digits[d] = t;
	n->used++;
	return 1;
}

BigInteger schoolMultiplyBigIntegers(BigInteger n1, BigInteger n2)
/*
  Returns n1 * n2 by school algorithm
*/
{
	size_t t1, t2, i, j;
	DIGIT t;
	DOUBLEDIGIT p;
	BigInteger n;

	t1 = sizeOfBigInteger(n1);
	t2 = sizeOfBigInteger(n2);
	if (t1 * t2 == 0)
		return initBigInteger(8);
	if ((n = initBigInteger(t1 + t2)) == NULL)
		return NULL;
	n->used = t1 + t2;
	n->sign = n1->sign * n2->sign;
	for (i = 0; i < t1; i++)
	{
		if (n1->digits[i] == 0)
			continue;
		t = 0;
		for (j = 0; j < t2; j++)
		{
			p = DD(n1->digits[i]) * DD(n2->digits[j]) +
				DD(n->digits[i + j]) + DD(t);
			n->digits[i + j] = LOHALF(p);
			t = HIHALF(p);
		}
		n->digits[i + t2] = t;
	}
	n->used = sizeOfBigInteger(n);
	return n;
}

int shiftBigIntegerToLeftNumberOfDigits(BigInteger n, DIGIT ndigits)
/*
	Thats the same than n = n * 2^(BITS_PER_DIGIT * ndigits)
*/
{
	if ((n->alloc - n->used) < ndigits)
		if (! increaseSizeOfBigInteger(n, ndigits - (n->alloc - n->used)))
			return 0;
	memmove(n->digits + ndigits, n->digits, n->used * sizeof(DIGIT));
	memset(n->digits, 0, ndigits * sizeof(DIGIT));
	n->used += ndigits;
	return 1;
}

int multiplyBigIntegerByPowerOfTwo(BigInteger n, DIGIT power)
/*
  Computes n = n * 2^power
  If necessary expands n
*/
{
	size_t newSize, m, i;
	if ((power == 0) || (sizeOfBigInteger(n) == 0))
		return 1;

	/*
		Compute the new size and alloc space for it
	*/
	newSize = (bitsInBigInteger(n) + power + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
	if (newSize > n->alloc)
		if (! increaseSizeOfBigInteger(n, newSize - n->alloc))
			return 0;
	/*
		If power is 158 and BITS_PER_DIGIT is 32, 178 / 32 = 5
		we first shifts letf 5 digits
	*/
	if (power >= BITS_PER_DIGIT)
	{
		m = power / BITS_PER_DIGIT;
		if (! shiftBigIntegerToLeftNumberOfDigits(n, m))
			return 0;
	}
	/*
		The remainder 18  bits
	*/
	m = power % BITS_PER_DIGIT;
	if (m == 0)
		return 1;

	DIGIT mask, shift, r0, r1;
	DIGIT *aux;
	/*
		m = 18
		14              18
		mask = 00000000000000111111111111111111
		shift = 32 - 18 = 14 
	*/
	shift = BITS_PER_DIGIT - m;
	mask = ((DIGIT) 1 << m) - 1;
	aux = n->digits;
	r0 = 0;
	for (i = 0; i < n->used; i++)
	{
		/*
			r1 stores the first 18 bits of *aux
			*aux stores 
			*/
		r1 = (*aux >> shift) & mask;
		*aux = ((*aux << m) | r0);
		aux++;
		r0 = r1;
	}
	if (r0 > 0)
		n->digits[n->used++] = r0;
	n->used = sizeOfBigInteger(n);
	return 1;
}

int shiftBigIntegerToLeftNumberOfBits(BigInteger n, DIGIT nbits)
{
	return multiplyBigIntegerByPowerOfTwo(n, nbits);
}

int addMultipleOfBigInteger(BigInteger * n1, BigInteger n2, DIGIT m,int8_t sign)
{
	/*
     Computes n1 = n1 + sign * digit * n2
	*/
	BigInteger t, n;
	if ((t = cloneBigInteger(n2)) == NULL)
		return 0;
	if (m != 1)
		if (!multiplyBigIntegerByDigit(t,m))
			return 0;
	t->sign *= sign;
	if ((n = addBigIntegers(t,*n1)) == NULL)
		return 0;
	freeBigInteger(*n1);
	*n1 = n;
	return 1;
}

int exponentialBigIntegerToPowerOfTwo(BigInteger * n, size_t power)
/*
  n = n ^ (2 ^ power)
*/
{
	/*
		Nothing to do
	*/
	if (power == 0)
		return 1;
	if ((sizeOfBigInteger(*n) == 0) || isOneBigInteger(*n))
		return 1;
	/*
		Start squaring
	*/
	size_t i;
	BigInteger r;
	for (i = 0; i < power; i++)
	{
		if ((r = multiplyTwoBigIntegers(*n, *n)) == NULL)
			return 0;
		freeBigInteger(*n);
		*n = r;
	}
	return 1;
}

BigInteger powerOfBigIntegers(BigInteger n1, BigInteger n2)
/*
  The algorithm uses the absolute values of n1 and n2

  Returns n1^n2

  This function uses the Sliding-window exponentiation algorithm
  described in A Handbook Of Applied Cryptography by Alfred J. Menezes,
  Paul C. van Oorschot and Scott A. Vanstone, pag. 616. with k = 8
*/
{
	/*
		Trivial cases
	*/
	if ((sizeOfBigInteger(n1) == 0) && (sizeOfBigInteger(n2) == 0))
		return NULL;
	if (sizeOfBigInteger(n2) == 0)
		return initWithLongInt((DIGIT) 1,1);
	if (sizeOfBigInteger(n1) == 0)
		return initWithLongInt((DIGIT) 0,1);

	int8_t s1, s2;
	s1 = n1->sign;
	n1->sign = 1;
	s2 = n2->sign;
	n2->sign = 1;
	/*
		Precomputation: g[i] = n1^i for i = 0,1,2,3,5,7,.....,255
	*/
	BigInteger *g, r;
	size_t nbit, i;

	r = NULL;
	if((g = (BigInteger *)calloc(256,sizeof(BigInteger *))) == NULL)
		goto final;
	if ((g[0] = initWithLongInt((DIGIT) 1,1)) == NULL)
		goto final;
	if ((g[1] = cloneBigInteger(n1)) == NULL)
		goto final;
	if ((g[2] = multiplyTwoBigIntegers(g[1], g[1])) == NULL)
		goto final;
	for (i = 1; i < 128; i++)
		if ((g[2 * i + 1] = multiplyTwoBigIntegers(g[2 * i - 1], g[2])) == NULL)
			goto final;

    if ((r = initWithLongInt((DIGIT) 1,1)) == NULL)
		goto final;
    size_t obit;
    size_t nbits = bitsInBigInteger(n2);
	uint8_t error = 0;
	DIGIT part;
	while((error == 0) && (nbits > 0))
	{
		BigInteger aux;
        obit = nbits;
		part = nextSlidiwinWindowInBigInteger(n2, &nbits, 8, &error);
		if (error == 1)
            goto final;
        
        if (!exponentialBigIntegerToPowerOfTwo(&r, obit - nbits))
		{
			error = 1;
			goto final;
		}
		if (part != 0) 
		{
			if ((aux = multiplyTwoBigIntegers(r,g[part])) == NULL)
			{
				error = 1;
				goto final;
			}
			freeBigInteger(r);
			r = aux;
		}
	} 
final:
	n1->sign = s1;
	n2->sign = s2;
	r->sign = s1 * s2;
	for (i = 0; i < 256; i++)
		freeBigInteger(g[i]);
    if (error == 1)
    {
		freeBigInteger(r);
        r = NULL;
    }
	free(g);
	return r;
}
