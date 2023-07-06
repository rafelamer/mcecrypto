/**************************************************************************************
* Filename:   modular.c
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
#include <mceintegers.h>
#include <stdlib.h>

BigInteger modulusOfBigIntegerByPowerOfTwo(BigInteger n, DIGIT power)
/*
  Returns n % (2^power)
*/
{
	BigInteger m;
	DIGIT b, i;

	if ((power == 0) || (sizeOfBigInteger(n) == 0))
		return initBigInteger(ALLOCSIZE);

	if ((m = cloneBigInteger(n)) == NULL)
		return NULL;

	b = (power + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
	for (i = b; i < m->used; i++)
		m->digits[i] = 0;

	i = power % BITS_PER_DIGIT;
	m->digits[b - 1] &= ((DIGIT) 1 << i) - (DIGIT) 1;
	m->used = sizeOfBigInteger(m);
	return m;
}

BigInteger modulusOfBigInteger(BigInteger n1, BigInteger n2)
/*
  Returns r = n1 mod (n2)
*/
{
	BigInteger q, r;
	if ((r = divideBigIntegerByBigInteger(n1, n2, &q)) == NULL)
		return NULL;	
	freeBigInteger(q);
	return r;
}

BigInteger modulusOfProductOfBigInteger(BigInteger n1, BigInteger n2, BigInteger n3)
/*
  The algorithm uses the absolute values of n1, n2 and n2

  Returns r = n1 * n2 mod(n3)
*/
{
	BigInteger r, m;
	if ((r = multiplyTwoBigIntegers(n1, n2)) == NULL)
		return NULL;
	if ((m = modulusOfBigInteger(r, n3)) == NULL)
	{
		freeBigInteger(r);
		return NULL;
	}
	freeBigInteger(r);
	return m;
}

int modulusOfExponentialOfBigIntegerToAPowerOfTwo(BigInteger * n, BigInteger n2, DIGIT power)
/*
    Computes
	n = n ^ (2 ^ power)  mod(n2)
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
		if ((r = modulusOfProductOfBigInteger(*n, *n, n2)) == NULL)
			return 0;
		freeBigInteger(*n);
		*n = r;
		r = NULL;
	}
	return 1;
}

BigInteger modularInverseOfBigInteger(BigInteger n1, BigInteger n2, int8_t * error)
/*
  The algorithm uses the absolute values of n1 and n2

  Returns a positive number r such tat n1 * r = 1 mod (n2)
  *error =  0 if OK
	= -1 if n1 and n2 are not coprimes
	= -2 otherwise
*/
{
	BigInteger r, x, y;
	*error = 0;

	if ((r = extendedEuclidAlgorithmBigIntegers(n1, n2, &x, &y)) == NULL)
	{
		*error = -2;
		goto final;
	}
	if (!isOneBigInteger(r))
	{
		*error = -1;
		goto final;
	}
	freeBigInteger(y);
	freeBigInteger(r);
	if (x->sign == -1)
	{
		r = cloneBigInteger(n2);
		r->sign = 1;
		subtrackBigIntegerAbsoluteValueTo(r, x);
		freeBigInteger(x);
		return r;
	}
	return x;

final:
	freeBigInteger(r);
	freeBigInteger(x);
	freeBigInteger(y);
	return NULL;
}

int normalizeBigIntegerModulus(BigInteger *n,BigInteger p)
{
    BigInteger m;
	if ((m = modulusOfBigInteger(*n,p)) == NULL)
		return 0;
	freeBigInteger(*n);
	*n = m;
	return 1;
}

BigInteger modulusOfExponentialBigIntegers(BigInteger n1,BigInteger n2,BigInteger n3)
/*
  The algorithm uses the absolute values of n1, n2 and n3

  Returns r = n1^n2 mod(n3)

  Is the same algorithm than powerOfBigIntegers, but now after ever multiplication,
  we take modulus n3
*/
{
	if (sizeOfBigInteger(n3) == 0)
		return NULL;
	if ((sizeOfBigInteger(n1) == 0) && (sizeOfBigInteger(n2) == 0))
		return NULL;
	if (sizeOfBigInteger(n2) == 0)
		return initWithLongInt((DIGIT) 1,1);
	
	if (sizeOfBigInteger(n1) == 0)
		return initWithLongInt((DIGIT) 0,1);

	/*
		Precomputation: g[i] = n1^i mod (n3)  for i = 0,1,2,3,5,7,.....,255
	*/
	BigInteger *g, r;
	size_t i;

	r = NULL;
	if((g = (BigInteger *)calloc(256,sizeof(BigInteger *))) == NULL)
		goto final;
	if ((g[0] = initWithLongInt((DIGIT) 1,1)) == NULL)
		goto final;
	if ((g[1] = modulusOfBigInteger(n1,n3)) == NULL)
		goto final;
	if ((g[2] = modulusOfProductOfBigInteger(g[1], g[1], n3)) == NULL)
		goto final;
	for (i = 1; i < 128; i++)
		if ((g[2 * i + 1] = modulusOfProductOfBigInteger(g[2 * i - 1], g[2], n3)) == NULL)
			goto final;

	if ((r = initWithLongInt((DIGIT) 1,1)) == NULL)
		goto final;

	size_t obit;
  	size_t nbits = bitsInBigInteger(n2);
	uint8_t error = 0;
	DIGIT part;
	BigInteger exp;
	exp = initWithLongInt((DIGIT)0,1);
	while((error == 0) && (nbits > 0))
	{
		BigInteger aux;
        obit = nbits;
		part = nextSlidiwinWindowInBigInteger(n2, &nbits, 8, &error);
		if (error == 1)
            goto final;
		if (! modulusOfExponentialOfBigIntegerToAPowerOfTwo(&r, n3, obit - nbits))
		{
				error = 1;
				goto final;
		}
		for(int i=0;i<obit - nbits;i++)
			multiplyBigIntegerByDigit(exp, (DIGIT)2);
		if (part != 0) 
		{
			if ((aux = modulusOfProductOfBigInteger(r,g[part],n3)) == NULL)
			{
				error = 1;
				goto final;
			}
			freeBigInteger(r);
			r = aux;
			addDigitToBigInteger(exp, part, 0);
		}
	} 	
final:
	for (i = 0; i < 256; i++)
		freeBigInteger(g[i]);	
	free(g);
	if(error == 1)
	{
		freeBigInteger(r);
		r = NULL;
	}
	return r;
}

int LegendreSymbol(BigInteger n,BigInteger p,uint8_t *error)
/*
	Returns the Legendre symbol of the numbers n and p. p must be prime
*/
{
	BigInteger n1, n2, n3;
	int result;
	n1 = n2 = n3 = NULL;
	*error = 0;
	result = 0;
	if ((n1 = cloneBigInteger(p)) == NULL)
	{
		*error = 1;
		goto final;
	}
	if ((n2 = initWithLongInt((DIGIT)1,1)) == NULL)
	{
		*error = 1;
		goto final;
	}
	if (!subtrackAtPositionToBigInteger(n1,(DIGIT)1,n2,(DIGIT)0))
	{
		*error = 1;
		goto final;
	}
	shiftBigIntegerToRightNumberOfBits(n1, (DIGIT)1);
	if ((n3 = modulusOfExponentialBigIntegers(n, n1, p)) == NULL)
	{
		*error = 1;
		goto final;
	}
	if (isOneBigInteger(n3))
	{
		result = 1;
		goto final;
	}
	if (!addAtPositionToBigInteger(n3,(DIGIT)1,n2,(DIGIT)0))
	{
		*error = 1;
		goto final;
	}
	freeBigInteger(n1);
	if ((n1 = modulusOfBigInteger(n3, p)) == NULL)
	{
		*error = 1;
		goto final;
	}
	if (sizeOfBigInteger(n1) == 0)
		result = -1;

final:
	freeBigInteger(n1);
	freeBigInteger(n2);
	freeBigInteger(n3);
	return result;
}





