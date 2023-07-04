/**************************************************************************************
* Filename:   gcd.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2023
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
#include <bigintegers.h>

BigInteger extendedEuclidAlgorithmBigIntegers(BigInteger n1, BigInteger n2, BigInteger * x, BigInteger * y)
/*
  The algorithm uses the absolute values of n1 and n2

  Returns r = gcd(n1,n2);
  and finds x and y such that n1 * x + n2 * y = r
*/
{
	BigInteger u, v, lx, ly;
	size_t lu, lv, l;
	int exch;

	if ((sizeOfBigInteger(n1) == 0) || (sizeOfBigInteger(n2) == 0))
		return NULL;

	if ((u = cloneBigInteger(n1)) == NULL)
		goto final;
	if ((v = cloneBigInteger(n2)) == NULL)
		goto final;
	u->sign = v->sign = 1;

	lu = numberOfLowerBitsZeroBigInteger(u);
	lv = numberOfLowerBitsZeroBigInteger(v);
	l = min(lu, lv);
	shiftBigIntegerToRightNumberOfBits(u, l);
	shiftBigIntegerToRightNumberOfBits(v, l);

	exch = 0;
	if (compareBigIntegerAbsoluteValues(u, v) == -1)
	{
		BigInteger t;
		t = u;
		u = v;
		v = t;
		exch = 1;
	}
	if ((*x = initWithLongInt((DIGIT) 1,1)) == NULL)
		goto final;
	if ((*y = initBigInteger(ALLOCSIZE)) == NULL)
		goto final;
	if ((ly = initWithLongInt((DIGIT) 1,1)) == NULL)
		goto final;
	if ((lx = initBigInteger(ALLOCSIZE)) == NULL)
		goto final;

	while (sizeOfBigInteger(v) > 0)
	{
		BigInteger r, q, t1, t2;
		r = divideBigIntegerByBigInteger(u, v, &q);
		freeBigInteger(u);
		u = v;
		v = r;
		/*
			Extended part for *x and lx
			(lx, x) = ((x - (q * lx)),lx)
		*/
		t1 = multiplyTwoBigIntegers(q, lx);
		t2 = subtrackBigIntegers(*x, t1);
		freeBigInteger(t1);
		freeBigInteger(*x);
		*x = lx;
		lx = t2;
		/*
			Extended part for *y and ly
		*/
		t1 = multiplyTwoBigIntegers(q, ly);
		t2 = subtrackBigIntegers(*y, t1);
		freeBigInteger(t1);
		freeBigInteger(*y);
		*y = ly;
		ly = t2;
		freeBigInteger(q);
	}
	freeBigInteger(lx);
	freeBigInteger(ly);
	freeBigInteger(v);
	if (! multiplyBigIntegerByPowerOfTwo(u, l))
		goto final;
	if (exch == 1)
	{
		BigInteger t;
		t = *y;
		*y = *x;
		*x = t;
	}
	return u;

final:
	freeBigInteger(u);
	freeBigInteger(v);
	freeBigInteger(*x);
	freeBigInteger(*y);
	freeBigInteger(lx);
	freeBigInteger(lx);
	return NULL;
}

BigInteger leastCommonMultipleOfBigIntegers(BigInteger n1, BigInteger n2)
/*
  The algorithm uses the absolute values of n1 and n2
  Returns r = lcm(n1,n2)
*/
{
	BigInteger t, r, q, x, y;
	t = r = q = NULL;
	if ((t = extendedEuclidAlgorithmBigIntegers(n1, n2, &x, &y)) == NULL)
		goto final;
	if ((r = divideBigIntegerByBigInteger(n1, t, &q)) == NULL)
		goto final;
	if (sizeOfBigInteger(r) > 0)
		goto final;
	freeBigInteger(t);
	if ((t = multiplyTwoBigIntegers(q, n2)) == NULL)
		goto final;

final:
	freeBigInteger(r);
	freeBigInteger(q);
	freeBigInteger(x);
	freeBigInteger(y);
	return t;
}
