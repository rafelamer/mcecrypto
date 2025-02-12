/**************************************************************************************
* Filename:   karatsuba.c
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

BigInteger karatsuba_simple(BigInteger z0,BigInteger z1,DIGIT m,DIGIT  ndigits)
{
	BigInteger n;
	if ((n = initBigInteger(ndigits)) == NULL)
		return NULL;
	n->used = ndigits;
	n->sign = 1;
	if (addAtPositionToBigInteger(n, (DIGIT)1, z0, 0) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	if (addAtPositionToBigInteger(n, (DIGIT)1, z1, m) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	return n;
}

BigInteger karatsuba_general(BigInteger z2, BigInteger z, BigInteger z0, size_t m, size_t ndigits)
{
	
	BigInteger n;
	if ((n = initBigInteger(ndigits)) == NULL)
		return NULL;
	n->used = ndigits;

	if (addAtPositionToBigInteger(n, (DIGIT)1, z2, 2 * m) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	if (addAtPositionToBigInteger(n, (DIGIT)1, z, m) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	if (addAtPositionToBigInteger(n, (DIGIT)1, z0, 0) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	if (subtrackAtPositionToBigInteger(n, (DIGIT)1, z2, m) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	if (subtrackAtPositionToBigInteger(n, (DIGIT)1, z0, m) < 0)
	{
		freeBigInteger(n);
		return NULL;
	}
	
	return n;
}

BigInteger multiplyByKaratsubaBigIntegers(BigInteger n1,BigInteger n2)
{
	BigInteger l, s;
	size_t m;
	if (n1->used >= n2->used)
	{
		l = n1;
		s = n2;
	} 
	else
	{
		l = n2;
		s = n1;
	}
	/*
		Non recursive case
	*/
	if (l->used < 118)
		return schoolMultiplyBigIntegers(l, s);

	/*
		First recursive case
	*/
	m = (l->used % 2) == 0 ? l->used / 2 : l->used / 2 + 1;
	BigInteger x1, x0;
	x0 = partOfBigInteger(l,0,m);
	x1 = partOfBigInteger(l,m,l->used - m);
	if (s->used <= m)
	{
		BigInteger z0, z1, r;
		z0 = multiplyByKaratsubaBigIntegers(x0, s);
		z1 = multiplyByKaratsubaBigIntegers(x1, s);
		r = karatsuba_simple(z0, z1, m, l->used + s->used);
		freeBigInteger(z0);
		freeBigInteger(z1);
		free(x0);
		free(x1);
		r->sign = l->sign * s->sign;
		return r;
	}
	/*
		General recursive case
	*/
	BigInteger y1, y0, s1, s2, z0, z, z2, r;
	y0 = partOfBigInteger(s, 0, m);
	y1 = partOfBigInteger(s, m, s->used - m);
	z0 = multiplyByKaratsubaBigIntegers(x0, y0);
	z2 = multiplyByKaratsubaBigIntegers(x1, y1);
	s1 = addBigIntegerAbsoluteValues(x1, x0);
	s2 = addBigIntegerAbsoluteValues(y1, y0);
	z = multiplyByKaratsubaBigIntegers(s1, s2);
	r = karatsuba_general(z2, z, z0, m, l->used + s->used);
	freeBigInteger(z0);
	freeBigInteger(z2);
	freeBigInteger(z);
	freeBigInteger(s1);
	freeBigInteger(s2);
	free(x0);
	free(x1);
	free(y0);
	free(y1);
	r->sign = l->sign * s->sign;
	return r;
}
