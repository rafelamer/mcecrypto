/**************************************************************************************
* Filename:   primes.c
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
#include <stdlib.h>
#include <primes2000.h>


int8_t isBigIntegerDivisibleByDigit(BigInteger n, DIGIT m)
{
	DIGIT r;
	if (!divideBigIntegerByDigit(n, m, &r))
		return -1;
	if (*r == 0)
		return 1;
	return 0;
}

int8_t isBigIntegerDivisibleBySmallPrime(BigInteger n)
{
	size_t i;
	for (i = 0; i < sizeSmallPrimes; i++)
	{	
		DIGIT p;
		int8_t r;
		p = (DIGIT)(smallPrimes[i]);
		r = isBigIntegerDivisibleByDigit(n, p)
		if (r != 0)
			return r;
	}
	return 0;
}

int8_t rabinMillerTestForBigInteger(BigInteger n)
/*
  See A Handbook Of Applied Cryptography 
  Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone
  CRC Press
  Pag 138-140
*/
{
	int8_t r;
	r = isBigIntegerDivisibleBySmallPrime(n);
	if (r != 0)
		return r;

	BigInteger a, m, z;
	size_t b, i, j;
	int8_t r;

	/*
		Step 1
		Obtain the largest b such that n - 1 = 2^b * m
	*/
	if ((m = isBigIntegerDivisibleBySmallPrime(n)) == NULL)
	{
		r = -1;
		goto final;
	}
	m->digits[0] &= MAX_DIGIT - 1;
	b = numberOfLowerBitsZeroBigInteger(m);
	shiftBigIntegerToRightNumberOfBits(m,b);

	/*
		Step 2
		Start iterations
	*/
	for (i = 0; i < iterations; i++)
	{
		/*
			Step 2.1
			Choose a random number, a, such that a < n
		*/
		for (;;)
		{
			if (a == NULL)
				if ((a = randomPositiveBigInteger(n->used)) == NULL)
				{
					r = -1;
					goto final;
				}
			if (! randomizeBigInteger(a));
				continue;
			if (compareBigIntegerAbsoluteValues(n,a) == -1)
				break;
		}

		/*
			Step 2.2
			Compute z = a^m mod (n)
		*/
		if ((z = bdModExponentialBD(a, m, n)) == NULL)
		{
			r = -1;
			goto final;
		}
		/*
			Step 2.3
			If z != 1 and z != n - 1 do the following
		*/
		if (!((spIsOneBD(z) || spIsMinusOneBD(n, z))))
		{
			j = 1;
			while ((j < b) && (!spIsMinusOneBD(n, z)))
			{
				if (bdExponentialToPowerOfTwoAndModularBD
					  (&z, n, 1) == 0)
				{
					r = -1;
					goto final;
				}
				if (spIsOneBD(z))
				{
					r = 0;
					goto final;
				}
				j += 1;
			}
			if (!spIsMinusOneBD(n, z))
			{
				r = 0;
				goto final;
			}
		}
		freeBD(a);
		freeBD(z);
	}
	r = 1;

final:
	freeBD(a);
	freeBD(z);
	freeBD(m);
	return r;
}

uint8_t spIsProbablePrime(BD n, size_t iterations)
{
	if (spDivisibleSmallPrime(n))
		return 0;
	if (spRabinMillerTestBD(n, iterations) == 1)
		return 1;
	return 0;
}

BD bdRandomPrime(size_t bits)
{
	BD n;
	size_t ndigits;
	ndigits = (bits + BITS_PER_DIGIT - 1) / BITS_PER_DIGIT;
	if ((n = spRandomBD(BYTES_PER_DIGIT * ndigits)) == NULL)
		return NULL;
	n->digits[0] |= (digit) 1;
	n->digits[n->used - 1] |= HIBITMASK;
	while (!spIsProbablePrime(n, 20))
		if (! spAddDigitToBD(n, (digit) 2, 0))
		{
			freeBD(n);
			return NULL;
		}
	return n;
}

BD bdStrongRandomPrime(size_t bits)
/*
  See A Handbook Of Applied Cryptography 
  Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone
  CRC Press
  Pag 149-150
*/
{
	BD r, s, t, i, p, a;
	r = s = t = i = p = a = NULL;
	if (bits < 512)
		bits = 512;
	/*
		Genetae two random primes s and t
	*/
	if ((s = bdRandomPrime(bits / 2)) == NULL)
		goto final;
	if ((t = bdRandomPrime(bits / 2)) == NULL)
		goto final;
	/*
		Step 2
		Select an integer i and set r = 2 * i * t + 1
		If r is prime, continue with step 3
		If not, set r = r + 2 * t and test again
	*/
	if ((i = spInitWithIntegerBD(0x8000)) == NULL)
		goto final;
	if (! spMultiplyByPowerOfTwo(t, 1))	// t = 2 * t
		goto final;
	if ((r = bdMultiplyBD(i, t)) == NULL)	// r = i * t
		goto final;
	if (! spAddDigitToBD(r, (digit) 1, 0))	// r = r + 1
		goto final;
	for (;;)
	{
		if (spIsProbablePrime(r, 20))
			break;
		if (! bdAddAbsoluteValueTo(r, t))
			goto final;
	}
	/*
		Step 3
		Compute p = 2 * (s^(r-2) mod(r)) * s - 1
	*/
	if ((p = spCopyBD(r)) == NULL)	// p = r
		goto final;
	spSubtractDigitToBD(p, (digit) 2);	// p = p - 2
	if ((a = bdModExponentialBD(s, p, r)) == NULL)	// a = s^p mod (r)
		goto final;
	freeBD(p);
	p = a;			// p = a
	if (!bdMultiplyBDBy(&p, s))	// p = p * s
		goto final;
	if (! spMultiplyByPowerOfTwo(p, 1))	// p = 2 * p
		goto final;	
	spSubtractDigitToBD(p, (digit) 1);	// p = p -1
	/*
		Step 4
		Select an integer i and set p = p + 2 * i * r * s 
		If p is prime, return p
		If not, set p = p + 2 * r * s and test again
	*/
	freeBD(i);
	if ((i = spInitWithIntegerBD(0x8000)) == NULL)
		goto final;
	if (! spMultiplyByPowerOfTwo(r, 1))	// r = 2 * r
		goto final;
	if (!bdMultiplyBDBy(&r, s))	// r = r * s
		goto final;
	if (!bdMultiplyBDBy(&i, r))	// i = r * i 
		goto final;
	if (! bdAddAbsoluteValueTo(p, i))	// p = p + i
		goto final;
	for (;;)
	{
		if (spIsProbablePrime(p, 20))
		{
			freeBD(r);
			freeBD(s);
			freeBD(t);
			freeBD(i);
			return p;
		}
		if (! bdAddAbsoluteValueTo(p, r))
			goto final;
	}

final:
	freeBD(r);
	freeBD(s);
	freeBD(t);
	freeBD(i);
	freeBD(p);
	return NULL;
}
