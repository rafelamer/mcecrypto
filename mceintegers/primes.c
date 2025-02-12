/**************************************************************************************
* Filename:   primes.c
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
#include <mceintegers.h>
#include <stdlib.h>
#include <primes2000.h>

int isBigIntegerDivisibleBySmallPrime(BigInteger n)
{
	size_t i;
	for (i = 0; i < sizeSmallPrimes; i++)
	{	
		DIGIT p;
		int8_t r;
		p = (DIGIT)(smallPrimes[i]);
		r = isBigIntegerDivisibleByDigit(n, p);
		if (r != 0)
			return r;
	}
	return 0;
}

int rabinMillerTestForBigInteger(BigInteger n, size_t iterations)
/*
  See A Handbook Of Applied Cryptography 
  Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone
  CRC Press
  Pag 138-140
*/
{
	BigInteger a, m, z;
	size_t b, i, j;
	int8_t r;
	a = m = z = NULL;
	
	/*
		Step 1
		Obtain the largest b such that n - 1 = 2^b * m
	*/
	if ((m = cloneBigInteger(n)) == NULL)
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
			{
				if ((a = randomPositiveBigInteger(n->used)) == NULL)
				{
					r = -1;
					goto final;
				}
			}
			else
			{ 
				if (! randomizeBigInteger(a))
					continue;
			}
			if (! normalizeBigIntegerModulus(&a,n))
				continue;
			if (compareBigIntegerAbsoluteValues(n,a) >= 0)
				break;
		}

		/*
			Step 2.2
			Compute z = a^m mod (n)
		*/
		if ((z = modulusOfExponentialBigIntegers(a, m, n)) == NULL)
		{
			r = -1;
			goto final;
		}
		/*
			Step 2.3
			If z != 1 and z != n - 1 do the following
		*/
		if (! ((isOneBigInteger(z) || isDiferenceOfBigIntegersMinusOne(n,z))))
		{
			j = 1;
			while ((j < b) && (! isDiferenceOfBigIntegersMinusOne(n, z)))
			{
				if (modulusOfExponentialOfBigIntegerToAPowerOfTwo(&z, n, 1) == 0)
				{
					r = -1;
					goto final;
				}
				if (isOneBigInteger(z))
				{
					r = 0;
					goto final;
				}
				j += 1;
			}
			if (! isDiferenceOfBigIntegersMinusOne(n, z))
			{
				r = 0;
				goto final;
			}
		}
		freeBigInteger(z);
	}
	r = 1;

final:
	freeBigInteger(a);
	freeBigInteger(z);
	freeBigInteger(m);
	return r;
}

uint8_t isPrimeRabinMillerBigInteger(BigInteger n, size_t iterations)
{
	if (isBigIntegerDivisibleBySmallPrime(n) != 0)
		return 0;
	if (rabinMillerTestForBigInteger(n, iterations) == 1)
		return 1;
	return 0;
}

BigInteger randomBigIntegerPrime(size_t bits)
{
	BigInteger n;

	if ((n = randomPositiveBigIntegerWithBits(bits)) == NULL)
		return NULL;
	n->digits[0] |= (DIGIT)1;
	while (! isPrimeRabinMillerBigInteger(n,RABINMILLERITERATIONS))
	{
		if (! addDigitToBigInteger(n, (DIGIT)2, 0))
		{
			freeBigInteger(n);
			return NULL;
		}
	}
	return n;
}

BigInteger randomBigIntegerStrongPrime(size_t bits)
/*
	See A Handbook Of Applied Cryptography 
	Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone
	CRC Press
	Pag 149-150

	A prime number p is said to be a strong prime if there exist integers r, s, 
	and t such that the following three conditions are satisfied:
		p − 1 has a large prime factor, denoted r
		p + 1 has a large prime factor, denoted s
		r − 1 has a large prime factor, denoted t.
*/
{
	BigInteger r, s, t, i, p, a, b;
	r = s = t = i = p = a = NULL;
	if (bits < 64)
		bits = 64;
	/*
		Genetae two random prime numbers s and t
	*/
	if ((s = randomBigIntegerPrime(bits / 2)) == NULL)
		goto final;
	if ((t = randomBigIntegerPrime(bits / 2)) == NULL)
		goto final;
	
	/*
		Step 2
		Select an integer i and set r = 2 * i * t + 1
		If r is prime, continue with step 3
		If not, set r = r + 2 * t and test again
	*/
	if ((i = randomPositiveBigInteger(1)) == NULL)
		goto final;
	if (! multiplyBigIntegerByPowerOfTwo(t, 1))	// t = 2 * t
		goto final;
	if ((r = multiplyTwoBigIntegers(i, t)) == NULL)	// r = i * t
		goto final;
	if (! addDigitToBigInteger(r, (DIGIT)1, 0))	// r = r + 1
		goto final;
	
	for (;;)
	{
		if (isPrimeRabinMillerBigInteger(r, RABINMILLERITERATIONS))
			break;
		if (! addAtPositionToBigInteger(r, (DIGIT)1, t, 0))
			goto final;
	}

	/*
		Now, we have r0

		Step 3
		Compute p = 2 * (s^(r-2) mod(r)) * s - 1
	*/
	if ((p = cloneBigInteger(r)) == NULL)	// p = r
		goto final;
	if (! subtrackDigitToBigInteger(p, (DIGIT)2, 0)) // p = p - 2
		goto final;
	if ((a = modulusOfExponentialBigIntegers(s, p, r)) == NULL)	// a = s^p mod (r)
		goto final;
	freeBigInteger(p);
	if ((p = multiplyTwoBigIntegers(a, s)) == NULL)   // p = a * s
		goto final;
	if (! multiplyBigIntegerByPowerOfTwo(p, (DIGIT)1))   // p = 2 * p
		goto final;
	if (! subtrackDigitToBigInteger(p, (DIGIT)1, 0))	// p = p - 1
		goto final;
	freeBigInteger(a);

	/*
		Now we have p0

		Step 4
		Select an integer i and set p = p + 2 * i * r * s 
		If p is prime, return p
		If not, set p = p + 2 * r * s and test again
	*/
	if (! randomizeBigInteger(i))
		goto final;
	if (! multiplyBigIntegerByPowerOfTwo(r, 1))	// r = 2 * r0
		goto final;
	if ((a = multiplyTwoBigIntegers(r, s)) == NULL)   // a = 2 * r0 * s
		goto final;
	if ((b = multiplyTwoBigIntegers(a, i)) == NULL)   // b = 2 * r0 * s * i 
		goto final;
	if (! addAtPositionToBigInteger(b, (DIGIT)1, p, (DIGIT)0)) // b = 2 * r0 * s * i + p0
		goto final;
	for (;;)
	{
		if (isPrimeRabinMillerBigInteger(b, RABINMILLERITERATIONS))
			goto final;

		if (! addAtPositionToBigInteger(b, (DIGIT)1, a, 0))
		{
			freeBigInteger(b);
			goto final;
		}
	}

final:
	freeBigInteger(r);
	freeBigInteger(s);
	freeBigInteger(t);
	freeBigInteger(i);
	freeBigInteger(p);
	freeBigInteger(a);
	return b;
}
