/**************************************************************************************
* Filename:   division.c
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
#define POSITIVE(x) if(x < 0) {x = -x;}
#define NEGATIVE(x) if(x > 0) {x = -x;}
#define ASSIGNTO(x,y) if (! copyBigIntegerTo(x,y)) goto final

int isBigIntegerDivisibleByDigit(BigInteger n, DIGIT m)
{
	
	DOUBLEDIGIT w = 0;
    DIGIT t;
    size_t i, k;
    for (i = 0; i < n->used; i++)
    {
        k = n->used - i - 1;
        w = (w << BITS_PER_DIGIT) | ((DOUBLEDIGIT) n->digits[k]);
        if (w >= m)
        {
            t = (DIGIT) (w / m);
            w -= ((DOUBLEDIGIT) t) * ((DOUBLEDIGIT) m);
        }
    }
    if (w == 0)
        return 1;
    return 0;
}

void shiftBigIntegerToRightNumberOfDigits(BigInteger n, DIGIT ndigits)
{
	if (ndigits == 0)
		return;
	if (n->used <= ndigits)
	{
		setZeroBigInteger(n);
		return;
	}

	DIGIT *top, *bottom;
	size_t i;
	bottom = n->digits;
	top = n->digits + ndigits;

	for (i = 0; i < n->used - ndigits; i++)
		*bottom++ = *top++;

	for (; i < n->used; i++)
		*bottom++ = 0;
	n->used = sizeOfBigInteger(n);
}

void shiftBigIntegerToRightNumberOfBits(BigInteger n, DIGIT nbits)
/*
  Is the same function divideBigIntegerByPowerOfTwo, but discarding
  the remainder
*/
{
	if ((nbits == 0) || (sizeOfBigInteger(n) == 0))
		return;

	if (nbits >= BITS_PER_DIGIT)
		shiftBigIntegerToRightNumberOfDigits(n, nbits / BITS_PER_DIGIT);
	if (sizeOfBigInteger(n) == 0)
		return;

	nbits %= BITS_PER_DIGIT;
	if (nbits == 0)
		return;

	DIGIT mask, shift, r0, r1;
	DIGIT *aux;
	shift = BITS_PER_DIGIT - nbits;
	mask = ((DIGIT) 1 << nbits) - 1;
	aux = n->digits + (n->used - 1);
	r0 = 0;
	while (aux >= n->digits)
	{
		r1 = *aux & mask;
		*aux = (*aux >> nbits) | (r0 << shift);
		aux--;
		r0 = r1;
	}
	n->used = sizeOfBigInteger(n);
}

uint8_t findFirstDigitByBisection(BigInteger t1, BigInteger t2,DIGIT *m)
/*
	If *m * t2 < t1, then we don't modify *m and the function returns 1
	If *m * t2 >= t1, then
		We find the digit x such that 
	    	x <= *m
			x * t2 < t1
			(x+1) * t2 < t1
	Finally, *m = x and the function returns 1
*/
{
	DIGIT dm = *m;
	uint8_t value = 0;
	int8_t sign = -1;
	BigInteger x, y, z;
	x = y = z = NULL;
	if ((z = cloneBigInteger(t2)) == NULL)
		goto final;
	if (! multiplyBigIntegerByDigit(z,*m))
		goto final;
	/*
		Trivial case *m * t2 < t1
	*/
	if (compareBigIntegerAbsoluteValues(z,t1) < 0 )
	{
		value = 1;
		goto final;
	}
	/*
		Now *m * t2 >= t1
	*/
	if ((x = cloneBigInteger(t2)) == NULL)
		goto final;
	if ((y = cloneBigInteger(t2)) == NULL)
		goto final;
	/*
		Bisection method with a final adjustements
	*/
	while (dm > 0)
	{
		if (!addAtPositionToBigInteger(y, (DIGIT)1, z, 0))
			goto final;
		shiftBigIntegerToRightNumberOfBits(y, (DIGIT)1);
		dm /= 2;
		// printf("%lu %d\n",*m,sign);
		if (sign == 1)
			(*m) += dm;
		else
			(*m) -= dm; 
		// printf("%lu\n",*m);

		if (compareBigIntegerAbsoluteValues(y,t1) > 0)
		{
			ASSIGNTO(y,z);
			ASSIGNTO(x,y);
			NEGATIVE(sign);
		}
		else
		{
			ASSIGNTO(y,x);
			POSITIVE(sign);
		}
	}
	/*
		Final adjustement
	*/
	ASSIGNTO(t2,x);
	if (! multiplyBigIntegerByDigit(x,*m))
		goto final;
	for(;;)
	{
		uint8_t test;
		test = 0;
		if (compareBigIntegerAbsoluteValues(x,t1) <= 0)
		{
			if (!addAtPositionToBigInteger(x, (DIGIT)1, t2, 0))
				goto final;
			(*m) += 1;
			test = 1;
		}
		if (compareBigIntegerAbsoluteValues(x,t1) >= 0)
		{
			if (!subtrackAtPositionToBigInteger(x, (DIGIT)1, t2, 0))
				goto final;
			(*m) -= 1;
			if (test == 1)
				break; 
		}
	}
	value = 1;
	
final:
	freeBigInteger(x);
	freeBigInteger(y);
	freeBigInteger(z);	
	return value;
}

BigInteger remainderOfBigIntegerDividedByPowerOfTwo(BigInteger n, DIGIT power)
/*
  Returns n % (2^power)
*/
{
	BigInteger m;
	DIGIT b, i;

	if ((power == 0) || (sizeOfBigInteger(n) == 0))
		return initWithLongInt(0,0);

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


BigInteger divideBigIntegerByPowerOfTwo(BigInteger n, DIGIT power)
/*
  Divides n by 2^power, i.e., shifts to the right a certain number of bits
  Returns the remainder, i.e., the bits discarded
*/
{
	DIGIT d;
	BigInteger r;

	if ((power == 0) || (sizeOfBigInteger(n) == 0))
		return initBigInteger(ALLOCSIZE);
	/*
		Remainder
	*/
	if ((r = modulusOfBigIntegerByPowerOfTwo(n, power)) == NULL)
		return NULL;

	/*
		Quotient
		If power is 150 and BITS_PER_DIGIT is 32, 150 / 32 = 4
		we first shifts right 4 digits
	*/
	if (power >= BITS_PER_DIGIT)
		shiftBigIntegerToRightNumberOfDigits(n, power / BITS_PER_DIGIT);
	if (sizeOfBigInteger(n) == 0)
		return r;
	/*
		d = 150 % 32 = 22
		and we have to shift right 22 bits
	*/
	d = power % BITS_PER_DIGIT;
	if (d == 0)
		return r;

	DIGIT mask, shift, r0, r1;
	DIGIT *aux;
	/*
		mask = 00000000001111111111111111111111
		shift = 10
	*/
	shift = BITS_PER_DIGIT - d;
	mask = ((DIGIT) 1 << d) - 1;
	aux = n->digits + (n->used - 1);
	r0 = 0;
	while (aux >= n->digits)
	{
		r1 = *aux & mask;
		*aux = (*aux >> d) | (r0 << shift);
		aux--;
		r0 = r1;
	}
	n->used = sizeOfBigInteger(n);
	return r;
}

int divideBigIntegerByDigit(BigInteger n, DIGIT m, DIGIT * r)
{
	size_t p, i;

	if (m == 0)
		return -1;
	*r = 0;
	if ((m == 1) || (sizeOfBigInteger(n) == 0))
		return 1;
	/*
		m is a power of two
	*/
	if (digitIsPowerOfTwo(m, &p))
	{
		BigInteger res;
		if ((res = divideBigIntegerByPowerOfTwo(n, p)) == NULL)
			return -1;
		if (res->used == 0)
			*r = 0;
		else if (res->used == 1)
			*r = res->digits[0];
		else
		{
			freeBigInteger(res);
			return -1;
		}
		freeBigInteger(res);
		return 1;
	}
	/*
		General case
	*/
	DOUBLEDIGIT w = 0;
	DIGIT t;
	for (p = 0; p < n->used; p++)
	{
		i = n->used - p - 1;
		w = (w << BITS_PER_DIGIT) | ((DOUBLEDIGIT) n->digits[i]);
		if (w >= m)
		{
			t = (DIGIT) (w / m);
			w -= ((DOUBLEDIGIT) t) * ((DOUBLEDIGIT) m);
		} 
		else
		{
			t = 0;
		}
		n->digits[i] = (DIGIT) t;
	}
	*r = (DIGIT) w;
	n->used = sizeOfBigInteger(n);
	return 1;
}

BigInteger divideBigIntegerByBigIntegerMenezes(BigInteger n1, BigInteger n2, BigInteger * q)
/*
  Integer division
  Returns r and q such that n1 = q * n2 + r 

  The general case |n1| > |n2| for this function uses the  Multiple-precision 
  division algorithm described in A Handbook Of Applied Cryptography by 
  Alfred J. Menezes, Paul C. van Oorschot and Scott A. Vanstone, pag. 598.

  If the base b is very large, i. e. b = 2^64, the step 3.2 is extremely slow. I wrote
  the function findFirstDigitByBisection to accelerate the process.
*/
{
	BigInteger x, t1, t2;
	x = t1 = t2 = NULL;
	size_t i, n, t;
	int cmp;
	/*
		Error case: n2 == 0
	*/
	if (sizeOfBigInteger(n2) == 0)
		return NULL;
	/*
		Trivial case 1: n1 == 0
	*/
	if (sizeOfBigInteger(n1) == 0)
	{
		*q = initWithLongInt(0,1);
		x = initWithLongInt(0,1);
		return x;
	}
	/*
		Trivial case 2: n1 == n2
	*/
	if ((cmp = compareBigIntegerAbsoluteValues(n1, n2)) == 0)
	{
		*q = initWithLongInt(1,1);
		x = initWithLongInt(0,1);
		return x;
	}
	/*
		Trivial case 3: |n1| < |n2| 
	*/
	if (cmp == -1)
	{
		if (n1->sign == 1)
		{
			x = cloneBigInteger(n1);
			*q = initWithLongInt(0,1);
			return x;
		}
		if (n1->sign == -1)
		{
			x = cloneBigInteger(n2);
			x->sign = 1;
			*q = initWithLongInt(1,n2->sign);
			subtrackBigIntegerAbsoluteValueTo(x,n1);
			return x;		
		}
	}
	/*
		General case: |n1| > |n2| 
		First, we initialize the variable x
	*/ 
	n = sizeOfBigInteger(n1) - 1;
	t = sizeOfBigInteger(n2) - 1;
	if ((x = cloneBigInteger(n1)) == NULL)
		goto final;
	
	/*
		Supose that n1 is positive
	*/
	x->sign = 1;

	/*
		Step 1
	*/
	if ((*q = initBigInteger(n - t + 1)) == NULL)
		goto final;
	(*q)->used = n - t + 1;
	/*
		Step 2
		If it is done like in the book A Handbook Of Applied Cryptography,
		i.e. increasing (*q)->digits[n-t-1] one by one, 
		it is very slow, so we need a method to accelerate the process.
	*/
	if ( compareBigIntegerAbsoluteValuesAtPosition(x, n2, n - t) >= 0)
	{
		if ((t2 = cloneBigInteger(n2)) == NULL)
			goto final; 
		if (! shiftBigIntegerToLeftNumberOfDigits(t2,n-t))
			goto final;
		if ((t1 = cloneBigInteger(t2)) == NULL)
			goto final; 
		(*q)->digits[n-t] = 1;
		while ( compareBigIntegerAbsoluteValuesAtPosition(x,t2,0) == 1)
		{
			(*q)->digits[n-t] *= 2;
			if (! shiftBigIntegerToLeftNumberOfBits(t2, 1))
				goto final;
		}
		if (! findFirstDigitByBisection(x,t1,&((*q)->digits[n-t])))
			goto final;
			if (! subtrackAtPositionToBigInteger(x, (*q)->digits[n-t], n2, n-t))  
            	goto final;
		freeBigInteger(t1);
		freeBigInteger(t2);
	}
	/*
		Step 3
	*/
	for (i = n;i >= t + 1; i--)
	{
		int cmp;
		/*
			Step 3.1
		*/
    	if (x->digits[i] == n2->digits[t])
		{
    		(*q)->digits[i-t-1] = MAX_DIGIT - 1;
    	}
    	else
		{
			DOUBLEDIGIT z;
			z = (DOUBLEDIGIT) (x->digits[i]) << BITS_PER_DIGIT;
			z |= (DOUBLEDIGIT) (x->digits[i - 1]);
			z /= n2->digits[t];
			(*q)->digits[i-t-1] = LOHALF(z);
		}
		/*
			Step 3.2	
		*/
		if ((t1 = clonePartOfBigInteger(x,i,3)) == NULL)
			goto final;
		if ((t2 = clonePartOfBigInteger(n2,t,2)) == NULL)
			goto final;	
		if (! findFirstDigitByBisection(t1,t2, &((*q)->digits[i-t-1])))
			goto final;
		freeBigInteger(t2);
		freeBigInteger(t1);
		/*
			Step 3.3
		*/
		if (! subtrackAtPositionToBigInteger(x,(*q)->digits[i-t-1],n2,i-t-1))
			goto final;
		/*
			Step 3.4
		*/
		if (x->sign == -1)
		{
			if (! addAtPositionToBigInteger(x,1,n2,i-t-1))
				goto final;
			(*q)->digits[i-t-1] -= 1;
			x->sign = 1;
		}			
	}
	if (n1->sign == 1 && n2->sign == 1)
		return x;
	if (n1->sign == -1)
	{
		x->sign = -1;
		if (! addAtPositionToBigInteger(x, (DIGIT)1, n2, 0))
			goto final;
		if (! addDigitToBigInteger(*q, 1, 0))
			goto final;
		(*q)->sign = - n2->sign;
	}
	if(n2->sign == -1)
		(*q)->sign = -1;
	freeBigInteger(t1);
	freeBigInteger(t2);
	return x;

final:
	freeBigInteger(*q);
	freeBigInteger(x);
	freeBigInteger(t1);
	freeBigInteger(t2);
	return NULL;
}

BigInteger divideBigIntegerByBigInteger(BigInteger n1, BigInteger n2, BigInteger * q)
/*
  Integer division
  Returns r and q such that n1 = q * n2 + r 
*/
{
	BigInteger x, y, t1, t2, t3;
	size_t i, n, t;
	DIGIT norm;
	uint8_t neg;
	int cmp;
	neg = (n1->sign == n2->sign) ? 1 : -1;
	x = y = t1 = t2 = t3 = NULL;

	/*
		Error case: n2 == 0
	*/
	if (sizeOfBigInteger(n2) == 0)
		return NULL;
	/*
		Trivial case 1: n1 == 0
	*/
	if (sizeOfBigInteger(n1) == 0)
	{
		*q = initWithLongInt(0,1);
		x = initWithLongInt(0,1);
		return x;
	}
	/*
		Trivial case 2: n1 == n2
	*/
	if ((cmp = compareBigIntegerAbsoluteValues(n1, n2)) == 0)
	{
		*q = initWithLongInt(1,1);
		x = initWithLongInt(0,1);
		return x;
	}
	/*
		Trivial case 3: |n1| < |n2| 
	*/
	if (cmp == -1)
	{
		if (n1->sign == 1)
		{
			x = cloneBigInteger(n1);
			*q = initWithLongInt(0,1);
			return x;
		}
		if (n1->sign == -1)
		{
			x = cloneBigInteger(n2);
			x->sign = 1;
			*q = initWithLongInt(1,n2->sign);
			subtrackBigIntegerAbsoluteValueTo(x,n1);
			return x;		
		}
	}
	/*
		General case: |n1| > |n2| 
		First, we initialize the variables *q, t1, t2, x and y
	*/
		if ((*q = initBigInteger(n1->used + 2)) == NULL)
		return NULL;
	(*q)->used = n1->used + 2;
	if (((t1 = initBigInteger(ALLOCSIZE)) == NULL) ||
	    ((t2 = initBigInteger(ALLOCSIZE)) == NULL) ||
	    ((x = cloneBigInteger(n1)) == NULL) || ((y = cloneBigInteger(n2)) == NULL))
		goto final;

	x->sign = y->sign = 1;
	norm = bitsInBigInteger(y) % BITS_PER_DIGIT;
	if (norm < (BITS_PER_DIGIT - 1))
	{
		norm = BITS_PER_DIGIT - 1 - norm;
		if (! multiplyBigIntegerByPowerOfTwo(x, norm))
			goto final;
		if (! multiplyBigIntegerByPowerOfTwo(y, norm))
			goto final;
	} 
	else
	{
		norm = 0;
	}

	n = x->used - 1;
	t = y->used - 1;
	if (! shiftBigIntegerToLeftNumberOfDigits(y, n - t))
		goto final;

	while (compareBigIntegerAbsoluteValues(x, y) != -1)
	{
		(*q)->digits[n - t]++;
		subtrackBigIntegerAbsoluteValueTo(x,y);
	}
	shiftBigIntegerToRightNumberOfDigits(y, n - t);
	for (i = n; i > t; i--)
	{
		size_t k = i - t - 1;
		if (i > x->used)
			continue;
		if (x->digits[i] == y->digits[t])
		{
			(*q)->digits[k] = MAX_DIGIT;
		} 
		else
		{
			DOUBLEDIGIT z;
			z = (DOUBLEDIGIT) (x->digits[i]) << BITS_PER_DIGIT;
			z |= (DOUBLEDIGIT) (x->digits[i - 1]);
			z /= (DOUBLEDIGIT) (y->digits[t]);
			if (z > (DOUBLEDIGIT) MAX_DIGIT)
				z = MAX_DIGIT;
			(*q)->digits[k] = (DIGIT) z;
		}
		(*q)->digits[k] = (*q)->digits[k] + 1;
		do
		{
			(*q)->digits[k] = (*q)->digits[k] - 1;
			setZeroBigInteger(t1);
			t1->digits[0] = (t == 0) ? 0 : y->digits[t - 1];
			t1->digits[1] = y->digits[t];
			t1->used = 2;
			if (! multiplyBigIntegerByDigit(t1, (*q)->digits[k]))
				goto final;
			t2->digits[0] = (i < 2) ? 0 : x->digits[i - 2];
			t2->digits[1] = (i < 1) ? 0 : x->digits[i - 1];
			t2->digits[2] = x->digits[i];
			t2->used = 3;
		}
		while (compareBigIntegerAbsoluteValues(t1, t2) == 1);

		if (! copyBigIntegerTo(y, t1))
			goto final;
		if (! multiplyBigIntegerByDigit(t1, (*q)->digits[k]))
			goto final;
		
		if (! shiftBigIntegerToLeftNumberOfDigits(t1, k))
			goto final;
		
		if ((t3 = subtrackBigIntegers(x, t1)) == NULL)
			goto final;	
		
		if (! copyBigIntegerTo(t3, x))
			goto final;
		freeBigInteger(t3);

		if (x->sign == -1)
		{
			if (! copyBigIntegerTo(y, t1))
				goto final;
			if (! shiftBigIntegerToLeftNumberOfDigits(t1, k))
				goto final;
			if ((t3 = addBigIntegers(x, t1)) == NULL)
				goto final;
			if (! copyBigIntegerTo(t3, x))
				goto final;
			freeBigInteger(t3);
		}
	}

	shiftBigIntegerToRightNumberOfBits(x, norm);
	if (n1->sign == 1 && n2->sign == 1)
		return x;
	if (n1->sign == -1)
	{
		x->sign = -1;
		if (! addAtPositionToBigInteger(x, (DIGIT)1, n2, 0))
			goto final;
		if (! addDigitToBigInteger(*q, 1, 0))
			goto final;
		(*q)->sign = - n2->sign;
	}
	if(n2->sign == -1)
		(*q)->sign = -1;

	freeBigInteger(t1);
	freeBigInteger(t2);
	freeBigInteger(y);
	return x;

final:
	freeBigInteger(*q);
	freeBigInteger(t1);
	freeBigInteger(t2);
	freeBigInteger(x);
	freeBigInteger(y);
	return NULL;
}









