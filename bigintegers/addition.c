/**************************************************************************************
* Filename:   addition.c
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

int addDigitToBigInteger(BigInteger n, DIGIT m, size_t pos)
/*
  Computes |n| = |n| + m*B^pos
  If necessary expands n
*/
{
	DIGIT t = 0;
	size_t i = pos;
	if (m == 0)
		return 1;
	while (pos >= n->alloc)
		if (! increaseSizeOfBigInteger(n,ALLOCSIZE))
			return 0;
	if (n->used < pos + 1)
		n->used = pos + 1;

	add_two_integers_and_carry(n,i, m, t);
	while (t > 0)
	{
		i++;
		if (i > n->alloc)
			if (! increaseSizeOfBigInteger(n,ALLOCSIZE))
				return 0;
		if (i > n->used)
			n->used++;
		add_two_integers_and_carry(n,i, 0, t);
	}
	return 1;
}

BigInteger addBigIntegerAbsoluteValues(BigInteger n1,BigInteger n2)
{
	BigInteger l, s, n;

	if (compareBigIntegerAbsoluteValues(n1, n2) >= 0)
	{
		l = n1;
		s = n2;
	}
	else
	{
		s = n1;
		l = n2;
	}

	if ((n = cloneBigInteger(l)) == NULL)
		return NULL;

	size_t i;
	DIGIT t = 0;

	for (i = 0; i < s->used; i++)
		add_two_integers_and_carry(n,i,s->digits[i],t);

	while (t > 0)
	{
		if (n->used == n->alloc)
			if (! increaseSizeOfBigInteger(n,ALLOCSIZE))
			{
				freeBigInteger(n);
				return NULL;
			}
		add_two_integers_and_carry(n,i,0,t);
		i++;
		if (i > n->used)
			n->used = i;
	}
	n->sign = 1;
	return n;
}

void subtrackBigIntegerAbsoluteValueTo(BigInteger n1,BigInteger n2)
/*
	Computes n1 = max(0,|n1| - |n2|)
	S'ha d'eliminar
*/
{
	int cmp;
	cmp = compareBigIntegerAbsoluteValues(n1, n2);
	if (cmp <= 0)
	{
		setZeroBigInteger(n1);
		return ;
	}
	size_t i;
	DIGIT t;
	t = 0;
	for (i = 0; i < n2->used; i++)
		subtrack_two_integers_and_carry(n1,i,n2->digits[i], t);
	while (t > 0)
	{
		subtrack_two_integers_and_carry(n1,i,0,t);
		i++;
	}
	n1->used = sizeOfBigInteger(n1);
}

BigInteger subtrackBigIntegerAbsoluteValues(BigInteger n1,BigInteger n2,int8_t *cmp)
{
	BigInteger l, s, n;
	*cmp = compareBigIntegerAbsoluteValues(n1, n2);
	if (*cmp == 0)
		return initBigInteger(ALLOCSIZE);
	else if (*cmp == 1)
	{
		l = n1;
		s = n2;
	}
	else
	{
		s = n1;
		l = n2;
	}
	if ((n = cloneBigInteger(l)) == NULL)
		return NULL;

	size_t i;
	DIGIT t = 0;

	for (i = 0; i < s->used; i++)
		subtrack_two_integers_and_carry(n,i,s->digits[i], t);
	while (t > 0)
	{
		subtrack_two_integers_and_carry(n,i,0,t);
		i++;
	}
	n->used = sizeOfBigInteger(n);
	n->sign = 1;
	return n;
}

BigInteger addBigIntegers(BigInteger n1,BigInteger n2)
{
	int8_t sign;
	BigInteger n;

	testSignAndZero(n1);
	testSignAndZero(n2);
	sign = n1->sign * n2->sign;
	/*
		n1 and n2 with diferent sign
	*/
	if (sign == -1)
	{
		n = subtrackBigIntegerAbsoluteValues(n1,n2,&sign);
		n->sign = n1->sign * sign;
		return n;
	}
	/*
		n1 and n2 with the same sign
	*/
	if (sign == 1)
	{
		n = addBigIntegerAbsoluteValues(n1, n2);
		n->sign = n1->sign;
		return n;
	}
	return NULL;
}

BigInteger subtrackBigIntegers(BigInteger n1,BigInteger n2)
{
	int8_t sign;
	BigInteger n;

	testSignAndZero(n1);
	testSignAndZero(n2);
	sign = n1->sign * n2->sign;
	/*
		n1 and n2 with diferent sign
	*/
	if (sign == -1)
	{
		n = addBigIntegerAbsoluteValues(n1, n2);
		n->sign = n1->sign;
		return n;
	}
	/*
		n1 and n2 with the same sign
	*/
	if (sign == 1)
	{
		n = subtrackBigIntegerAbsoluteValues(n1, n2, &sign);
		n->sign = n1->sign * sign;
		return n;
	}
	return NULL;
}

int addAbsolutValuesAtPositionToBigInteger(BigInteger n,BigInteger z,DIGIT pos)
{
	memset(n->digits + n->used, 0, (n->alloc - n->used) * sizeof(DIGIT));
	if (n->alloc < z->used + pos + 1)
		if (! increaseSizeOfBigInteger(n,z->used + pos + 1 - n->alloc))
			return 0;

	size_t i;
	DIGIT t = 0;

	for (i = 0; i < z->used; i++)
	{
		add_two_integers_and_carry(n,i + pos,z->digits[i],t);
	}
	while (t > 0)
	{
		add_two_integers_and_carry(n,i + pos,0,t);
		i++;
	}
	if (i + pos > n->used)
		n->used = i + pos;
	n->sign = 1;
	return 1;
}

int subtrackAbsolutValuesAtPositionToBigInteger(BigInteger n,BigInteger z,DIGIT pos,int8_t *cmp)
/*
	Computes n = |n1| - |n2 * B^pos|
*/
{
	size_t i;
	DIGIT t = 0;

	cleanUpBigInteger(n);
	cleanUpBigInteger(z);
	*cmp = compareBigIntegerAbsoluteValuesAtPosition(n,z,pos);
	if (*cmp == 0)
	{
		setZeroBigInteger(n);
		return 1;
	}
	if (*cmp == 1)
	{
		for (i = 0; i < pos; i++)
			subtrack_two_integers_and_carry(n,i,0,t);
		for (i = 0; i < z->used; i++)
			subtrack_two_integers_and_carry(n,i,z->digits[i + pos],t);
		for (i = z->used; i < n->used; i++)
			subtrack_two_integers_and_carry(n,i,0,t);
		if (i > n->used)
			n->used = i;
		return 1;
	}
	if (*cmp == -1)
	{
		DIGIT aux;
		if (n->alloc < z->used + pos + 1)
		if (! increaseSizeOfBigInteger(n,z->used + pos + 1 - n->alloc))
			return 0;
		for (i = 0; i < pos; i++)
		{
			aux = n->digits[i];
			subtrack_two_given_integers_and_carry(n,i,0,aux,t);
		}
		for (i = pos; i < n->used; i++)
		{
			aux = n->digits[i];
			subtrack_two_given_integers_and_carry(n,i,z->digits[i - pos],aux,t);
		}
		DIGIT count = max(n->used,pos);
		for (i = count; i < z->used + pos; i++)
			subtrack_two_given_integers_and_carry(n,i,z->digits[i - pos],0,t);
		while (t > 0)
		{
			subtrack_two_given_integers_and_carry(n,i,0,0,t);
			i++;
		}
		if (i > n->used)
			n->used = i;
		n->sign = -1;
	}
	return 1;
}

int addAtPositionToBigInteger(BigInteger n,DIGIT factor,BigInteger z,DIGIT pos)
/*
	Computes n = n + factor * z*B^pos
	Returns:  1 if OK
			  0 if error
*/
{
	int8_t sn, sz, cmp;
	BigInteger aux;

	testSignAndZero(n);
	testSignAndZero(z);
	cleanUpBigInteger(n);
	cleanUpBigInteger(z);
	sn = n->sign;
	sz = z->sign;
	if ((aux = cloneBigInteger(z)) == NULL)
		return 0;
	if (! shiftBigIntegerToLeftNumberOfDigits(aux, pos))
		return 0;
	if (! multiplyBigIntegerByDigit(aux,factor))
	{
		freeBigInteger(aux);
		return 0;
	}
	/*
		n and z with diferent sign
	*/
	if (sn != sz)
	{
		if (! subtrackAbsolutValuesAtPositionToBigInteger(n, aux, 0, &cmp))
			return 0;
		return 1;
	}
	/*
		n and z with the same sign
	*/
	if (sn == sz)
	{
		if (! addAbsolutValuesAtPositionToBigInteger(n, aux, 0))
			return 0;
		return 1;
	}
	return 0;
}

int subtrackAtPositionToBigInteger(BigInteger n,DIGIT factor,BigInteger z,DIGIT pos)
/*
	Computes n = n - factor * z*B^pos
	Returns: 1 if OK
			 0 if error
*/
{
	int8_t sn, sz, cmp;
	BigInteger aux;

	testSignAndZero(n);
	testSignAndZero(z);
	cleanUpBigInteger(n);
	cleanUpBigInteger(z);
	sn = n->sign;
	sz = z->sign;
	if ((aux = cloneBigInteger(z)) == NULL)
		return 0;
	if (! shiftBigIntegerToLeftNumberOfDigits(aux, pos))
		return 0;

	if (! multiplyBigIntegerByDigit(aux,factor))
	{
		freeBigInteger(aux);
		return 0;
	}
	/*
		n and z with diferent sign
	*/
	if (sn != sz)
	{
		if (! addAbsolutValuesAtPositionToBigInteger(n, aux, 0))
			return 0;
		return 1;
	}
	/*
		n and z with the same sign
	*/
	if (sn == sz)
	{
		if (! subtrackAbsolutValuesAtPositionToBigInteger(n, aux, 0, &cmp))
			return 0;
		return 1;
	}
	return 0;
}
