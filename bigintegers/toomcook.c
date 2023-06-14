/**************************************************************************************
* Filename:   toomcook.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018
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
#include <stdlib.h>

BigInteger multiplyByToomCookBigIntegers(BigInteger n1, BigInteger n2)
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
	m = l->used / 3;
	if (3*m < l->used)
	 	m += 1;
	if (s->used <= 2*m)
		return multiplyByKaratsubaBigIntegers(l,s);

	/*
    Second recursive case

		See https://en.wikipedia.org/wiki/Toom-Cook_multiplication

		Split the numbers
	*/
	BigInteger x2, x1, x0, y2, y1, y0;
  	x0 = partOfBigInteger(l, 0, m);
	x1 = partOfBigInteger(l, m, m);
	x2 = partOfBigInteger(l, 2*m, l->used - 2*m);
	y0 = partOfBigInteger(s, 0, m);
	y1 = partOfBigInteger(s, m, m);
	y2 = partOfBigInteger(s, 2*m, s->used - 2*m);

	/*
		Evaluation of numbers p1, pm1 and pm2
		Remember thats p0 = x0 and pinf = x2
	*/
	BigInteger p, p1, pm1, pm2;
	p = p1 = pm1 = pm2 = NULL;
	p = addBigIntegers(x0,x2);
	p1 = addBigIntegers(p,x1);
	pm1 = subtrackBigIntegers(p,x1);
	pm2 = addBigIntegers(pm1,x2);
	multiplyBigIntegerByDigit(pm2,2);
	addMultipleOfBigInteger(&pm2,x0,1,-1);
	freeBigInteger(p);

	/*
		Evaluation of numbers q1, qm1 and qm2
		Remember thats q0 = y0 and qinf = y2
	*/
	BigInteger q1, qm1, qm2;
	q1 = qm1 = qm2 = NULL;
	p = addBigIntegers(y0,y2);
	q1 = addBigIntegers(p,y1);
	qm1 = subtrackBigIntegers(p,y1);
	qm2 = addBigIntegers(qm1,y2);
	multiplyBigIntegerByDigit(qm2,2);
	addMultipleOfBigInteger(&qm2,y0,1,-1);
	freeBigInteger(p);

	/*
		Pointwise multiplication
	*/
	BigInteger r0, r1, rm1, rm2, rinf;
	r0 = r1 = rm1 = rm2 = rinf = NULL;
	r0 = multiplyTwoBigIntegers(x0,y0);
	r1 = multiplyTwoBigIntegers(p1,q1);
	rm1 = multiplyTwoBigIntegers(pm1,qm1);
	rm2 = multiplyTwoBigIntegers(pm2,qm2);
	rinf = multiplyTwoBigIntegers(x2,y2);
	freeBigInteger(p1);
	freeBigInteger(pm1);
	freeBigInteger(pm2);
	freeBigInteger(q1);
	freeBigInteger(qm1);
	freeBigInteger(qm2);
	/*
		Interpolation
		Remember that s0 = r0 and s4 = rinf

		You have to modify the file from here !!!
	*/
	BigInteger s1, s2, s3;
	DIGIT remainder;
	s1 = s2 = s3 = NULL;
	s3 = subtrackBigIntegers(rm2,r1);
	divideBigIntegerByDigit(s3,3,&remainder);
	s1 = subtrackBigIntegers(r1,rm1);
	divideBigIntegerByDigit(s1,2,&remainder);
	s2 = subtrackBigIntegers(rm1,r0);
	s3->sign *= -1;
	addMultipleOfBigInteger(&s3,s2,1,1);
	divideBigIntegerByDigit(s3,2,&remainder);
	addMultipleOfBigInteger(&s3,rinf,2,1);
	addMultipleOfBigInteger(&s2,s1,1,1);
	addMultipleOfBigInteger(&s2,rinf,1,-1);
	addMultipleOfBigInteger(&s1,s3,1,-1);
	freeBigInteger(r1);
	freeBigInteger(rm1);
	freeBigInteger(rm2);

	/*
		Recomposition
	*/
	shiftBigIntegerToLeftNumberOfDigits(s1,m);
	addMultipleOfBigInteger(&s1,r0,1,1);
	freeBigInteger(r0);
	shiftBigIntegerToLeftNumberOfDigits(s2,2*m);
	addMultipleOfBigInteger(&s2,s1,1,1);
	freeBigInteger(s1);
	shiftBigIntegerToLeftNumberOfDigits(s3,3*m);
	addMultipleOfBigInteger(&s3,s2,1,1);
	freeBigInteger(s2);
	shiftBigIntegerToLeftNumberOfDigits(rinf,4*m);
	addMultipleOfBigInteger(&rinf,s3,1,1);
	freeBigInteger(s3);

	rinf->sign = l->sign * s->sign;
	return rinf;
}

BigInteger multiplyTwoBigIntegers(BigInteger n1, BigInteger n2)
{
	return multiplyByToomCookBigIntegers(n1, n2);
}

