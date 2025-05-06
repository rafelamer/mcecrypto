/**************************************************************************************
* Filename:   ecpoints.c
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

void free_elliptic_curve_point(EllipticCurvePoint *P)
{
    if (*P == NULL)
        return;
    freeBigInteger((*P)->x);
    freeBigInteger((*P)->y);
    free(*P);
    *P = NULL;
}

EllipticCurvePoint initEllipticCurvePoint(BigInteger x, BigInteger y, EllipticCurve ec)
{
    EllipticCurvePoint R;
    BigInteger lh, rh;

    if ((rh = rightHandWeierstrassEquation(x, ec)) == NULL)
        goto error;
    if ((lh = modulusOfProductOfBigInteger(y, y, ec->p)) == NULL)
        goto error;
    if (compareBigIntegerAbsoluteValues(lh,rh) != 0)
        goto error;

    if ((R = (EllipticCurvePoint) calloc(1,sizeof(elliptic_curve_point))) == NULL)
        goto error;

    R->is_infinity = 0;
    R->ec = ec->ec;
    R->x = x;
    R->y = y;
    return R;
error:
    freeBigInteger(rh);
    freeBigInteger(lh);
    return NULL;
}

EllipticCurvePoint cloneEllipticCurvePoint(EllipticCurvePoint P)
{
    EllipticCurvePoint R;
    if ((R = (EllipticCurvePoint) calloc(1,sizeof(elliptic_curve_point))) == NULL)
        return NULL;
    R->is_infinity = P->is_infinity;
    R->ec = P->ec;
    if (R->is_infinity)
        return R;
    if ((R->x = cloneBigInteger(P->x)) == NULL)
        goto final;
    if ((R->y = cloneBigInteger(P->y)) == NULL)
        goto final;
    return R;

final:
    freeEllipticCurvePoint(R);
    return NULL;
}

int areEqualEllipticCurvePoints(EllipticCurvePoint P,EllipticCurvePoint Q,BigInteger *n,BigInteger *d,EllipticCurve ec,uint8_t *error)
{
    BigInteger prime;
    *error = 0;
    if (P->ec != Q->ec)
        return 0;
    prime = ec->p;
    if ((*d = subtrackBigIntegers(Q->x,P->x)) == NULL)
        goto final;
    if (! normalizeBigIntegerModulus(d,prime))
		goto final;
    if ((*n = subtrackBigIntegers(Q->y,P->y)) == NULL)
        goto final;
    if (! normalizeBigIntegerModulus(n,prime))
		goto final;
    if (sizeOfBigInteger(*d) > 0)
        return 0;
    if (sizeOfBigInteger(*n) > 0)
        return 0;   
    return 1;
final:
    *error = 1;
    freeBigInteger(*n);
    *n = NULL;
    freeBigInteger(*d);
    *d = NULL;
    return 0;
}

EllipticCurvePoint addEllipticCurvePoints(EllipticCurvePoint P,EllipticCurvePoint Q,EllipticCurve ec)
{
    EllipticCurvePoint R = NULL;
    if (P->ec != Q->ec)
        return NULL;
    if (P->is_infinity)
    { 
        R = cloneEllipticCurvePoint(Q);
        return R;
    }
    if (Q->is_infinity)
    { 
        R = cloneEllipticCurvePoint(P);
        return R;
    }
    BigInteger a, b, binv, m, prime;
    a = b = binv = m = prime = NULL;
    prime = ec->p;
    uint8_t error = 1;
    if ((R = (EllipticCurvePoint) calloc(1,sizeof(elliptic_curve_point))) == NULL)
        goto final;
    R->ec = P->ec;
    R->is_infinity = 0;
    
    if (! areEqualEllipticCurvePoints(P, Q, &a, &b, ec, &error))
    {
        if (error == 1)
            goto final;
        error = 0;
        if(sizeOfBigInteger(b) == 0)
        {
            /*
                P + Q = 0 (point of infinity)
            */
            R->is_infinity = 1;
            goto final; 
        }
        else
        {
            /*
              P = (x1,y1), Q = (x2,y2) with x2 - x1 != 0. Then m = (y2-y1)/(x2-x1) and R = (x3,-y3)
              where
                     x3 = m^2 - x1 - x2
                     y3 = m(x3 - x1) + y1
            */
            if ((binv = modularInverseOfBigInteger(b, prime, &error)) == NULL)
                goto final;
            error = 1;
            freeBigInteger(b);
            if((m = modulusOfProductOfBigInteger(a, binv, prime)) == NULL)
                goto final;
            if ((R->x = multiplyTwoBigIntegers(m, m)) == NULL)
                goto final;
            if (! subtrackAtPositionToBigInteger(R->x, (DIGIT)1, P->x, (DIGIT)0))
                goto final;
            if (! subtrackAtPositionToBigInteger(R->x, (DIGIT)1, Q->x, (DIGIT)0))
                goto final;
            if (! normalizeBigIntegerModulus(&(R->x), prime))
		        goto final;
            if ((b = subtrackBigIntegers(R->x, P->x)) == NULL)
                goto final;
            if (! normalizeBigIntegerModulus(&b, prime))
		        goto final; 
            if ((R->y = multiplyTwoBigIntegers(b, m)) == NULL)
                goto final;
            if (! addAtPositionToBigInteger(R->y, (DIGIT)1, P->y, (DIGIT)0))
                goto final;
            R->y->sign *= -1;
            if (! normalizeBigIntegerModulus(&(R->y), prime))
		        goto final;
            error = 0;
            goto final;
        }
    }
    else
    {
        /*
            P = Q and R = 2P where P = (x1,y1) and the curve is y^2 = x^3 + ax + b
            if y1 = 0, then
                R = 0 (point of infinity)
            else
            m = (3x1^2 + a)/(2y1) and R = (x3,-y3)
            where
                x3 = m^2 - 2x1
                y3 = m(x3 - x1) + y1
        */

        if(sizeOfBigInteger(P->y) == 0)
        {
            /*
                2P = 0 (point of infinity)
            */
             R->is_infinity = 1;
             error = 0;
             goto final; 
        }
        else
        {
            error = 1;
            if ((b = cloneBigInteger(P->y)) == NULL)
                goto final;
            if (!multiplyBigIntegerByDigit(b, (DIGIT)2))
                goto final;
            if ((binv = modularInverseOfBigInteger(b, prime, &error)) == NULL)
                goto final;
            error = 1;
            freeBigInteger(b);
            if ((a = modulusOfProductOfBigInteger(P->x, P->x, prime)) == NULL)
                goto final;
            if (! multiplyBigIntegerByDigit(a, (DIGIT)3))
                goto final;
            if (! addAtPositionToBigInteger(a, (DIGIT)1, ec->a, (DIGIT)0))
                goto final;
            if ((m = modulusOfProductOfBigInteger(a, binv, prime)) == NULL)
                goto final;
            if ((R->x = multiplyTwoBigIntegers(m, m)) == NULL)
                goto final;
            if (! subtrackAtPositionToBigInteger(R->x, (DIGIT)2, P->x, (DIGIT)0))
                goto final;
            if (! normalizeBigIntegerModulus(&(R->x), prime))
		        goto final;
            if ((b = subtrackBigIntegers(R->x, P->x)) == NULL)
                goto final;
            if (! normalizeBigIntegerModulus(&b, prime))
		        goto final; 
            if ((R->y = multiplyTwoBigIntegers(b, m)) == NULL)
                goto final;
            if (! addAtPositionToBigInteger(R->y, (DIGIT)1, P->y, (DIGIT)0))
                goto final;
            R->y->sign *= -1;
            if (! normalizeBigIntegerModulus(&(R->y), prime))
		        goto final;
            error = 0;
            goto final;
        }
    }

final:
    freeBigInteger(a);
    freeBigInteger(b);
    freeBigInteger(binv);
    freeBigInteger(m);
    if (error == 1)
        freeEllipticCurvePoint(R);
    return R;
}

uint8_t doubleEllipticCurvePoint(EllipticCurvePoint P,EllipticCurve ec)
{
    int8_t error = 1;
    BigInteger a, b, binv, m, prime, x, y;
    a = b = binv = m = prime = x = y = NULL;
    prime = ec->p;


    error = 1;
    if ((b = cloneBigInteger(P->y)) == NULL)
        goto final;
    if (! multiplyBigIntegerByDigit(b, (DIGIT)2))
        goto final;
    if ((binv = modularInverseOfBigInteger(b, prime, &error)) == NULL)
        goto final;
    error = 1;
    freeBigInteger(b);
    if ((a = modulusOfProductOfBigInteger(P->x, P->x, prime)) == NULL)
        goto final;
    if (! multiplyBigIntegerByDigit(a, (DIGIT)3))
        goto final;
    if (! addAtPositionToBigInteger(a, (DIGIT)1, ec->a, (DIGIT)0))
        goto final;
    if ((m = modulusOfProductOfBigInteger(a, binv, prime)) == NULL)
        goto final;
    if ((x = multiplyTwoBigIntegers(m, m)) == NULL)
        goto final;
    if (! subtrackAtPositionToBigInteger(x, (DIGIT)1, P->x, (DIGIT)0))
        goto final;
    if (! subtrackAtPositionToBigInteger(x, (DIGIT)1, P->x, (DIGIT)0))
        goto final;    
    if (! normalizeBigIntegerModulus(&x, prime))
		goto final;     
    if ((b = subtrackBigIntegers(x, P->x)) == NULL)
        goto final;
    if (! normalizeBigIntegerModulus(&b, prime))
		goto final; 
    if ((y = multiplyTwoBigIntegers(b, m)) == NULL)
        goto final;
    if (! addAtPositionToBigInteger(y, (DIGIT)1, P->y, (DIGIT)0))
        goto final;
    y->sign *= -1;
    if (! normalizeBigIntegerModulus(&y, prime))
		goto final;
    error = 0;
    goto final;

final:
    freeBigInteger(a);
    freeBigInteger(binv);
    freeBigInteger(m);
    freeBigInteger(b);
    if (error == 1)
    {
        freeBigInteger(x);
        freeBigInteger(y);
        return 0;
    }
    freeBigInteger(P->x);
    P->x = x;
    freeBigInteger(P->y);
    P->y = y;
    if(sizeOfBigInteger(P->y) == 0)
        P->is_infinity = 1;
    return 1;
}

EllipticCurvePoint multiplyEllipticCurvePointByPowerOfTwo(EllipticCurvePoint P,DIGIT power,EllipticCurve ec)
{
    EllipticCurvePoint R, Q;
    size_t k;
    if ((R = cloneEllipticCurvePoint(P)) == NULL)
        return NULL;
    if (power == 0)
        return R;
    for(k=1;k<=power;k++)
    {
        if ((Q = addEllipticCurvePoints(R, R, ec)) == NULL)
        {
            freeEllipticCurvePoint(R);
            return NULL;
        }
        freeEllipticCurvePoint(R);
        R = Q;
    }
    return R;

final:
    freeEllipticCurvePoint(R);
    freeEllipticCurvePoint(Q);
    return NULL;
}

EllipticCurvePoint multiplyEllipticCurvePointByBigInteger(EllipticCurvePoint P,BigInteger n, EllipticCurve ec)
{
    EllipticCurvePoint R;
    if ((R = (EllipticCurvePoint) calloc(1,sizeof(elliptic_curve_point))) == NULL)
        return NULL;
    R->ec = P->ec;
    R->is_infinity = 1;
    if (sizeOfBigInteger(n) == 0 || P->is_infinity)
    {
        R->ec = P->ec;
        R->is_infinity = 1;
        return R;
    }
    /*
		Precomputation: g[i] = i*P mod (n3)  for i = 0,1,2,3,5,7,.....,255
	*/
	EllipticCurvePoint *g;
	size_t i;
	if ((g = (EllipticCurvePoint *)calloc(256,sizeof(EllipticCurvePoint *))) == NULL)
		goto final;
	g[0] = R;
	if ((g[1] = cloneEllipticCurvePoint(P)) == NULL)
		goto final;
	if ((g[2] = addEllipticCurvePoints(g[1],g[1],ec)) == NULL)
		goto final;
	for (i = 1; i < 128; i++)
		if ((g[2*i + 1] = addEllipticCurvePoints(g[2*i - 1],g[2],ec)) == NULL)
			goto final;

    if ((R = (EllipticCurvePoint) calloc(1,sizeof(elliptic_curve_point))) == NULL)
        return NULL;
    R->ec = P->ec;
    R->is_infinity = 1;

    size_t obit;
  	size_t nbits = bitsInBigInteger(n);
	uint8_t error = 0;
	DIGIT part;
    while((error == 0) && (nbits > 0))
	{
        EllipticCurvePoint aux;
        obit = nbits;
		part = nextSlidiwinWindowInBigInteger(n, &nbits, 8, &error);
		if (error == 1)
            goto final;
        if ((aux = multiplyEllipticCurvePointByPowerOfTwo(R,obit - nbits,ec)) == NULL)
		{
			error = 1;
			goto final;
		}
		freeEllipticCurvePoint(R);
        R = aux;
		if (part != 0) 
		{
			if ((aux = addEllipticCurvePoints(R,g[part],ec)) == NULL)
			{
				error = 1;
				goto final;
			}
			freeEllipticCurvePoint(R);
			R = aux;
		}
	}
    if (! normalizeBigIntegerModulus(&(R->x), ec->p))
		goto final;
    if (! normalizeBigIntegerModulus(&(R->y), ec->p))
		goto final; 

final:
	for (i = 0; i < 256; i++)
		freeEllipticCurvePoint(g[i]);	
	free(g);
	if(error == 1)
    {
		freeEllipticCurvePoint(R);
	    R = NULL;
    }
	return R;
}

BigInteger rightHandWeierstrassEquation(BigInteger x,EllipticCurve ec)
{
    BigInteger x2, x3;
    x2 = x3 = NULL;
    if ((x2 = modulusOfProductOfBigInteger(x,x,ec->p)) == NULL)
        goto error;
    if ((x3 = modulusOfProductOfBigInteger(x2,x,ec->p)) == NULL)
        goto error;
    freeBigInteger(x2);

    if ((x2 = modulusOfProductOfBigInteger(x, ec->a, ec->p)) == NULL)
        goto error;
    if (! addAtPositionToBigInteger(x3, (DIGIT)1, x2, (DIGIT)0))
        goto error;
    if (! addAtPositionToBigInteger(x3, (DIGIT)1, ec->b, (DIGIT)0))
        goto error;  
    freeBigInteger(x2);

    if ((x2 = modulusOfBigInteger(x3,ec->p)) == NULL)
        goto error;
    freeBigInteger(x3);
    return x2;
error:
    freeBigInteger(x2);
    freeBigInteger(x3);
    return NULL;
}

EllipticCurvePoint randomEllipticCurvePoint(EllipticCurve ec)
{
    size_t nbits;
    uint8_t ok;
    BigInteger x, y, res, exp;
    x = y = res = exp = NULL;
    EllipticCurvePoint P;

    if ((x = remainderOfBigIntegerDividedByPowerOfTwo(ec->p,2)) == NULL)
        goto error;
    if ((sizeOfBigInteger(x) > 1) || (x->digits[0] != 3))
        goto error;
    freeBigInteger(x);

    nbits = bitsInBigInteger(ec->p);
    if ((x = randomPositiveBigIntegerWithBits(nbits)) == NULL)
        goto error;
    
    ok = 0;
    while (! ok)
    {
        uint8_t els;
        freeBigInteger(y);
        if ((y = rightHandWeierstrassEquation(x,ec)) == NULL)
            goto error;
        ok = LegendreSymbol(y, ec->p, &els) == 1;
        if (els == 1)
            goto error;
        if (! ok)
            if(! addDigitToBigInteger(x, (DIGIT)1, 0))
                goto error;
        
    }
    if ((res = initWithLongInt((DIGIT)1,1)) == NULL)
	    goto error;
    if ((exp = cloneBigInteger(ec->p)) == NULL)
        goto error;
    if (! addAtPositionToBigInteger(exp,(DIGIT)1,res,(DIGIT)0))
        goto error;
    freeBigInteger(res);
    shiftBigIntegerToRightNumberOfBits(exp, (DIGIT)2);
    if ((res = modulusOfExponentialBigIntegers(y, exp, ec->p)) == NULL)
        goto error;
    freeBigInteger(y);
    freeBigInteger(exp);
    y = res;
    res = NULL;
    if ((P = initEllipticCurvePoint(x, y, ec)) == NULL)
        goto error;
    return P;
error:
    freeBigInteger(x);
    freeBigInteger(y);
    freeBigInteger(res);
    freeBigInteger(exp);
    return NULL;
}

static void printOnlyBigIntegerInBase(BigInteger n,DIGIT b)
{
	char *s;
	s = bigIntegerToString(n, b);
	printf("%s", s);
	freeString(s);
}

void  printEllipticCurvePointInBase(EllipticCurvePoint P,DIGIT b)
{
    if (P->is_infinity)
    {
        printf("Point of infinity\n");
        return;
    }
    printf("(");
    printOnlyBigIntegerInBase(P->x, b);
    printf(",");
    printOnlyBigIntegerInBase(P->y, b);
    printf(")\n");
}

void printEllipticCurvePoint(EllipticCurvePoint P)
{
    printEllipticCurvePointInBase(P,(DIGIT) 10);
}

void printEllipticCurve(EllipticCurve ec)
{
    printf("p = ");
    printBigInteger(ec->p);
    printf("a = ");
    printBigInteger(ec->a);
    printf("b = ");
    printBigInteger(ec->b);
    printf("G = (");
    printOnlyBigIntegerInBase(ec->Gx,(DIGIT)10);
    printf(",");
    printOnlyBigIntegerInBase(ec->Gy, (DIGIT)10);
    printf(")\n");
    printf("n = ");
    printBigInteger(ec->n);
}

void printEllipticCurveInBase(EllipticCurve ec,DIGIT b)
{
    printf("p = ");
    printBigIntegerInBase(ec->p, b);
    printf("a = ");
    printBigIntegerInBase(ec->a, b);
    printf("b = ");
    printBigIntegerInBase(ec->b, b);
    printf("G = (");
    printOnlyBigIntegerInBase(ec->Gx, b);
    printf(",");
    printOnlyBigIntegerInBase(ec->Gy, b);
    printf(")\n");
    printf("n = ");
    printBigIntegerInBase(ec->n, b);
}
