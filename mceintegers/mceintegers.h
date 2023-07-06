/**************************************************************************************
* Filename:   mceintegers.h
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
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#ifndef H_MCEINTEGERS_H_
#define H_MCEINTEGERS_H_ 1

#define DIGIT unsigned long long int
#define ALLOCSIZE 32
#define BYTES_PER_DIGIT 8
#define BITS_PER_DIGIT 64
#define MAX_DIGIT 0xFFFFFFFFFFFFFFFFUL
#define HIGHESTBITMASK 0x8000000000000000UL
#define NISTCURVES 9

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))
typedef __uint128_t DOUBLEDIGIT;
#define DD(n) ((DOUBLEDIGIT)(n))
#define LOHALF(x) ((DIGIT)(x))
#define HIHALF(x) ((DIGIT)((x) >> BITS_PER_DIGIT))
#define freeString(s) free_string((char **)(&(s)))
#define freeBigInteger(n)  free_big_integer(&(n))
#define freeEllipticCurve(c)  free_elliptic_curve(&(c))
#define freeEllipticCurves(c)  free_elliptic_curves(&(c))
#define freeEllipticCurvePoint(p)  free_elliptic_curve_point(&(p))
#define add_two_integers_and_carry(n,i,m,t)   \
{                                             \
	n->digits[i] += t;                        \
	t = (n->digits[i] < t) ? 1 : 0;           \
	n->digits[i] += m;                        \
	if (n->digits[i] < m)                     \
		t++;                                  \
}

#define subtrack_two_integers_and_carry(n,i,m,t)   \
{                                                  \
	n->digits[i] -= t;                             \
	t = (n->digits[i] > MAX_DIGIT - t) ? 1 : 0;    \
	n->digits[i] -= m;                             \
	if (n->digits[i] > MAX_DIGIT - m)              \
		t++;                                       \
}

#define subtrack_two_given_integers_and_carry(n,i,a,b,t) \
{                                                        \
	n->digits[i] = a;                                    \
	n->digits[i] -= t;                                   \
	t = (n->digits[i] > MAX_DIGIT - t) ? 1 : 0;          \
	n->digits[i] -= b;                                   \
	if (n->digits[i] > MAX_DIGIT - b)                    \
		t++;                                             \
}

#define SECP192K1 0
#define SECP192R1 1
#define SECP224K1 2
#define SECP224R1 3
#define SECP256K1 4
#define SECP256R1 5
#define SECP384R1 6
#define SECP521R1 7
#define TESTEC000 8

#define RABINMILLERITERATIONS 25

typedef struct {
	size_t used;
	size_t alloc;
	DIGIT *digits;
	int8_t sign;
} big_integer;
typedef big_integer *BigInteger;

/*
	Creation and basic operations
*/
void free_string(char **s);
int digitIsPowerOfTwo(DIGIT m, size_t * power);
BigInteger initBigInteger(size_t alloc);
BigInteger initWithLongInt(DIGIT m,int8_t s);
BigInteger cloneBigInteger(BigInteger n);
BigInteger clonePartOfBigInteger(BigInteger n,size_t pos,size_t len);
int copyBigIntegerTo(BigInteger n, BigInteger m);
size_t sizeOfBigInteger(BigInteger n);
size_t bitsInBigInteger(BigInteger n);
size_t bytesInBigInteger(BigInteger n);
void cleanUpBigInteger(BigInteger n);
size_t numberOfLowerBitsZeroBigInteger(BigInteger n);
int8_t bitOfBigIntegerAtPosition(BigInteger n,DIGIT pos);
unsigned char byteOfBigIntegerAtPosition(BigInteger n, size_t byte);
int compareBigIntegerAbsoluteValues(BigInteger n1,BigInteger n2);
int compareBigIntegerAbsoluteValuesAtPosition(BigInteger n1,BigInteger n2,DIGIT pos);
int compareBigIntegerAbsoluteValueWithDigitAtPos(BigInteger n, DIGIT m, DIGIT pos);
void setZeroBigInteger(BigInteger n);
int isOneBigInteger(BigInteger n);
int isMinusOneBigInteger(BigInteger n);
void testSignAndZero(BigInteger n);
int increaseSizeOfBigInteger(BigInteger n,size_t s);
void free_big_integer(BigInteger *n);
char *stringFromFile(const char *filename, int8_t *sign);
BigInteger bigIntegerFromString(const char *s, int8_t base, int8_t sign);
BigInteger readBigIntegerFromFile(const char *filename);
int digitIsPowerOfTwo(DIGIT m, size_t * power);
void reverseString(char *s, size_t len);
BigInteger partOfBigInteger(BigInteger n,DIGIT begin,DIGIT length);
char *bigIntegerToString(BigInteger n, DIGIT base);
BigInteger randomPositiveBigInteger(DIGIT ndigits);
BigInteger randomPositiveBigIntegerWithBits(DIGIT bits);
uint8_t randomizeBigInteger(BigInteger n);
void printBigIntegerInDecimal(BigInteger n);
void printBigInteger(BigInteger n);
void printBigIntegerInBase(BigInteger n,DIGIT b);
void printDigitInBase(DIGIT n,DIGIT b);
void printDigitsOfBigInteger(BigInteger n);

/*
	Addition and subtraction
*/
int addDigitToBigInteger(BigInteger n, DIGIT m, size_t pos);
int subtrackDigitToBigInteger(BigInteger n, DIGIT m, size_t pos);
BigInteger addBigIntegerAbsoluteValues(BigInteger n1,BigInteger n2);
void subtrackBigIntegerAbsoluteValueTo(BigInteger n1,BigInteger n2);
BigInteger subtrackBigIntegerAbsoluteValues(BigInteger n1,BigInteger n2,int8_t *cmp);
BigInteger subtrackBigIntegers(BigInteger n1,BigInteger n2);
BigInteger addBigIntegers(BigInteger n1,BigInteger n2);
int addAbsolutValuesAtPositionToBigInteger(BigInteger n,BigInteger z,DIGIT pos);
int subtrackAbsolutValuesAtPositionToBigInteger(BigInteger n,BigInteger z,DIGIT pos,int8_t *cmp);
int addAtPositionToBigInteger(BigInteger n,DIGIT factor,BigInteger z,DIGIT pos);
int subtrackAtPositionToBigInteger(BigInteger n,DIGIT factor,BigInteger z,DIGIT pos);

/*
	Sliding Window
*/
DIGIT nextSlidiwinWindowInBigInteger(BigInteger n, size_t *nbit, uint8_t size, uint8_t *error);
void printDecompositionOfBigInteger(BigInteger n, uint8_t size);

/*
	Multiplication
*/
int multiplyBigIntegerByDigit(BigInteger n, DIGIT m);
BigInteger schoolMultiplyBigIntegers(BigInteger n1, BigInteger n2);
int shiftBigIntegerToLeftNumberOfDigits(BigInteger n, DIGIT ndigits);
int shiftBigIntegerToLeftNumberOfBits(BigInteger n, DIGIT nbits);
int multiplyBigIntegerByPowerOfTwo(BigInteger n, DIGIT power);
BigInteger karatsuba_simple(BigInteger z0,BigInteger z1,DIGIT m,DIGIT  ndigits);
BigInteger karatsuba_general(BigInteger z2, BigInteger z, BigInteger z0, size_t m, size_t ndigits);
BigInteger multiplyByKaratsubaBigIntegers(BigInteger n1,BigInteger n2);
int addMultipleOfBigInteger(BigInteger * n1, BigInteger n2, DIGIT m,int8_t sign);
BigInteger multiplyByToomCookBigIntegers(BigInteger n1, BigInteger n2);
BigInteger multiplyTwoBigIntegers(BigInteger n1, BigInteger n2);
int exponentialBigIntegerToPowerOfTwo(BigInteger * n, size_t power);
BigInteger powerOfBigIntegers(BigInteger n1, BigInteger n2);

/*
	Division
*/
int isBigIntegerDivisibleByDigit(BigInteger n, DIGIT m);
void shiftBigIntegerToRightNumberOfDigits(BigInteger n, DIGIT ndigits);
void shiftBigIntegerToRightNumberOfBits(BigInteger n, DIGIT nbits);
uint8_t findFirstDigitByBisection(BigInteger t1, BigInteger t2,DIGIT *m);
BigInteger divideBigIntegerByPowerOfTwo(BigInteger n, DIGIT power);
BigInteger remainderOfBigIntegerDividedByPowerOfTwo(BigInteger n, DIGIT power);
int divideBigIntegerByDigit(BigInteger n, DIGIT m, DIGIT * r);
BigInteger divideBigIntegerByBigInteger(BigInteger n1, BigInteger n2, BigInteger * q);

/*
	Modular arithmetic
*/
BigInteger modulusOfBigIntegerByPowerOfTwo(BigInteger n, DIGIT power);
BigInteger modulusOfBigInteger(BigInteger n1, BigInteger n2);
BigInteger modulusOfProductOfBigInteger(BigInteger n1, BigInteger n2, BigInteger n3);
int modulusOfExponentialOfBigIntegerToAPowerOfTwo(BigInteger * n, BigInteger n2, DIGIT power);
BigInteger modularInverseOfBigInteger(BigInteger n1, BigInteger n2, int8_t * error);
BigInteger modulusOfExponentialBigIntegers(BigInteger n1,BigInteger n2,BigInteger n3);
int normalizeBigIntegerModulus(BigInteger *n,BigInteger p);
int isModularBigIntegerEqualToMinusOne(BigInteger n,BigInteger p);
int LegendreSymbol(BigInteger n,BigInteger p,uint8_t *error);

/*
	Extended EuclidAlgorithm
*/
BigInteger extendedEuclidAlgorithmBigIntegers(BigInteger n1, BigInteger n2, BigInteger * x, BigInteger * y);
BigInteger leastCommonMultipleOfBigIntegers(BigInteger n1, BigInteger n2);

/*
	Prime numbers
*/
int isBigIntegerDivisibleBySmallPrime(BigInteger n);
int rabinMillerTestForBigInteger(BigInteger n, size_t iterations);
uint8_t isPrimeRabinMillerBigInteger(BigInteger n, size_t iterations);
BigInteger randomBigIntegerPrime(size_t bits);
BigInteger randomBigIntegerStrongPrime(size_t bits);

/*
	Elliptic curves
*/
typedef struct {
	BigInteger p;
	BigInteger a;
	BigInteger b;
	BigInteger Gx;
	BigInteger Gy;
	BigInteger n;
	uint8_t ec;
	char name[32];
	uint8_t *oid;
	uint8_t oidlen;
} elliptic_curve;
typedef elliptic_curve *EllipticCurve;
typedef elliptic_curve **EllipticCurves;

typedef struct {
	BigInteger x;
	BigInteger y;
	uint8_t is_infinity;
	uint8_t ec;
} elliptic_curve_point;
typedef elliptic_curve_point *EllipticCurvePoint;

void free_elliptic_curve(EllipticCurve *ec);
void free_elliptic_curves(EllipticCurves *ecs);
void free_elliptic_curve_point(EllipticCurvePoint *P);
EllipticCurves initNISTEllipticCurves();
EllipticCurvePoint initEllipticCurvePoint(BigInteger x, BigInteger y, EllipticCurve ec);
EllipticCurvePoint cloneEllipticCurvePoint(EllipticCurvePoint P);
int areEqualEllipticCurvePoints(EllipticCurvePoint P,EllipticCurvePoint Q,BigInteger *n,BigInteger *d,EllipticCurve ec,uint8_t *error);
EllipticCurvePoint addEllipticCurvePoints(EllipticCurvePoint P,EllipticCurvePoint Q,EllipticCurve ec);
uint8_t doubleEllipticCurvePoint(EllipticCurvePoint P,EllipticCurve ec);
EllipticCurvePoint multiplyEllipticCurvePointByPowerOfTwo(EllipticCurvePoint P,DIGIT power,EllipticCurve ec);
EllipticCurvePoint multiplyEllipticCurvePointByBigInteger(EllipticCurvePoint P,BigInteger n,EllipticCurve ec);
BigInteger rightHandWeierstrassEquation(BigInteger x,EllipticCurve ec);
EllipticCurvePoint randomEllipticCurvePoint(EllipticCurve ec);
void printEllipticCurvePointInBase(EllipticCurvePoint P,DIGIT b);
void printEllipticCurvePoint(EllipticCurvePoint P);

#endif /* H_MCEINTEGERS_H_*/
