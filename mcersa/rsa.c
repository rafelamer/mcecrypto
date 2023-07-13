/**************************************************************************************
* Filename:   rsa.c
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
#include <mcersa.h>
#include <stdlib.h>
#include <oaep.h>

PrivateRSAKey initRSAPrivateKey()
{
	PrivateRSAKey rsa;
	rsa = NULL;
	if ((rsa = (PrivateRSAKey) malloc(sizeof(private_rsa_key))) == NULL)
		goto final;
	if ((rsa->pub = (PublicRSAKey) malloc(sizeof(public_rsa_key))) == NULL)
		goto final;
	rsa->pub->n = NULL;
	rsa->pub->ek = NULL;
	rsa->dk = NULL;
	rsa->p = NULL;
	rsa->q = NULL;
	rsa->kp = NULL;
	rsa->kq = NULL;
	rsa->c2 = NULL;
	return rsa;

final:
	freePrivateRSAKey(rsa);
	return NULL;
}

PublicRSAKey initRSAPublicKey()
{
	PublicRSAKey rsa;
	rsa = NULL;

	if ((rsa = (PublicRSAKey) malloc(sizeof(public_rsa_key))) == NULL)
		return NULL;
	rsa->n = NULL;
	rsa->ek = NULL;
	return rsa;
}

PrivateRSAKey generateRSAPrivateKey(size_t bits)
{
	PrivateRSAKey rsa;
	rsa = NULL;
	BigInteger p, q, n, e, d, phi, ek, dk, c2, kp, kq;
	p = q = n = e = d = phi = ek = dk = c2 = kp = kq = NULL;
	int8_t error;

	if (bits < 1024)
		bits = 1024;

	if ((rsa = (PrivateRSAKey)malloc(sizeof(private_rsa_key))) == NULL)
		goto final;
	if ((rsa->pub = (PublicRSAKey)malloc(sizeof(public_rsa_key))) == NULL)
		goto final;
	if ((p = randomBigIntegerStrongPrime(bits / 2)) == NULL)
		goto final;
	if ((q = randomBigIntegerStrongPrime(bits / 2)) == NULL)
		goto final;
	if ((n = multiplyTwoBigIntegers(p, q)) == NULL)
		goto final;
	if ((e = cloneBigInteger(p)) == NULL)
		goto final;
	if ((d = cloneBigInteger(q)) == NULL)
		goto final;
	if (! subtrackDigitToBigInteger(e, (DIGIT)1, 0 ))	// e = p - 1
		goto final;
	if (! subtrackDigitToBigInteger(d, (DIGIT)1,0))	// d = q - 1
		goto final;
	if ((phi = leastCommonMultipleOfBigIntegers(e, d)) == NULL)	// phi = lcm(p - 1,q - 1)
		goto final;

	/*
		Encryption key ek and decription key dk
	*/
	if ((ek = initWithLongInt(65537,1)) == NULL)
		goto final;
	for (;;)
	{
		dk = modularInverseOfBigInteger(ek, phi, &error);
		if (error == 0)
			break;
		if (error == -1)
		{
			if (! addDigitToBigInteger(ek, (DIGIT)1, 0))
				goto final;
		}
		else
			goto final;
	}
	/*
		c2 = q^(-1) mod (p)
	*/
	if ((c2 = modularInverseOfBigInteger(q, p, &error)) == NULL)
		goto final;

	/*
		Numbers kp and kq
	*/
	if ((kp = modulusOfBigInteger(dk, e)) == NULL)
		goto final;
	if ((kq = modulusOfBigInteger(dk, d)) == NULL)
		goto final;

	/*
		Set numbers in rsa
	*/
	freeBigInteger(e);
	e = NULL;
	freeBigInteger(d);
	d = NULL;
	freeBigInteger(phi);
	phi = NULL;
	rsa->pub->n = n;
	rsa->pub->ek = ek;
	rsa->p = p;
	rsa->q = q;
	rsa->dk = dk;
	rsa->kp = kp;
	rsa->kq = kq;
	rsa->c2 = c2;
	return rsa;

final:
	freePrivateRSAKey(rsa);
	freeBigInteger(p);
	freeBigInteger(q);
	freeBigInteger(n);
	freeBigInteger(e);
	freeBigInteger(d);
	freeBigInteger(phi);
	freeBigInteger(ek);
	freeBigInteger(dk);
	freeBigInteger(c2);
	return NULL;
}

void printRSAPrivateKey(PrivateRSAKey r)
{
	printf("n = ");
	printBigInteger(r->pub->n);
	printf("ek = ");
	printBigInteger(r->pub->ek);
	printf("p = ");
	printBigInteger(r->p);
	printf("q = ");
	printBigInteger(r->q);
	printf("dk = ");
	printBigInteger(r->dk);
	printf("dk mod (p - 1) = kp = ");
	printBigInteger(r->kp);
	printf("dk mod (q - 1) = kq = ");
	printBigInteger(r->kq);
	printf("q^(-1) mod (p) = c2 = ");
	printBigInteger(r->c2);
}

void printRSAPublicKey(PublicRSAKey r)
{
	printf("n = ");
	printBigInteger(r->n);
	printf("ek = ");
	printBigInteger(r->ek);
}

void free_RSA_PrivateKey(PrivateRSAKey * r)
{
	if (*r == NULL)
		return;
	freeBigInteger((*r)->p);
	freeBigInteger((*r)->q);
	freeBigInteger((*r)->dk);
	freeBigInteger((*r)->kp);
	freeBigInteger((*r)->kq);
	freeBigInteger((*r)->c2);
	freeBigInteger((*r)->pub->n);
	freeBigInteger((*r)->pub->ek);
	free((*r)->pub);
	free(*r);
	*r = NULL;
}

void free_RSA_PublicKey(PublicRSAKey * r)
{
	if (*r == NULL)
		return;
	freeBigInteger((*r)->n);
	freeBigInteger((*r)->ek);
	free(*r);
	*r = NULL;
}

/*
  Encrypt and decrypt BigIntegers
*/
BigInteger publicEncryptRSA(PublicRSAKey rsa, BigInteger m)
{
	BigInteger c;
	c = NULL;
	if (compareBigIntegerAbsoluteValues(rsa->n, m) <= 0)
		return NULL;
	if ((c = modulusOfExponentialBigIntegers(m, rsa->ek, rsa->n)) == NULL)
		return NULL;
	return c;
}

BigInteger privateDecryptRSA(PrivateRSAKey rsa, BigInteger c)
/*
  m = c^dk mod (n)

  But, it can be computed as follows

  m1 = c^kp mod (p)
  m2 = c^kq mod(q)
  h = (m1 - m2)*c2 mod(p)
  m = m2 + q * h
*/
{
	BigInteger m, m1, m2, h, t;
	m = m1 = m2 = h = t = NULL;
	int r = 0;

	m = m1 = m2 = h = NULL;
	if (compareBigIntegerAbsoluteValues(rsa->pub->n, c) <= 0)
		goto final;

	if ((m1 = modulusOfExponentialBigIntegers(c, rsa->kp, rsa->p)) == NULL)
		goto final;
	if ((m2 = modulusOfExponentialBigIntegers(c, rsa->kq, rsa->q)) == NULL)
		goto final;
	if ((m = subtrackBigIntegers(m1, m2)) == NULL)
		goto final;
	if ((h = modulusOfBigInteger(m, rsa->p)) == NULL)
		goto final;
	freeBigInteger(m);

	if ((t = modulusOfProductOfBigInteger(h, rsa->c2, rsa->p)) == NULL)
		goto final;
	if ((m = multiplyTwoBigIntegers(t, rsa->q)) == NULL)
		goto final;	
	freeBigInteger(t);	
	
	if (! addAbsolutValuesAtPositionToBigInteger(m, m2, 0))
		goto final;		
	r = 1;

final:
	freeBigInteger(m1);
	freeBigInteger(m2);
	freeBigInteger(h);
	freeBigInteger(t);
	if (r == 0)
		freeBigInteger(m);
	return m;
}

BigInteger publicEncryptOAEPRSA(PublicRSAKey rsa, BigInteger m)
{
	BigInteger c, p;
	size_t size, sizeEM, used, nbytes;
	unsigned char *hash, *dg, *EM;

	c = p = NULL;
	hash = EM = NULL;
	size = bytesInBigInteger(rsa->n) - 2 * hLen - 3;
	nbytes = bytesInBigInteger(m);

	if (nbytes > size)
		goto final;

	if ((hash = (unsigned char *)calloc(size, sizeof(unsigned char))) == NULL)
		goto final;
	memset(hash, 0x00, size);
	dg = (unsigned char *)(m->digits);
	memcpy(hash, dg, nbytes);

	sizeEM = size + 2 * hLen + 2;
	if ((EM = (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	if (oaep_encode(hash, size, sizeEM, LABEL_CLIENT, EM) < 0)
		goto final;

	used = (sizeEM + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((p = initBigInteger(used)) == NULL)
		goto final;
	dg = (unsigned char *)(p->digits);
	memcpy(dg, EM, sizeEM);
	p->used = used;

	if ((c = publicEncryptRSA(rsa, p)) == NULL)
		goto final;

final:
	freeString(hash);
	freeBigInteger(p);
	freeString(EM);
	return c;
}

BigInteger privateDecryptOAEPRSA(PrivateRSAKey rsa, BigInteger c)
{
	BigInteger p, m;
	unsigned char *dg, *EM;
	size_t size, sizeEM, used, nbytes;

	p = m = NULL;
	dg = EM = NULL;
	if ((p = privateDecryptRSA(rsa, c)) == NULL)
		goto final;

	size = bytesInBigInteger(rsa->pub->n) - 2 * hLen - 3;
	sizeEM = bytesInBigInteger(rsa->pub->n) - 1;
	if ((EM = (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	dg = (unsigned char *)(p->digits);
	memcpy(EM, dg, sizeEM);

	if (oaep_decode(EM, sizeEM, LABEL_CLIENT) < 0)
		goto final;

	nbytes = size;
	dg = EM + sizeEM - 1;
	while (*dg-- == 0x00)
		nbytes--;
	used = (nbytes + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((m = initBigInteger(used)) == NULL)
		goto final;

	dg = (unsigned char *)(m->digits);
	memcpy(dg, EM + (sizeEM - size), nbytes);
	m->used = used;

final:
	freeBigInteger(p);
	freeString(EM);
	return m;
}

BigInteger privateEncryptOAEPRSA(PrivateRSAKey rsa, BigInteger m)
{
	BigInteger c, p;
	size_t size, sizeEM, used, nbytes;
	unsigned char *hash, *dg, *EM;

	c = p = NULL;
	hash = EM = NULL;
	size = bytesInBigInteger(rsa->pub->n) - 2 * hLen - 3;
	nbytes = bytesInBigInteger(m);

	if (nbytes > size)
		goto final;

	if ((hash = (unsigned char *)calloc(size, sizeof(unsigned char))) == NULL)
		goto final;
	memset(hash, 0x00, size);
	dg = (unsigned char *)(m->digits);
	memcpy(hash, dg, nbytes);

	sizeEM = size + 2 * hLen + 2;
	if ((EM = (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;

	if (oaep_encode(hash, size, sizeEM, LABEL_CLIENT, EM) < 0)
		goto final;

	used = (sizeEM + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;
	if ((p = initBigInteger(used)) == NULL)
		goto final;
	dg = (unsigned char *)(p->digits);
	memcpy(dg, EM, sizeEM);
	p->used = used;

	if ((c = privateDecryptRSA(rsa, p)) == NULL)
		goto final;

final:
	freeString(hash);
	freeString(EM);
	freeBigInteger(p);
	return c;
}

BigInteger publicDecryptOAEPRSA(PublicRSAKey rsa, BigInteger c)
{
	BigInteger p, m;
	unsigned char *dg, *EM;
	size_t size, sizeEM, used, nbytes;

	p = m = NULL;
	dg = EM = NULL;
	if ((p = publicEncryptRSA(rsa, c)) == NULL)
		goto final;

	size = bytesInBigInteger(rsa->n) - 2 * hLen - 3;
	sizeEM = bytesInBigInteger(rsa->n) - 1;
	if ((EM = (unsigned char *)calloc(sizeEM, sizeof(unsigned char))) == NULL)
		goto final;
	dg = (unsigned char *)(p->digits);
	memcpy(EM, dg, sizeEM);

	if (oaep_decode(EM, sizeEM, LABEL_CLIENT) < 0)
		goto final;

	nbytes = size;
	dg = EM + sizeEM - 1;
	while (*dg-- == 0x00)
		nbytes--;
	used = (nbytes + BYTES_PER_DIGIT - 1) / BYTES_PER_DIGIT;

	if ((m = initBigInteger(used)) == NULL)
		goto final;

	dg = (unsigned char *)(m->digits);
	memcpy(dg, EM + (sizeEM - size), nbytes);
	m->used = used;

final:
	freeBigInteger(p);
	freeString(EM);
	return m;
}
