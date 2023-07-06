/**************************************************************************************
* Filename:   ecc.c
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
#include <mceecc.h>
#include <stdlib.h>

PrivateECCKey initECCPrivateKey()
{
    PrivateECCKey key;
    if ((key = (PrivateECCKey) malloc(sizeof(private_ecc_key))) == NULL)
		return NULL;
    key->ec = NULL;
    key->private = NULL;
    key->P = NULL;
    return key;
}

PublicECCKey initECCPublicKey()
{
    PublicECCKey key;
    if ((key = (PublicECCKey) malloc(sizeof(public_ecc_key))) == NULL)
		return NULL;
    key->ec = NULL;
    key->P = NULL;
    return key;
}

PrivateECCKey generateECCPrivateKey(EllipticCurve ec)
{
    PrivateECCKey key;
    EllipticCurvePoint G;
    BigInteger p, x, y;
    size_t bits;

    G = NULL;
    p = x = y = NULL;
    if ((key = initECCPrivateKey()) == NULL)
        return NULL;
    key->ec = ec;

    /*
        Generate a random Big Integer as a private key
    */
    bits = bitsInBigInteger(ec->n);
    for(;;)
    {
        if ((p = randomPositiveBigIntegerWithBits(bits)) == NULL)
            goto final;
        if (compareBigIntegerAbsoluteValues(p,ec->n) < 0)
            break;
        freeBigInteger(p);
    }
    key->private = p;
    /*
        Compute the public key
    */
    if ((x = cloneBigInteger(ec->Gx)) == NULL)
        goto final;
    if ((y = cloneBigInteger(ec->Gy)) == NULL)
        goto final;
    if ((G = initEllipticCurvePoint(x, y, ec)) == NULL)
        goto final;

    if((key->P = multiplyEllipticCurvePointByBigInteger(G, key->private, ec)) == NULL)
        goto final;
    freeEllipticCurvePoint(G);
    return key;

final:
    freeBigInteger(x);
    freeBigInteger(y);
    freeEllipticCurvePoint(G);
    return NULL;
}

void printECCPrivateKey(PrivateECCKey key)
{
    printf("The elliptic curve is: %s\n",key->ec->name);
    printf("The private key is:\n");
    printBigInteger(key->private);
    printf("The public key is the point:\n");
    printEllipticCurvePoint(key->P);

}

void printECCPublicKey(PublicECCKey key)
{
    printf("The elliptic curve is: %s\n",key->ec->name);
    printf("The public key is the point:\n");
    printEllipticCurvePoint(key->P);
}

void free_ECC_PrivateKey(PrivateECCKey *key)
{
    if (*key == NULL)
		return;
	freeBigInteger((*key)->private);
	freeEllipticCurvePoint((*key)->P);
    free(*key);
    *key = NULL;
}

void free_ECC_PublicKey(PublicECCKey *key)
{
    if (*key == NULL)
		return;
	freeEllipticCurvePoint((*key)->P);
    free(*key);
    *key = NULL;
}
