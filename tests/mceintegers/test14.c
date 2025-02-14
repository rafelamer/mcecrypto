/**************************************************************************************
* Filename:   test.c
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
#include <stdio.h>

int main(int argc, char **argv)
{

	EllipticCurves ecs = NULL;
	EllipticCurve ec;
	EllipticCurvePoint P, Q, R;
	BigInteger x, y;
	P = Q = R = NULL;
	int ret;
	ret = EXIT_FAILURE;
	
	if ((ecs = initNISTEllipticCurves()) == NULL)
		goto final;
	ec = ecs[SECP192K1];

	if ((x = bigIntegerFromString("5327737752262519347895146425715806011533907106842307429303",10,1)) == NULL)
		goto final;
	if ((y = bigIntegerFromString("3652114576131297913886519071837060826287052773555114435725",10,1)) == NULL)
		goto final;	

	if ((P = initEllipticCurvePoint(x, y, ec)) == NULL)
		goto final;
	x = y = NULL;

	if ((x = bigIntegerFromString("259511326824187019466673252354232922987275875183199213238",10,1)) == NULL)
		goto final;
	if ((y = bigIntegerFromString("1459052858618271245899201989936730578674610812809586112947",10,1)) == NULL)
		goto final;	
	
	if ((Q = initEllipticCurvePoint(x, y, ec)) == NULL)
		goto final;
	x = y = NULL;

	int eq;
	uint8_t error;

    if ((R = addEllipticCurvePoints(P, Q, ec)) == NULL)
        goto final;

    printEllipticCurvePoint(R);

	ret = EXIT_SUCCESS;

 final:
	freeEllipticCurves(ecs);
	freeEllipticCurvePoint(P);
	freeEllipticCurvePoint(Q);
    freeEllipticCurvePoint(R);
	freeBigInteger(x);
	freeBigInteger(y);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
