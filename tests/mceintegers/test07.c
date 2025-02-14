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
	BigInteger n1, n2, n3, n, m;
	int ret;

	ret = EXIT_FAILURE;
	n1 = n2 = n3 = n = m = NULL;

	if ((n1 = readBigIntegerFromFile("A.txt")) == NULL)
		goto final;
	if ((n2 = readBigIntegerFromFile("B.txt")) == NULL)
		goto final;

	if ((n3 = readBigIntegerFromFile("C.txt")) == NULL)
		goto final;

	if ((m = multiplyTwoBigIntegers(n1,n2)) == NULL)
		goto final;


	if ((n = modulusOfProductOfBigInteger(n1, n2, n3)) == NULL)
	 	goto final;
		
	printf("n1 = ");
	printBigInteger(n1);
	printf("n2 = ");
	printBigInteger(n2);
	
	printf("m = ");
	printBigInteger(m);

	printf("n = ");
	printBigInteger(n);

	ret = EXIT_SUCCESS;

 final:
	freeBigInteger(n1);
	freeBigInteger(n2);
	freeBigInteger(n3);
	freeBigInteger(m);
	freeBigInteger(n);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
