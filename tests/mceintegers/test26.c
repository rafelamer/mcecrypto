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
	BigInteger n1, n2;
	n1 = n2 = NULL;
	int ret;

	ret = EXIT_FAILURE;
	
	if ((n1 = bigIntegerFromString("4998234729384729834792837492837492837492387427893647523471",10,1)) == NULL)
		goto final;
	
	if ((n2 = initBigIntegerFromBinaryData(41, (unsigned char *)(n1->digits), 24)) == NULL)
		goto final;


	printf("Bits: %lu\n",bitsInBigInteger(n1));
	printBigIntegerInBase(n1,2);

	printf("\nBits: %lu\n",bitsInBigInteger(n2));
	printBigIntegerInBase(n2,2);
	//if ((n2 = bigIntegerFromString("5003",10,1)) == NULL)
	//	goto final;

    
	ret = EXIT_SUCCESS;

 final:
	freeBigInteger(n1);
	freeBigInteger(n2);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
