/**********************************************************************************
* Filename:   test00.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA encryption and decryption algorithm for 
*             educational purposes and should not be used in contexts that 
*             need cryptographically secure implementation
*	    
* License:    This file is free software; you can redistribute it and/or
*             modify it under the terms of:
*
*             The GNU General Public License as published by the Free Software
*             Foundation; either version 2 of the License, or (at your option)
*             any later version.
*
*	      See https://www.gnu.org/licenses/
***********************************************************************************/
#include <mcersa.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	BigInteger n;
	int ret;

	ret = EXIT_FAILURE;
	// if ((n = randomBigIntegerPrime(512)) == NULL)
	//	goto final;
	
	if ((n = randomBigIntegerStrongPrime(2048)) == NULL)
	 	goto final;

	printBigInteger(n);
	printf("Bits: %lu\n",bitsInBigInteger(n));
	ret = EXIT_SUCCESS;

 final:
	freeBigInteger(n);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
