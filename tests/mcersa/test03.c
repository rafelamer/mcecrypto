/**********************************************************************************
* Filename:   test01.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA and ECC encryption and decryption algorithm for 
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

int main(int argc, char **argv)
{
	PublicRSAKey key;
	key = NULL;
	int ret;
	ret = EXIT_FAILURE;
	if ((key = readPublicRSAKeyFromFile("ec_rsa.pub")) == NULL)
        goto final;
	printRSAPublicKey(key);
	ret = EXIT_SUCCESS;

 final:
	freePublicRSAKey(key);
	if (ret == EXIT_FAILURE)
		printf("Error generating the keys\n");
	return ret;
}
