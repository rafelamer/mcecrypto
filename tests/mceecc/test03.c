/**************************************************************************************
* Filename:   test03.c
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
#include <mceecc.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	EllipticCurves ecs = NULL;
	PrivateECCKey key;
    PublicECCKey pkey;
	key = NULL;
    pkey = NULL;
	int ret;
	ret = EXIT_FAILURE;

	if ((ecs = initNISTEllipticCurves()) == NULL)
		goto final;
	
    if ((key = readPrivateECCKeyFromFile("id_ecc.key", ecs)) == NULL)
        goto final;

    if ((pkey = readPublicECCKeyFromFile("id_ecc.pub", ecs)) == NULL)
        goto final;
    
    printECCPrivateKey(key);
    printECCPublicKey(pkey);
    
	ret = EXIT_SUCCESS;

final:
	freePrivateECCKey(key);
    freePublicECCKey(pkey);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
