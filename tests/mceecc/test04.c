/**************************************************************************************
* Filename:   test04.c
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
	int ret;
    char *outfile;
    outfile = NULL;
	ret = EXIT_FAILURE;

	if ((ecs = initNISTEllipticCurves()) == NULL)
		goto final;

    if (signFileWithECC("Crime-and-Punishment.txt", &outfile, "id_ecc.key", ecs, 1) != SIGNATURE_ECC_OK)
        goto final;

	ret = EXIT_SUCCESS;

final:
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
