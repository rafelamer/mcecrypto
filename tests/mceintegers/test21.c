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

	BigInteger x, y, p, n;
	x = y = p = n = NULL;
	uint8_t error = 0;
	int result;

	int ret;
	ret = EXIT_FAILURE;
	
	if ((x = bigIntegerFromString("2705605544504090048494726535546600759341439085363030419627988697753323042981690439026363421339079200879239893626964997506024881079043647046363842687480581109",10,1)) == NULL)
		goto final;
	if ((y = bigIntegerFromString("3432398830065304857490950399540696608634717650071652704697231729592771591698828026061279820330727277488648155695740429018560993999858321906287014145557528575",10,1)) == NULL)
		goto final;
	if ((p = bigIntegerFromString("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151",10,1)) == NULL)
		goto final;
		
	if ((n = modulusOfExponentialBigIntegers(x,y,p)) == NULL)
		goto final;

	printBigInteger(n);

	ret = EXIT_SUCCESS;

 final:
	freeBigInteger(x);
	freeBigInteger(y);
	freeBigInteger(p);
	freeBigInteger(n);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
