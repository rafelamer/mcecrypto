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
	BigInteger t1, t2, t3;
	t1 = t2 = t3 = NULL;
    int ret;
    DIGIT m;

    ret = EXIT_FAILURE;
    
    if ((t1 = randomPositiveBigIntegerWithBits(176)) == NULL)
		goto final;
	if ((t3 = randomPositiveBigInteger(2)) == NULL)
		goto final;
    if ((t2 = cloneBigInteger(t3)) == NULL)
        goto final;

    m = 1;
    while (compareBigIntegerAbsoluteValues(t3,t1) <= 0)
    {
        if (! multiplyBigIntegerByPowerOfTwo(t3, 12))
            goto final;
        m <<= 12;   
    }
    
    freeBigInteger(t3);

    if ((t3 = cloneBigInteger(t2)) == NULL)
        goto final;

    if (! findFirstDigitByBisection(t1,t2, &m))
        goto final;

    if (! multiplyBigIntegerByDigit(t3,m))
        goto final;

    printf("%d\n",compareBigIntegerAbsoluteValues(t3,t1));
    if (! addAtPositionToBigInteger(t3, (DIGIT)1, t2,(DIGIT)0))
        goto final;

    printf("%d\n",compareBigIntegerAbsoluteValues(t3,t1));
	ret = EXIT_SUCCESS;

 final:
	freeBigInteger(t1);
	freeBigInteger(t2);
    freeBigInteger(t3);
	if (ret == EXIT_FAILURE)
		printf("Error with some operations\n");
	return ret;
}
