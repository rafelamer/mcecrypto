/**************************************************************************************
* Filename:   slidingwindow.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2023
* Disclaimer: This code is presented "as is" and it has been written to 
*             implement the RSA encryption and decryption algorithm for 
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

DIGIT nextSlidiwinWindowInBigInteger(BigInteger n, size_t *nbit, uint8_t size, uint8_t *error)
/*
  This function uses the Sliding-window exponentiation algorithm
  described in A Handbook Of Applied Cryptography by Alfred . J. Menezes,
  Paul C. van Oorschot and Scott A. Vanstone, pag. 616. with k = 8
*/
{ 
	if (sizeOfBigInteger(n) == 0)
	{
		*error = 1;
		return (DIGIT) 0;
	}
	if (size > BITS_PER_DIGIT)
	{
		*error = 1;
		return (DIGIT) 0;
	}
	/*
		Example: supose that BITS_PER_DIGIT is 32,
		n2 = 11000000110110111001 00101001100000010100010110001111 01000100010011000000101000101100 in base 2
		and size = 8, we break n as follows
		11 0 0 0 0 0 0 11011011 1001001 0 10011 0 0 0 0 0 0 1010001 0 1100011 11010001 0 0 0 10011 0 0 0 0 0 0 1010001 0 11 0 0
		i. e., every part is 
		0 
		or 
		begins and ends with 1 and has length <= size    
	*/
	uint8_t bit = bitOfBigIntegerAtPosition(n, *nbit - 1); 
	if (bit == 0)
	{
		*error = 0;
		(*nbit)--;
		return (DIGIT) 0;
	}
	size_t ndigit, i;
	DIGIT index, m, mask;
	/*
		Digit that contains the bit at position *nbit
		Examples:
					*nbit = 0 and BITS_PER_DIGIT = 64, then ndigit = 0 (first digit) and i = 0
					*nbit = 64 and BITS_PER_DIGIT = 64, then ndigit = 1 (first digit) and i = 0
					*nbit = 124 and BITS_PER_DIGIT = 64, then ndigit = 2 (second digit) and i = 60
					*nbit = 192 and BITS_PER_DIGIT = 64, then ndigit = 3 (third digit)
	*/
	ndigit = *nbit / BITS_PER_DIGIT;
	i = *nbit % BITS_PER_DIGIT;
	m = n->digits[ndigit];
	if (i >= size)
	{
		(*nbit) -= size;
		mask = MAX_DIGIT >> (BITS_PER_DIGIT - size);
		mask = mask << (i - size);
		index = (DIGIT) ((m & mask) >> (i - size));
	} 
	else
	{
		mask = ((DIGIT) 1 << i) - 1;
		index = m & mask;
		if (ndigit == 0)
			*nbit -= i;
 		else
		{
			*nbit -= size;
			m = n->digits[ndigit - 1];
			mask = ~(((DIGIT) 1 << (BITS_PER_DIGIT - (size - i))) - 1);
			index <<= size - i;
			index |= (m & mask) >> (BITS_PER_DIGIT - (size - i));
		}
	}
	while ((index % 2) == 0)
	{
		index /= 2;
		(*nbit)++;
	}
	return index;
}

void printDecompositionOfBigInteger(BigInteger n, uint8_t size)
{
	size_t nbits = bitsInBigInteger(n);
	uint8_t error = 0;
	DIGIT part;
	while((error == 0) && (nbits > 0))
	{
		part = nextSlidiwinWindowInBigInteger(n, &nbits, size, &error);
		printDigitInBase(part,2);
		printf("  ");
	} 
	if (error == 1)
		printf("\nThere is some error\n");
	printf("\n");
}

