
/**************************************************************************************
* Filename:   test07.c
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
#include <mceutils.h>
#include <string.h>

int main(int argc,char *argv[])
{
	unsigned char text[] = "e65814e438275923984729b v298c29832bn93742bn983742n89 f85550029e723dc7e7";
    unsigned char secret[] = "My secret key";
	unsigned char output[64];
	textToHMAC512(text, strlen(text), secret, strlen(secret), output);
	printBytesInHexadecimal(output,64);
	return 0;
}