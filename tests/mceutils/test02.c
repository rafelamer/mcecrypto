/**************************************************************************************
* Filename:   test02.c
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	unsigned char *text, *ztext, *rtext;
	size_t nbytes, alloc, znbytes, zalloc;
	int ret;

	ret = EXIT_FAILURE;
	text = ztext = rtext = NULL;
	/*
	   Read the file to memory
	 */
	if ((text = readFileBinaryMode("Lion.jpg", &nbytes, &alloc)) == NULL)
		goto final;

	printf("Bytes read: %lu\n", nbytes);

	if ((ztext = zlib_compress_data(text, nbytes, &znbytes, &zalloc)) == NULL)
		goto final;

	printf("Compressed size: %lu. Allocated size: %lu\n", znbytes, zalloc);

	if ((rtext = zlib_uncompress_data(ztext, znbytes, nbytes)) == NULL) {
		printf("Error uncompressig data\n");
		goto final;
	}

	if (memcmp(text, rtext, nbytes) != 0)
		goto final;

	printf("Uncompressed size: %lu. Allocated size: %lu\n", nbytes, zalloc);

	ret = EXIT_SUCCESS;

 final:
	if (text != NULL)
		free(text);
	if (ztext != NULL)
		free(ztext);
	if (rtext != NULL)
		free(rtext);

	if (ret == EXIT_FAILURE)
		printf("Error compressing or decompressing the file\n");
	else
		printf("Compression and decompression OK\n");

	return ret;
}
