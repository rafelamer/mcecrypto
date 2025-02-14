/**************************************************************************************
* Filename:   test13.c
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
#include <zlib.h>

int main(int argc, char *argv[])
{
	unsigned char *text, *ztext, *rtext;
	size_t nbytes, alloc, znbytes, rnbytes, zalloc;
	int ret;

	ret = EXIT_FAILURE;
	text = ztext = rtext = NULL;
	/*
	   Read the file to memory
	 */
	if ((text = readFileBinaryMode("Lion.jpg", &nbytes, &alloc)) == NULL)
		goto final;

	printf("Bytes read: %lu\n", nbytes);

    z_stream defstream;
    defstream.zalloc = Z_NULL;
    defstream.zfree = Z_NULL;
    defstream.opaque = Z_NULL;
    defstream.avail_in = nbytes;
    defstream.next_in = (Bytef *)text;
    defstream.avail_out = (uInt)(nbytes);
    if ((ztext = (unsigned char *)calloc(nbytes,sizeof(unsigned char))) == NULL)
    {
        printf("Error calloc 1\n");
        exit(0);
    }
    defstream.next_out = (Bytef *)ztext;

    deflateInit(&defstream, Z_BEST_COMPRESSION);
    deflate(&defstream, Z_FINISH);
    deflateEnd(&defstream);
    znbytes = defstream.total_out;
	printf("Compressed size: %lu.\n", znbytes);

    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = (uInt)znbytes;
    infstream.next_in = (Bytef *)ztext;
    if ((rtext = (unsigned char *)calloc(nbytes,sizeof(unsigned char))) == NULL)
    {
        printf("Error calloc 2\n");
        exit(0);
    }

    infstream.avail_out = (uInt)nbytes;
    infstream.next_out = (Bytef *)rtext;
    inflateInit(&infstream);
    inflate(&infstream, Z_NO_FLUSH);
    inflateEnd(&infstream);
    rnbytes = infstream.total_out;
    printf("Unompressed size: %lu.\n", rnbytes);

	if (nbytes != rnbytes)
		goto final;

	if (memcmp(text, rtext, nbytes) != 0)
		goto final;

	printf("Uncompressed size: %lu", nbytes);

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
