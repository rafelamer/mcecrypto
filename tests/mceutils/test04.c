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
#include <mceintegers.h>
#include <stdio.h>
#include <string.h>
#include <config.h>
#include <sha1.h>

#define BYTE unsigned char

int sha1_test()
{
	BYTE text1[] = { "abc" };
	BYTE text2[] = { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };
	BYTE text3[] = { "aaaaaaaaaa" };
	BYTE hash1[SHA1_DIGEST_SIZE] = { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d };
	BYTE hash2[SHA1_DIGEST_SIZE] = { 0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1 };
	BYTE hash3[SHA1_DIGEST_SIZE] = { 0x34, 0x95, 0xff, 0x69, 0xd3, 0x46, 0x71, 0xd1, 0xe1, 0x5b, 0x33, 0xa6, 0x3c, 0x13, 0x79, 0xfd, 0xed, 0xd3, 0xa3, 0x2a };
	BYTE buf[SHA1_DIGEST_SIZE];
	int idx;
	struct sha1_ctx ctx;
	int pass = 1;

	sha1_init_ctx(&ctx);
	sha1_process_bytes(text1, strlen((char *)text1), &ctx);
	sha1_finish_ctx(&ctx, buf);
	pass = pass && !memcmp(hash1, buf, SHA1_DIGEST_SIZE);

	sha1_init_ctx(&ctx);
	sha1_process_bytes(text2, strlen((char *)text2), &ctx);
	sha1_finish_ctx(&ctx, buf);
	pass = pass && !memcmp(hash2, buf, SHA1_DIGEST_SIZE);

	sha1_init_ctx(&ctx);
	sha1_process_bytes(text3, strlen((char *)text3), &ctx);
	sha1_finish_ctx(&ctx, buf);
	pass = pass && !memcmp(hash3, buf, SHA1_DIGEST_SIZE);

	return (pass);
}

int main()
{
	printf("SHA1 tests: %s\n", sha1_test()? "SUCCEEDED" : "FAILED");

	return (0);
}

