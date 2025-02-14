/**************************************************************************************
* Filename:   test12.c
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
#include <argon2.h>
#include <mceutils.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define HMAC_SHA256_DIGEST_LENGTH 32
#define HMAC_SHA512_DIGEST_LENGTH 64

#define WRITEERROR {                    	\
	close(fd);							    \
	unlink("Lion.jpg.aes.asc");			    \
	ret =  ENCRYPTION_AES_WRITE_FILE_ERROR; \
	goto final;			  			        \
}

int main(int argc,char *argv[])
{
	static const unsigned char baesf[] = "-----BEGIN AES ENCRYPTED FILE-----";
	static const unsigned char eaesf[] = "-----END AES ENCRYPTED FILE-----";
	Stack st;
	unsigned char *text;
	size_t nbytes, alloc;
	int ret;
	uint8_t mode;
	int ascii = 0;

	st = NULL;
	ret = ENCRYPTION_AES_ERROR;
	

	/*
	   Initialize the Stack
	 */
	if ((st = stInitStack()) == NULL)
		goto final;
	
	/*
	   Read the file and store the data Stack
	 */
	if ((text = readFileBinaryMode("rfc3279.txt", &nbytes, &alloc)) == NULL)
	{
		ret = ENCRYPTION_AES_FILE_NOT_FOUND;
		goto final;
	}
	stSetDataInStack(st, text, nbytes, alloc);
	text = NULL;

	Stack stplain = NULL;
	if ((stplain = stInitStackWithSize(st->used)) == NULL)
	{	
		printf("Error initialising stplain\n");
		goto final;
	}
	if (! stCopyDataFromStack(stplain,st))
		goto final;
	
	if (stStacksAreEqual(st, stplain))
		printf("Stacks st and stplain are equal\n");

	/*
	   Encrypt the Stack
	 */
	mode = STACKCOMPRESS | STACKHMAC;
	if (ascii)
		mode |= STACKENCODE;

	ret = encryptStackAES(st, "my secret passphrase", 20, mode, KDFARGON2);
	if (ret != ENCRYPTION_AES_OK)
		goto final;


	Stack ste = NULL;
	ste = stInitStackWithSize(st->used);
	if (! stCopyDataFromStack(ste,st))
		goto final;


	if (stStacksAreEqual(st, ste))
		printf("Stacks st and ste are equal\n");

	ret = decryptStackAES(ste, "my secret passphrase", 20, mode, KDFARGON2);
	if (ret != ENCRYPTION_AES_OK) {
		printf("decryptStackAES returned code %d\n",ret);
		goto final;
	}

	if (stStacksAreEqual(ste, stplain))
		printf("Stacks st and stplain are equal\n");
	else
		printf("Stacks st and stplain are not equal\n");		

	/*
	   Write the encrypted file
	 */
	int fd;
	if ((fd = open("rfc3279.txt.aes", O_WRONLY | O_CREAT | O_TRUNC,S_IRUSR | S_IWUSR)) < 0)
	{
		ret = ENCRYPTION_AES_WRITE_FILE_ERROR;
		goto final;
	}
	if (ascii)
	{
		size_t t;
		t = strlen((char *)baesf);
		if (write(fd, baesf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		if (write(fd, st->data, st->used) != st->used)
			WRITEERROR;
		t = strlen((char *)eaesf);
		if (write(fd, eaesf, t) != t)
			WRITEERROR;
		if (write(fd, "\n", 1) != 1)
			WRITEERROR;
		close(fd);
		ret = ENCRYPTION_AES_OK;
		goto final;
	}

	if (write(fd, st->data, st->used) != st->used)
		WRITEERROR;
	close(fd);
	ret = ENCRYPTION_AES_OK;
	
final:
	freeStack(st);
	freeStack(stplain);
	freeStack(ste);
	freeString(text);
	return ret;
}
