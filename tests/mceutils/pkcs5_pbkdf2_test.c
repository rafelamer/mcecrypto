#include <mce/mcersa.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef KEK_KEY_LEN
#define KEK_KEY_LEN 384
#endif

#ifndef ITERATION
#define ITERATION 10
#endif

int main(int argc, char *argv[])
{
	char *p1, *p2;
	unsigned char bs[18];
	int ret;
	FILE *fp;

	p1 = p2 = NULL;
	ret = EXIT_FAILURE;
	p1 = getPassword("Enter the encryption password: ");
	p2 = getPassword("Verifying. Enter the encryption password again: ");

	if (strlen(p1) != strlen(p2))
		goto final;
	if (memcmp(p1, p2, strlen(p1)) != 0)
		goto final;
	freeString(p2);
	/*
	   Now create a key and a iv from the password and a random salt
	 */
	unsigned char *out;
	size_t out64;
	unsigned char *salt;

	out = salt = NULL;
	if ((out = malloc(KEK_KEY_LEN * sizeof(unsigned char))) == NULL)
		goto final;
	if ((fp = fopen("/dev/urandom", "r")) == NULL)
		goto final;
	if (fread(bs, sizeof(unsigned char), 18, fp) != 18)
		goto final;
	if ((salt = b64_encode(bs, 18, &out64)) == NULL)
		goto final;
	printf("Salt: %s\n", salt);

	if (pkcs5_pbkdf2
	    (p1, strlen(p1), salt, strlen((char *)salt), out, KEK_KEY_LEN,
	     ITERATION) != 0)
		goto final;
	freeString(salt);
	freeString(p1);

	size_t i;
	printf("out: ");
	for (i = 0; i < KEK_KEY_LEN; i++)
		printf("%02x", out[i]);
	printf("\n");

	freeString(out);
	ret = EXIT_SUCCESS;

 final:
	freeString(p1);
	freeString(p2);
	freeString(salt);
	freeString(out);
	if (ret == EXIT_FAILURE)
		printf("Verify failure. Exiting\n");
	return 0;
}
