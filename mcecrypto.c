/**************************************************************************************
* Filename:   mcecrypto.c
* Author:     Rafel Amer (rafel.amer AT upc.edu)
* Copyright:  Rafel Amer 2018-2025
* Disclaimer: This code is presented "as is" and it has been written to
*             implement the RSA and ECC encryption and decryption algorithm for
*             educational purposes and should not be used in contexts that
*             need cryptographically secure implementation
*
* License:    This software is free software; you can redistribute it and/or
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
#include <mcecrypto.h>
#include <stdlib.h>
#include <cmdline.h>

int main(int argc, char **argv)
{
	int ret;
	static struct gengetopt_args_info ai;
	static char keyRSAName[] = "id_rsa";
	static char keyECCName[] = "id_ecc";

	ret = EXIT_FAILURE;
	if (cmdline_parser(argc, argv, &ai) != 0) {
		fprintf(stderr, "Error reading the command line parameters\n");
		goto final;
	}
	if (ai.help_given) {
		printf("%s\n", gengetopt_args_info_usage);
		printf("%s\n", *gengetopt_args_info_help);
		ret = EXIT_SUCCESS;
		goto final;
	}
	/*



		List elliptic curves
	*/
	if (ai.list_flag)
	{
		size_t i;
		EllipticCurves ecs = NULL;

		if (ai.infile_given || ai.outfile_given || ai.encrypt_given || ai.decrypt_given ||
		    ai.ascii_given || ai.keyfile_given || ai.keytype_given || ai.sign_flag ||
		    ai.verify_flag || ai.ec_given || ai.bits_given || ai.noaes_flag)
		{
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		if ((ecs = initNISTEllipticCurves()) == NULL)
		{
			fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
			goto final;
		}
		for (i = 0;i < NISTCURVES - 1;i++)
			printf("%s\n",ecs[i]->name);
		ret = EXIT_SUCCESS;
		freeEllipticCurves(ecs);
		goto final;
	}
	/*









	   Process the different options
	   1. Generate a pair of public and private RSA or ECC key
	 */
	if (ai.genkey_flag) {
		int bits;
		char *name;

		if (ai.infile_given || ai.encrypt_given || ai.decrypt_given ||
		    ai.ascii_given || ai.keyfile_given || ai.sign_flag ||
		    ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		if (ai.bits_given)
		{
			bits = ai.bits_arg;
			if (bits > 8192)
				bits = 8192;

			if (ai.outfile_given)
				name = ai.outfile_arg;
			else
				name = keyRSAName;
			if (generateAndSavePairRSAKeys(bits,name,!ai.noaes_flag))
			{
				printf("Public private RSA key pair generated successfully\n");
				ret = EXIT_SUCCESS;
			}
			else
			{
				fprintf(stderr,"Error generating a private public RSA key pair\n");
			}
		}
		else if (ai.ec_given)
		{
			EllipticCurves ecs = NULL;
			EllipticCurve ec;
			if ((ecs = initNISTEllipticCurves()) == NULL)
			{
				fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
				goto final;
			}
			if ((ec = findEllipticCurveFronName(ai.ec_arg, ecs)) == NULL)
			{
				fprintf(stderr,"Error in the name of the elliptic curve\n");
				goto final;
			}
			if (ai.outfile_given)
				name = ai.outfile_arg;
			else
				name = keyECCName;

			if (generateAndSavePairECCKeys(name, ec, !ai.noaes_flag))
			{
				printf("Public private ECC key pair generated successfully\n");
				ret = EXIT_SUCCESS;
			}
			else
			{
				fprintf(stderr,"Error generating a private public ECC key pair\n");
			}
			freeEllipticCurves(ecs);
		}
		else
		{
			fprintf(stderr,"You must supply the number of bits --bits or the elliptic curve --ec\n");
		}
		goto final;
	}
	else if (ai.ec_given)
	{
		EllipticCurves ecs = NULL;
		EllipticCurve ec;
		if ((ecs = initNISTEllipticCurves()) == NULL)
		{
			fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
			goto final;
		}
		if ((ec = findEllipticCurveFronName(ai.ec_arg, ecs)) == NULL)
		{
			fprintf(stderr,"Error in the name of the elliptic curve\n");
			goto final;
		}
		printEllipticCurve(ec);
		ret = EXIT_SUCCESS;
		goto final;
	}
    /*









	   2.1 Encrypts a file with the symetric algorithm AES
	 */
	if (ai.encrypt_flag && (!ai.keyfile_given)) {
		char *infile, *outfile;
		int r;

		if (!ai.infile_given)
		{
			fprintf(stderr,"You have to supply the name of the input file to encrypt: --infile=filename\n");
			goto final;
		}

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag || ai.sign_flag || ai.verify_flag || ai.ec_given)
		{
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}

		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		r = encryptFileWithAES(infile, &outfile, KDFARGON2, ai.ascii_flag);
		if (r == ENCRYPTION_AES_OK)
		{
			printf("File encrypted successfuly. Encrypted file is %s\n",outfile);
			ret = EXIT_SUCCESS;
		} else if (r == ENCRYPTION_AES_FILE_NOT_FOUND)
			fprintf(stderr,"The file %s was not found or can not be read\n",infile);
		else if (r == ENCRYPTION_AES_WRONG_PASSWORD)
			fprintf(stderr,"The two passphrases does not coincide. Try again\n");
		else if (r == ENCRYPTION_AES_ERROR)
			fprintf(stderr,"Some error ocurred while encrypting the file %s\n",infile);
		else if (r == ENCRYPTION_AES_WRITE_FILE_ERROR)
			fprintf(stderr, "Error opening or writing the outfile %s\n",outfile);
		else if (r == ENCRYPTION_AES_PASSWORD_SHORT)
			fprintf(stderr,"Passphrase too short. It must be at least 10 characters long\n");
		else if (r == ZLIB_UNCOMPRESS_ERROR)
			fprintf(stderr,"Passphrase too short. It must be at least 10 characters long\n");

		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}
	/*









	   2.2 Decrypts a file with the symetric algorithm AES
	 */
	if (ai.decrypt_flag && (!ai.keyfile_given))
	{
		char *infile, *outfile;
		infile = outfile = NULL;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,"You have to supply the name of the input file: --infile=filename\n");
			goto final;
		}

		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag || ai.sign_flag || ai.verify_flag || ai.show_flag || ai.ec_given)
		{
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		if (! ai.outfile_given)
		{
			printf("You must supply the name of the output file: --outfile=filename\n");
			goto final;
		}
		outfile = ai.outfile_arg;
		r = decryptFileWithAES(infile, outfile,KDFARGON2);
		if (r == ENCRYPTION_AES_OK)
		{
			printf("File decrypted successfuly. Decrypted file is %s\n",outfile);
			ret = EXIT_SUCCESS;
		} else if (r == ENCRYPTION_AES_FILE_NOT_FOUND)
			fprintf(stderr,"The file %s was not found or can not be read",infile);
		else if (r == ENCRYPTION_AES_ERROR)
			fprintf(stderr,"Some error ocurred while decrypting the file %s\n",infile);
		else if (r == ENCRYPTION_AES_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",outfile);
		else if (r == ENCRYPTION_AES_WRONG_PASSWORD)
			fprintf(stderr,"You have entered a wrong passphrase\n");
		else if (r ==  ENCRYPTION_AES_WRITE_FILE_ERROR)
			fprintf(stderr,"Error writing the output file\n");
		goto final;
	}
	/*









		3. Show a public or private RSA or ECC key
	*/
	if(ai.show_flag && ai.keyfile_given)
	{
		char *keyfile;
		keyfile = ai.keyfile_arg;
		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag || ai.ec_given || ai.encrypt_flag || ai.sign_flag || ai.ascii_flag)
		{
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		if (memcmp(ai.keytype_arg,"rsaprivate",10) == 0)
		{
			PrivateRSAKey rsa;
			if ((rsa = readPrivateRSAKeyFromFile(keyfile)) != NULL)
			{
				printf("The contents of the private RSA key are\n");
				printRSAPrivateKey(rsa);
				freePrivateRSAKey(rsa);
				ret = EXIT_SUCCESS;
				goto final;
			}
			if ((rsa = readEncryptedPrivateRSAKeyFromFile(keyfile)) != NULL)
			{
				printf("The contents of the private RSA key are\n");
				printRSAPrivateKey(rsa);
				freePrivateRSAKey(rsa);
				ret = EXIT_SUCCESS;
				goto final;
			}
		}
		else if (memcmp(ai.keytype_arg,"rsapublic",9) == 0)
		{
			PublicRSAKey rsa;
			if ((rsa = readPublicRSAKeyFromFile(keyfile)) != NULL)
			{
				printf("The contents of the public RSA key are\n");
				printRSAPublicKey(rsa);
				freePublicRSAKey(rsa);
				ret = EXIT_SUCCESS;
				goto final;
			}
		}
		else if (memcmp(ai.keytype_arg,"eccprivate",10) == 0)
		{
			PrivateECCKey key;
			EllipticCurves ecs = NULL;
			if ((ecs = initNISTEllipticCurves()) == NULL)
			{
				fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
				goto final;
			}
			if ((key = readPrivateECCKeyFromFile(keyfile, ecs)) != NULL)
			{
				printf("The contents of the private ECC key are\n");
				printECCPrivateKey(key);
				freePrivateECCKey(key);
				freeEllipticCurves(ecs);
				ret = EXIT_SUCCESS;
				goto final;
			}
			if ((key = readEncryptedPrivateECCKeyFromFile(keyfile, ecs)) != NULL)
			{
				printf("The contents of the private ECC key are\n");
				printECCPrivateKey(key);
				freePrivateECCKey(key);
				freeEllipticCurves(ecs);
				ret = EXIT_SUCCESS;
				goto final;
			}
			freeEllipticCurves(ecs);
		}
		else if (memcmp(ai.keytype_arg,"eccpublic",9) == 0)
		{
			PublicECCKey key;
			EllipticCurves ecs = NULL;
			if ((ecs = initNISTEllipticCurves()) == NULL)
			{
				fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
				goto final;
			}
			if ((key = readPublicECCKeyFromFile(keyfile, ecs)) != NULL)
			{
				printf("The contents of the public ECC key are\n");
				printECCPublicKey(key);
				freePublicECCKey(key);
				freeEllipticCurves(ecs);
				ret = EXIT_SUCCESS;
				goto final;
			}
			freeEllipticCurves(ecs);
		}
		printf("I can't read the public or private key in %s or the keytype %s is not correct\n",keyfile,ai.keytype_arg);
		goto final;
	}
	/*









		4. Encrypts a file using an RSA or ECC public key
	*/
	 if (ai.encrypt_flag && ai.keyfile_given) {
		char *infile, *outfile, *keyfile;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,"You have to write the name of the input file: --infile=filename\n");
			goto final;
		}
		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.sign_flag || ai.verify_flag || ai.show_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		keyfile = ai.keyfile_arg;
		/*
		  4.1 RSA public key
		*/
		if (memcmp(ai.keytype_arg,"rsapublic",9) == 0) {
			r = encryptFileWithRSA(infile, &outfile, keyfile, ai.ascii_flag);
			if (r == ENCRYPTION_RSA_OK) {
				printf("File encrypted successfuly. Encrypted file is %s\n",outfile);
				ret = EXIT_SUCCESS;
			} else if (r == ENCRYPTION_RSA_FILE_NOT_FOUND)
				fprintf(stderr,"The file %s was not found or can not be read",infile);
			else if (r == ENCRYPTION_RSA_ERROR)
				fprintf(stderr,"Some error ocurred while encrypting the file %s\n",infile);
			else if (r == ENCRYPTION_RSA_OPEN_FILE_ERROR)
				fprintf(stderr, "Error opening the outfile %s\n",outfile);
			else if (r == ENCRYPTION_RSA_WRITE_FILE_ERROR)
					fprintf(stderr, "Error writing the outfile %s\n",outfile);
			else if (r == ENCRYPTION_RSA_PUBLIC_KEY_ERROR)
				fprintf(stderr,"Error opening the public key file %s\n",keyfile);
		}
		/*
			4.2 ECC public key
		*/

		if (memcmp(ai.keytype_arg,"eccpublic",9) == 0) {
			EllipticCurves ecs = NULL;
			if ((ecs = initNISTEllipticCurves()) == NULL) {
				fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
				goto final;
			}
			r = encryptFileWithECC(infile, &outfile, keyfile, ecs, ai.ascii_flag);
			if (r == ENCRYPTION_ECC_OK) {
				printf("File encrypted successfuly. Encrypted file is %s\n",outfile);
				ret = EXIT_SUCCESS;
			} else if (r == ENCRYPTION_ECC_FILE_NOT_FOUND)
				fprintf(stderr,"The file %s was not found or can not be read",infile);
			else if (r == ENCRYPTION_ECC_ERROR)
				fprintf(stderr,"Some error ocurred while encrypting the file %s\n",infile);
			else if (r == ENCRYPTION_ECC_OPEN_FILE_ERROR)
				fprintf(stderr, "Error opening the outfile %s\n",outfile);
			else if (r == ENCRYPTION_ECC_WRITE_FILE_ERROR)
				fprintf(stderr, "Error writing the outfile %s\n",outfile);
			else if (r == ENCRYPTION_ECC_PUBLIC_KEY_ERROR)
				fprintf(stderr,"Error opening the public key file %s\n",keyfile);
		}
		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}
	/*









		5. Decrypts a file using an RSA or ECC private key
	*/
	if (ai.decrypt_flag && ai.keyfile_given) {
		char *infile, *keyfile;
		int r;

		if (!ai.infile_given) {
			fprintf(stderr,"You have to write the name of the input file: --infile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.sign_flag || ai.verify_flag || ai.show_flag || ai.outfile_given) {
			fprintf(stderr, "Wrong combination of parameters. You don't have to specify --outfile\n");
			goto final;
		}
		infile = ai.infile_arg;
		keyfile = ai.keyfile_arg;
		/*
		  5.1 RSA private key
		*/
		if (memcmp(ai.keytype_arg,"rsaprivate",10) == 0) {
			r = decryptFileWithRSA(infile, keyfile);
			if (r == ENCRYPTION_RSA_OK) {
				printf ("File decrypted successfuly.\n");
				ret = EXIT_SUCCESS;
			} else if (r == ENCRYPTION_RSA_FILE_NOT_FOUND)
				fprintf(stderr,"The file %s was not found or can not be read",infile);
			else if (r == ENCRYPTION_RSA_ERROR)
				fprintf(stderr,"Some error ocurred while decrypting the file %s\n",infile);
			else if (r == ENCRYPTION_RSA_OPEN_FILE_ERROR)
				fprintf(stderr, "Error opening the output file\n");
			else if (r == ENCRYPTION_RSA_PRIVATE_KEY_ERROR)
				fprintf(stderr,"Error opening the private key file %s\n",keyfile);
			goto final;
		}
		/*
		  5.2 ECC private key
		*/
		if (memcmp(ai.keytype_arg,"eccprivate",10) == 0) {
			EllipticCurves ecs = NULL;
			if ((ecs = initNISTEllipticCurves()) == NULL) {
				fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
				goto final;
			}
			r = decryptFileWithECC(infile, keyfile, ecs);
			if (r == ENCRYPTION_ECC_OK) {
				printf ("File decrypted successfuly.\n");
				ret = EXIT_SUCCESS;
			} else if (r == ENCRYPTION_ECC_FILE_NOT_FOUND)
				fprintf(stderr,"The file %s was not found or can not be read",infile);
			else if (r == ENCRYPTION_ECC_ERROR)
				fprintf(stderr,"Some error ocurred while decrypting the file %s\n",infile);
			else if (r == ENCRYPTION_ECC_OPEN_FILE_ERROR)
				fprintf(stderr, "Error opening the output file\n");
			else if (r == ENCRYPTION_RSA_PRIVATE_KEY_ERROR)
				fprintf(stderr,"Error opening the private key file %s\n",keyfile);
			goto final;
		}
	}
	/*









		6. Encrypts an unencrypted RSA private key file
	*/
	if (ai.encryptkey_flag && ai.keyfile_given && (memcmp(ai.keytype_arg,"rsaprivate",10) == 0)) {
		char *infile, *outfile;
		PrivateRSAKey rsa;
		rsa = NULL;
		if (!ai.outfile_given) {
			fprintf(stderr,"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag || ai.show_flag ||
			ai.decrypt_flag || ai.ascii_flag || ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.keyfile_arg;
		outfile = ai.outfile_arg;
		if ((rsa = readPrivateRSAKeyFromFile(infile)) == NULL) {
			fprintf(stderr,"Error reading the unencrypted private RSA key %s\n",infile);
			goto final;
		}
		if (!writeEncryptedPrivateRSAKeyToFile(outfile, rsa))
			fprintf(stderr,"Error writing the encrypted private RSA key %s\n",outfile);
		freePrivateRSAKey(rsa);
		printf("Saved the encrypted private RSA key to %s\n", outfile);
		goto final;
	}
	/*









		7. Encrypts an unencrypted ECC private key file
	*/
	if (ai.encryptkey_flag && ai.keyfile_given && (memcmp(ai.keytype_arg,"eccprivate",10) == 0)) {
		char *infile, *outfile;
		PrivateECCKey ecc;
		ecc = NULL;
		if (!ai.outfile_given) {
			fprintf(stderr,"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag || ai.show_flag ||
			ai.decrypt_flag || ai.ascii_flag || ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.keyfile_arg;
		outfile = ai.outfile_arg;
		EllipticCurves ecs = NULL;
		if ((ecs = initNISTEllipticCurves()) == NULL) {
			fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
			goto final;
		}
		if ((ecc = readPrivateECCKeyFromFile(infile, ecs)) == NULL) {
			fprintf(stderr,"Error reading the unencrypted private ECC key %s\n",infile);
			goto final;
		}
		if (!writeEncryptedPrivateECCKeyToFile(outfile, ecc))
			fprintf(stderr,"Error writing the encrypted private ECC key %s\n",outfile);
		freePrivateECCKey(ecc);
		printf("Saved the encrypted private ECC key to %s\n", outfile);
		goto final;
	}
	/*









		8. Decrypts an encrypted RSA private key file
	*/
	if (ai.decryptkey_flag && ai.keyfile_given && (memcmp(ai.keytype_arg,"rsaprivate",10) == 0)) {
		char *infile, *outfile;
		PrivateRSAKey rsa;
		rsa = NULL;
		if (!ai.outfile_given) {
			fprintf(stderr,"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag || ai.show_flag ||
			ai.decrypt_flag || ai.ascii_flag || ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.keyfile_arg;
		outfile = ai.outfile_arg;
		if ((rsa = readEncryptedPrivateRSAKeyFromFile(infile)) == NULL) {
			fprintf(stderr,"Error reading the unencrypted private RSA key %s\n",infile);
			goto final;
		}
		if (!writePrivateRSAKeyToFile(outfile, rsa))
			fprintf(stderr,"Error writing the encrypted private RSA key %s\n",outfile);
		freePrivateRSAKey(rsa);
		printf("Saved the unencrypted private RSA key to %s\n", outfile);
		goto final;
	}
	/*









		9. Decrypts an encrypted ECC private key file
	*/
	if (ai.decryptkey_flag && ai.keyfile_given && (memcmp(ai.keytype_arg,"eccprivate",10) == 0)) {
		char *infile, *outfile;
		PrivateECCKey ecc;
		ecc = NULL;
		if (!ai.outfile_given) {
			fprintf(stderr,"You have to write the name of the output file: --outfile=filename\n");
			goto final;
		}
		if (ai.encrypt_flag || ai.bits_given || ai.genkey_flag || ai.show_flag ||
			ai.decrypt_flag || ai.ascii_flag || ai.sign_flag || ai.verify_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.keyfile_arg;
		outfile = ai.outfile_arg;
		EllipticCurves ecs = NULL;
		if ((ecs = initNISTEllipticCurves()) == NULL) {
			fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
			goto final;
		}
		if ((ecc = readEncryptedPrivateECCKeyFromFile(infile, ecs)) == NULL) {
			fprintf(stderr,"Error reading the encrypted private ECC key %s\n",infile);
			goto final;
		}
		if (!writePrivateECCKeyToFile(outfile, ecc))
			fprintf(stderr,"Error writing the unencrypted private ECC key %s\n",outfile);

		freePrivateECCKey(ecc);
		printf("Saved the unencrypted private ECC key to %s\n", outfile);
		goto final;
	}
	/*









		10. Signs a file with a private RSA key
	*/
	if(ai.sign_flag && ai.infile_given && ai.keyfile_given && (memcmp(ai.keytype_arg,"rsaprivate",10) == 0)) {
		char *infile, *outfile, *keyfile;
		int r;

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.encrypt_flag || ai.verify_flag || ai.show_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		keyfile = ai.keyfile_arg;
		r = signFileWithRSA(infile,&outfile,keyfile,ai.ascii_flag);
		if (r == SIGNATURE_RSA_OK) {
			printf("File signed successfuly. Signed file is %s\n",outfile);
			ret = EXIT_SUCCESS;
		} else if (r == SIGNATURE_RSA_FILE_NOT_FOUND)
			fprintf(stderr,"The file %s was not found or can not be read\n",infile);
		else if (r == SIGNATURE_RSA_ERROR)
			fprintf(stderr,"Some error ocurred while signing the file %s\n",infile);
		else if (r == SIGNATURE_RSA_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",outfile);
		else if (r == ENCRYPTION_RSA_PRIVATE_KEY_ERROR)
			fprintf(stderr, "Error reading the private key RSA file %s\n",keyfile);

		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}
	/*









		11. Signs a file with a private ECC key
	*/
	if(ai.sign_flag && ai.infile_given && ai.keyfile_given && (memcmp(ai.keytype_arg,"eccprivate",10) == 0)) {
		char *infile, *outfile, *keyfile;
		int r;

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.encrypt_flag || ai.verify_flag || ai.show_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		outfile = NULL;
		if (ai.outfile_given)
			outfile = ai.outfile_arg;
		keyfile = ai.keyfile_arg;
		EllipticCurves ecs = NULL;
		if ((ecs = initNISTEllipticCurves()) == NULL) {
			fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
			goto final;
		}
		r = signFileWithECC(infile,&outfile,keyfile,ecs,ai.ascii_flag);
		if (r == SIGNATURE_ECC_OK) {
			printf("File signed successfuly. Signed file is %s\n",outfile);
			ret = EXIT_SUCCESS;
		} else if (r == SIGNATURE_ECC_FILE_NOT_FOUND)
			fprintf(stderr,"The file %s was not found or can not be read",infile);
		else if (r == SIGNATURE_ECC_ERROR)
			fprintf(stderr,"Some error ocurred while signing the file %s\n",infile);
		else if (r == SIGNATURE_ECC_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the outfile %s\n",outfile);
		else if (r == ENCRYPTION_ECC_PRIVATE_KEY_ERROR)
			fprintf(stderr, "Error reading the private ECC key file %s\n",keyfile);

		if (!ai.outfile_given)
			freeString(outfile);
		goto final;
	}
	/*









		12. Extract and verify a signed file with RSA public key
	*/
	if (ai.verify_flag && ai.infile_given && ai.keyfile_given && (memcmp(ai.keytype_arg,"rsapublic",9) == 0)) {
		char *infile, *keyfile;
		int r;

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.encrypt_flag || ai.sign_flag || ai.ascii_flag || ai.show_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		keyfile = ai.keyfile_arg;
		r = verifyAndExtractSignedFileWithRSA(infile, keyfile);
		if (r == SIGNATURE_RSA_OK) {
			printf("File %s verified and extracted successfuly\n",infile);
			ret = EXIT_SUCCESS;
		}
		else if (r == SIGNATURE_RSA_BAD)
			fprintf(stderr,"The file %s has in incorrect signature\n",infile);
		else if (r == SIGNATURE_RSA_FILE_NOT_FOUND)
			fprintf(stderr,"The file %s was not found or can not be read\n",infile);
		else if (r == SIGNATURE_RSA_ERROR)
			fprintf(stderr,"Some error ocurred while extranting abd verifying the file %s, signed with RSA\n",infile);
		else if (r == SIGNATURE_RSA_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the output file\n");
		else if (r == ENCRYPTION_RSA_PUBLIC_KEY_ERROR)
			fprintf(stderr, "Error reading the public RSA key file %s\n",keyfile);
		else if (r == ENCRYPTION_RSA_WRITE_FILE_ERROR)
			fprintf(stderr, "Error writing the output file");
		goto final;
	}

	/*









		13. Extract and verify a signed file with RSA public key
	*/
	if (ai.verify_flag && ai.infile_given && ai.keyfile_given && (memcmp(ai.keytype_arg,"eccpublic",9) == 0)) {
		char *infile, *keyfile;
		int r;

		if (ai.decrypt_flag || ai.bits_given || ai.genkey_flag ||
			ai.encrypt_flag || ai.sign_flag || ai.ascii_flag || ai.show_flag) {
			fprintf(stderr, "Wrong combination of parameters\n");
			goto final;
		}
		infile = ai.infile_arg;
		keyfile = ai.keyfile_arg;
		EllipticCurves ecs = NULL;
		if ((ecs = initNISTEllipticCurves()) == NULL) {
			fprintf(stderr,"Error reading the data for SECP and Brainpool elliptic curves\n");
			goto final;
		}
		r = verifyAndExtractSignedFileWithECC(infile, keyfile, ecs);
		if (r == SIGNATURE_ECC_OK) {
			printf("File %s verified and extracted successfuly\n",infile);
			ret = EXIT_SUCCESS;
		}
		else if (r == SIGNATURE_ECC_BAD)
			fprintf(stderr,"The file %s has in incorrect signature\n",infile);
		else if (r == SIGNATURE_ECC_FILE_NOT_FOUND)
			fprintf(stderr,"The file %s was not found or can not be read\n",infile);
		else if (r == SIGNATURE_ECC_ERROR)
			fprintf(stderr,"Some error ocurred while ppp verifying the file %s\n",infile);
		else if (r == SIGNATURE_ECC_OPEN_FILE_ERROR)
			fprintf(stderr, "Error opening the output file\n");
		else if (r == ENCRYPTION_ECC_PUBLIC_KEY_ERROR)
			fprintf(stderr, "Error reading the public ECC key file %s\n",keyfile);
		else if (r == ENCRYPTION_ECC_WRITE_FILE_ERROR)
			fprintf(stderr, "Error writing the output file");
		goto final;
	}


	/*
	  If any option is processed, the help is shon
	*/
	printf("%s\n", gengetopt_args_info_usage);
	printf("%s\n", *gengetopt_args_info_help);
	ret = EXIT_SUCCESS;
/*
	Final of the program
*/
 final:
	cmdline_parser_free(&ai);
	return ret;
}
