#include <mcecrypto.h>
#include <stdlib.h>
#include "cmdline.h"

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
	   Process the different options
	   1. Generate a pair of public and private key
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
				fprintf(stderr,"Error reading the data for NIST elliptic curves\n");
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

	/*
	   Final of the program
	 */
	printf("%s\n", gengetopt_args_info_usage);
	printf("%s\n", *gengetopt_args_info_help);
	ret = EXIT_SUCCESS;

 final:
	cmdline_parser_free(&ai);
	return ret;
}
