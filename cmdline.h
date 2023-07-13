/** @file cmdline.h
 *  @brief The header file for the command line option parser
 *  generated by GNU Gengetopt version 2.23
 *  http://www.gnu.org/software/gengetopt.
 *  DO NOT modify this file, since it can be overwritten
 *  @author GNU Gengetopt */

#ifndef CMDLINE_H
#define CMDLINE_H

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h> /* for FILE */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef CMDLINE_PARSER_PACKAGE
/** @brief the program name (used for printing errors) */
#define CMDLINE_PARSER_PACKAGE "mcecrypto"
#endif

#ifndef CMDLINE_PARSER_PACKAGE_NAME
/** @brief the complete program name (used for help and version) */
#define CMDLINE_PARSER_PACKAGE_NAME "mcecrypto"
#endif

#ifndef CMDLINE_PARSER_VERSION
/** @brief the program version */
#define CMDLINE_PARSER_VERSION "1.0"
#endif

/** @brief Where the command line options are stored */
struct gengetopt_args_info
{
  const char *help_help; /**< @brief Print help and exit help description.  */
  const char *version_help; /**< @brief Print version and exit help description.  */
  char * infile_arg;	/**< @brief File to encrypt or sign.  */
  char * infile_orig;	/**< @brief File to encrypt or sign original value given at command line.  */
  const char *infile_help; /**< @brief File to encrypt or sign help description.  */
  char * outfile_arg;	/**< @brief Name of the encrypted or the signed file.  */
  char * outfile_orig;	/**< @brief Name of the encrypted or the signed file original value given at command line.  */
  const char *outfile_help; /**< @brief Name of the encrypted or the signed file help description.  */
  int encrypt_flag;	/**< @brief Encrypts a file (default=off).  */
  const char *encrypt_help; /**< @brief Encrypts a file help description.  */
  int decrypt_flag;	/**< @brief Decrypts a file (default=off).  */
  const char *decrypt_help; /**< @brief Decrypts a file help description.  */
  int genkey_flag;	/**< @brief Generates a pair of RSA or ECC keys (default=off).  */
  const char *genkey_help; /**< @brief Generates a pair of RSA or ECC keys help description.  */
  int bits_arg;	/**< @brief Bits of the generated RSA key (default='2048').  */
  char * bits_orig;	/**< @brief Bits of the generated RSA key original value given at command line.  */
  const char *bits_help; /**< @brief Bits of the generated RSA key help description.  */
  char * ec_arg;	/**< @brief Elliptic curve (default='secp521r1').  */
  char * ec_orig;	/**< @brief Elliptic curve original value given at command line.  */
  const char *ec_help; /**< @brief Elliptic curve help description.  */
  int ascii_flag;	/**< @brief Writes the output file in ASCII format (default=off).  */
  const char *ascii_help; /**< @brief Writes the output file in ASCII format help description.  */
  char * keyfile_arg;	/**< @brief File of the public or private RSA or ECC key.  */
  char * keyfile_orig;	/**< @brief File of the public or private RSA or ECC key original value given at command line.  */
  const char *keyfile_help; /**< @brief File of the public or private RSA or ECC key help description.  */
  int show_flag;	/**< @brief Shows a public or private RSA key (default=off).  */
  const char *show_help; /**< @brief Shows a public or private RSA key help description.  */
  int noaes_flag;	/**< @brief Saves the RSA private key unencrypted (default=off).  */
  const char *noaes_help; /**< @brief Saves the RSA private key unencrypted help description.  */
  int encryptkey_flag;	/**< @brief Encrypts an RSA or ECC private key (default=off).  */
  const char *encryptkey_help; /**< @brief Encrypts an RSA or ECC private key help description.  */
  int decryptkey_flag;	/**< @brief Decrypts an RSA or ECC private key (default=off).  */
  const char *decryptkey_help; /**< @brief Decrypts an RSA or ECC private key help description.  */
  int sign_flag;	/**< @brief Signs a file (default=off).  */
  const char *sign_help; /**< @brief Signs a file help description.  */
  int verify_flag;	/**< @brief Verify and extract a signed file (default=off).  */
  const char *verify_help; /**< @brief Verify and extract a signed file help description.  */
  
  unsigned int help_given ;	/**< @brief Whether help was given.  */
  unsigned int version_given ;	/**< @brief Whether version was given.  */
  unsigned int infile_given ;	/**< @brief Whether infile was given.  */
  unsigned int outfile_given ;	/**< @brief Whether outfile was given.  */
  unsigned int encrypt_given ;	/**< @brief Whether encrypt was given.  */
  unsigned int decrypt_given ;	/**< @brief Whether decrypt was given.  */
  unsigned int genkey_given ;	/**< @brief Whether genkey was given.  */
  unsigned int bits_given ;	/**< @brief Whether bits was given.  */
  unsigned int ec_given ;	/**< @brief Whether ec was given.  */
  unsigned int ascii_given ;	/**< @brief Whether ascii was given.  */
  unsigned int keyfile_given ;	/**< @brief Whether keyfile was given.  */
  unsigned int show_given ;	/**< @brief Whether show was given.  */
  unsigned int noaes_given ;	/**< @brief Whether noaes was given.  */
  unsigned int encryptkey_given ;	/**< @brief Whether encryptkey was given.  */
  unsigned int decryptkey_given ;	/**< @brief Whether decryptkey was given.  */
  unsigned int sign_given ;	/**< @brief Whether sign was given.  */
  unsigned int verify_given ;	/**< @brief Whether verify was given.  */

} ;

/** @brief The additional parameters to pass to parser functions */
struct cmdline_parser_params
{
  int override; /**< @brief whether to override possibly already present options (default 0) */
  int initialize; /**< @brief whether to initialize the option structure gengetopt_args_info (default 1) */
  int check_required; /**< @brief whether to check that all required options were provided (default 1) */
  int check_ambiguity; /**< @brief whether to check for options already specified in the option structure gengetopt_args_info (default 0) */
  int print_errors; /**< @brief whether getopt_long should print an error message for a bad option (default 1) */
} ;

/** @brief the purpose string of the program */
extern const char *gengetopt_args_info_purpose;
/** @brief the usage string of the program */
extern const char *gengetopt_args_info_usage;
/** @brief the description string of the program */
extern const char *gengetopt_args_info_description;
/** @brief all the lines making the help output */
extern const char *gengetopt_args_info_help[];

/**
 * The command line parser
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser (int argc, char **argv,
  struct gengetopt_args_info *args_info);

/**
 * The command line parser (version with additional parameters - deprecated)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param override whether to override possibly already present options
 * @param initialize whether to initialize the option structure my_args_info
 * @param check_required whether to check that all required options were provided
 * @return 0 if everything went fine, NON 0 if an error took place
 * @deprecated use cmdline_parser_ext() instead
 */
int cmdline_parser2 (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  int override, int initialize, int check_required);

/**
 * The command line parser (version with additional parameters)
 * @param argc the number of command line options
 * @param argv the command line options
 * @param args_info the structure where option information will be stored
 * @param params additional parameters for the parser
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_ext (int argc, char **argv,
  struct gengetopt_args_info *args_info,
  struct cmdline_parser_params *params);

/**
 * Save the contents of the option struct into an already open FILE stream.
 * @param outfile the stream where to dump options
 * @param args_info the option struct to dump
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_dump(FILE *outfile,
  struct gengetopt_args_info *args_info);

/**
 * Save the contents of the option struct into a (text) file.
 * This file can be read by the config file parser (if generated by gengetopt)
 * @param filename the file where to save
 * @param args_info the option struct to save
 * @return 0 if everything went fine, NON 0 if an error took place
 */
int cmdline_parser_file_save(const char *filename,
  struct gengetopt_args_info *args_info);

/**
 * Print the help
 */
void cmdline_parser_print_help(void);
/**
 * Print the version
 */
void cmdline_parser_print_version(void);

/**
 * Initializes all the fields a cmdline_parser_params structure 
 * to their default values
 * @param params the structure to initialize
 */
void cmdline_parser_params_init(struct cmdline_parser_params *params);

/**
 * Allocates dynamically a cmdline_parser_params structure and initializes
 * all its fields to their default values
 * @return the created and initialized cmdline_parser_params structure
 */
struct cmdline_parser_params *cmdline_parser_params_create(void);

/**
 * Initializes the passed gengetopt_args_info structure's fields
 * (also set default values for options that have a default)
 * @param args_info the structure to initialize
 */
void cmdline_parser_init (struct gengetopt_args_info *args_info);
/**
 * Deallocates the string fields of the gengetopt_args_info structure
 * (but does not deallocate the structure itself)
 * @param args_info the structure to deallocate
 */
void cmdline_parser_free (struct gengetopt_args_info *args_info);

/**
 * Checks that all the required options were specified
 * @param args_info the structure to check
 * @param prog_name the name of the program that will be used to print
 *   possible errors
 * @return
 */
int cmdline_parser_required (struct gengetopt_args_info *args_info,
  const char *prog_name);

extern const char *cmdline_parser_ec_values[];  /**< @brief Possible values for ec. */


#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* CMDLINE_H */
