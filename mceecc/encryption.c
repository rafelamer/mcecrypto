/**************************************************************************************
 * Filename:   encryption.c
 * Author:     Rafel Amer (rafel.amer AT upc.edu)
 * Copyright:  Rafel Amer 2018-2023
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
#include <mceecc.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>

#define WRITEERROR {                        \
		close(fd);						    \
		unlink(*outfile);					\
		ret =  ENCRYPTION_WRITE_FILE_ERROR; \
		goto final;							\
	}

static const unsigned char beccf[] = "-----BEGIN EC ENCRYPTED FILE-----";
static const unsigned char eeccf[] = "-----END EC ENCRYPTED FILE-----";

