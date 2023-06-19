/**************************************************************************************
 * Filename:   compress.c
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
#include <zlib.h>
#include <stdlib.h>
#include <string.h>

#define ZLIBCHUNK 16384

#define CALL_ZLIB_DEFLATE(x)  unsigned char out[ZLIBCHUNK];							          \
	st.avail_in = (x) * sizeof(unsigned char);												  \
	st.next_in = (Bytef *)p;																  \
	insize -= (x);																			  \
	flush = (insize == 0) ? Z_FINISH : Z_NO_FLUSH;											  \
	do																						  \
	{																						  \
		size_t have;																		  \
		st.avail_out = ZLIBCHUNK;															  \
		st.next_out = (Bytef *)out;															  \
		ret = deflate(&st,flush);															  \
		if ((ret != Z_OK) && (ret != Z_STREAM_END))											  \
		{																					  \
			deflateEnd(&st);																  \
			free(str);																		  \
			*alloc = 0;																		  \
			*outsize = 0;																	  \
			return NULL;									  								  \
		}																					  \
		have = ZLIBCHUNK - st.avail_out;													  \
		if ((*alloc - *outsize) < have)														  \
		{																					  \
			*alloc += ZLIBCHUNK;															  \
			if ((str = (unsigned char *)realloc(str,*alloc * sizeof(unsigned char))) == NULL) \
				return NULL;												  				  \
		}										 											  \
		memcpy(str + *outsize,out,have);													  \
		*outsize += have;																	  \
	} while (st.avail_out == 0);															  \
	p += (x);

#define CALL_ZLIB_INFLATE(x)  unsigned char out[ZLIBCHUNK];							          \
	st.avail_in = (x) * sizeof(unsigned char);												  \
	st.next_in = (Bytef *)p;																  \
	insize -= (x);																			  \
	do																						  \
	{																						  \
		size_t have;																		  \
		st.avail_out = ZLIBCHUNK;															  \
		st.next_out = (Bytef *)out;															  \
		ret = inflate(&st,Z_NO_FLUSH);														  \
		if ((ret != Z_OK)  && (ret != Z_STREAM_END))										  \
		{																				      \
			inflateEnd(&st);																  \
			free(str);																		  \
			*alloc = 0;																		  \
			*outsize = 0;																	  \
			return NULL;																	  \
		}																					  \
		have = ZLIBCHUNK - st.avail_out;													  \
		if ((*alloc - *outsize) < have)														  \
		{																					  \
			*alloc += ZLIBCHUNK;															  \
			if ((str = (unsigned char *)realloc(str,*alloc * sizeof(unsigned char))) == NULL) \
				return NULL;															      \
		}																					  \
		memcpy(str + *outsize,out,have);													  \
		*outsize += have;																	  \
	} while (st.avail_out == 0);															  \
	p += (x);

/*
  Compress and uncompress with zlib
*/
unsigned char *zlib_compress_data(unsigned char *data, size_t insize, size_t * outsize, size_t * alloc)
{
	z_stream st;
	unsigned char *str, *p;
	int flush, ret;

	*outsize = 0;
	*alloc = 0;
	if (insize == 0)
		return NULL;

	st.zalloc = Z_NULL;
	st.zfree = Z_NULL;
	st.opaque = Z_NULL;
	if (deflateInit(&st, Z_BEST_COMPRESSION) != Z_OK)
		return NULL;

	*alloc = 2 * ZLIBCHUNK;
	if ((str =
	     (unsigned char *)calloc(*alloc, sizeof(unsigned char))) == NULL)
		return NULL;

	p = data;
	while (insize > ZLIBCHUNK)
	{
		CALL_ZLIB_DEFLATE(ZLIBCHUNK);
	}
	if (insize > 0)
	{
		CALL_ZLIB_DEFLATE(insize);
	}
	deflateEnd(&st);
	return str;
}

unsigned char *zlib_uncompress_data(unsigned char *data, size_t insize, size_t * outsize, size_t * alloc)
{
	z_stream st;
	unsigned char *str, *p;
	int ret;

	*outsize = 0;
	*alloc = 0;
	if (insize == 0)
		return NULL;

	st.zalloc = Z_NULL;
	st.zfree = Z_NULL;
	st.opaque = Z_NULL;
	if (inflateInit(&st) != Z_OK)
		return NULL;

	*alloc = ZLIBCHUNK;
	if ((str =
	     (unsigned char *)calloc(*alloc, sizeof(unsigned char))) == NULL)
		return NULL;

	p = data;
	while (insize > ZLIBCHUNK)
	{
		CALL_ZLIB_INFLATE(ZLIBCHUNK);
	}
	if (insize > 0)
	{
		CALL_ZLIB_INFLATE(insize);
	}
	inflateEnd(&st);
	return str;
}

