/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 2011 2016 Harald von Fellenberg <hvf@hvf.ch>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 3 of the License, or 
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "generic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KeccakHash.h"



/* 
 * parameter safe wrappers for SHA3 routines for each hash length
 */

 /*************************** 224 ************************************/

HashReturn SHA3_224_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHA3_224)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHA3_224;
    context->magic = HASH_MAGIC_SHA3_224;
	*state = (hashState *) context;
	return Keccak_HashInitialize_SHA3_224 (context);
}

HashReturn  SHA3_224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_224)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  SHA3_224_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_224)
        return BAD_ALGORITHM;

	// if (!hashval)
	//	hashval = context->out;

	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_SHA3_224);
	return retval;
}

HashReturn SHA3_224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SHA3_224_init (&state, HASH_BITLENGTH_SHA3_224);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA3_224);
        exit (1);
    }

    retval = SHA3_224_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_224_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SHA3_224_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_224_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SHA3_224_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA3_224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA3_224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA3_224_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA3_224);
	return SUCCESS;
}


 /*************************** 256 ************************************/

HashReturn SHA3_256_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHA3_256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHA3_256;
    context->magic = HASH_MAGIC_SHA3_256;
	*state = (hashState *) context;
	return Keccak_HashInitialize_SHA3_256 (context);
}

HashReturn  SHA3_256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_256)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  SHA3_256_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_256)
        return BAD_ALGORITHM;

	//if (!hashval)
		//hashval = context->out;

	//return Keccak_HashFinal (context, hashval);
	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_SHA3_256);
	return retval;
}

HashReturn SHA3_256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SHA3_256_init (&state, HASH_BITLENGTH_SHA3_256);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA3_256);
        exit (1);
    }

    retval = SHA3_256_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_256_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SHA3_256_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_256_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SHA3_256_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA3_256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA3_256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA3_256_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA3_256);
	return SUCCESS;
}


 /*************************** 384 ************************************/

HashReturn SHA3_384_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHA3_384)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHA3_384;
    context->magic = HASH_MAGIC_SHA3_384;
	*state = (hashState *) context;
	return Keccak_HashInitialize_SHA3_384 (context);
}

HashReturn  SHA3_384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_384)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  SHA3_384_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_384)
        return BAD_ALGORITHM;

//	if (!hashval)
		//hashval = context->out;

	//return Keccak_HashFinal (context, hashval);
	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_SHA3_384);
	return retval;
}

HashReturn SHA3_384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SHA3_384_init (&state, HASH_BITLENGTH_SHA3_384);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_384_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA3_384);
        exit (1);
    }

    retval = SHA3_384_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_384_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SHA3_384_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_384_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SHA3_384_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_384)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA3_384_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA3_384_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA3_384_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_384)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA3_384);
	return SUCCESS;
}


 /*************************** 512 ************************************/

HashReturn SHA3_512_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHA3_512)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHA3_512;
    context->magic = HASH_MAGIC_SHA3_512;
	*state = (hashState *) context;
	return Keccak_HashInitialize_SHA3_512 (context);
}

HashReturn  SHA3_512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_512)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  SHA3_512_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHA3_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHA3_512)
        return BAD_ALGORITHM;

	//if (!hashval)
		//hashval = context->out;

	//return Keccak_HashFinal (context, hashval);
	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_SHA3_512);
	return retval;
}

HashReturn SHA3_512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SHA3_512_init (&state, HASH_BITLENGTH_SHA3_512);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHA3_512);
        exit (1);
    }

    retval = SHA3_512_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_512_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SHA3_512_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHA3_512_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SHA3_512_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHA3_512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHA3_512_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHA3_512_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHA3_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHA3_512)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHA3_512);
	return SUCCESS;
}


 /*************************** SHAKE128 ************************************/

HashReturn SHAKE128_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHAKE128)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHAKE128;
    context->magic = HASH_MAGIC_SHAKE128;
	*state = (hashState *) context;
	return Keccak_HashInitialize_SHAKE128 (context);
}

HashReturn  SHAKE128_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHAKE128)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  SHAKE128_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;

	HashReturn	retval;

    if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHAKE128)
        return BAD_ALGORITHM;

	Keccak_HashFinal (context, context->out);

	// if hashval is NULL, we allocate a buffer for intermediate storage
	if (!hashval) hashval = (BitSequence *)malloc (SqueezingOutputLength/8);
	size_t	nchunksize = 100;	// squeeze 64 bytes (only) each time
	//size_t squeezechunksize = 8*nchunksize;
	size_t nbytesdone;
	//int bitslefttodo = SqueezingOutputLength;
	for (nbytesdone = 0; nbytesdone < SqueezingOutputLength/8; 
		nbytesdone += nchunksize) {
		if (nbytesdone + nchunksize > SqueezingOutputLength/8) 
			nchunksize = SqueezingOutputLength/8 - nbytesdone;
		retval = Keccak_HashSqueeze (context, context->out, nchunksize*8);
		if (hashval) memcpy (hashval+nbytesdone, context->out, nchunksize);
	}
	// copy back into context->out
	memcpy (context->out, hashval, SqueezingOutputLength/8);

	return retval;
}

HashReturn SHAKE128_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SHAKE128_init (&state, HASH_BITLENGTH_SHAKE128);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHAKE128_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHAKE128);
        exit (1);
    }

    retval = SHAKE128_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHAKE128_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SHAKE128_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHAKE128_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SHAKE128_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE128)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHAKE128_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHAKE128_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHAKE128_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE128)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHAKE128);
	return SUCCESS;
}


 /*************************** SHAKE256 ************************************/

HashReturn SHAKE256_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHAKE256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHAKE256;
    context->magic = HASH_MAGIC_SHAKE256;
	*state = (hashState *) context;
	return Keccak_HashInitialize_SHAKE256 (context);
}

HashReturn  SHAKE256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHAKE256)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  SHAKE256_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;

	HashReturn	retval;

    if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHAKE256)
        return BAD_ALGORITHM;

	Keccak_HashFinal (context, context->out);

	retval = Keccak_HashSqueeze (context, context->out, SqueezingOutputLength);
	if (hashval) memcpy (hashval, context->out, SqueezingOutputLength/8);
	return retval;
}

HashReturn SHAKE256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = SHAKE256_init (&state, HASH_BITLENGTH_SHAKE256);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHAKE256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_SHAKE256);
        exit (1);
    }

    retval = SHAKE256_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHAKE256_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = SHAKE256_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "SHAKE256_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn SHAKE256_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHAKE256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = SHAKE256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn SHAKE256_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_SHAKE256);
	return SUCCESS;
}

 /*************************** XOFSHAKE128 ************************************/

HashReturn XOFSHAKE128_init (hashState  *state, int hashbitlen, EXTRA_DATA extra)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHAKE128)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHAKE128;
    context->magic = HASH_MAGIC_SHAKE128;
	context->xof_OK = 1;
	context->xoflength= XOF_LENGTH_XOFSHAKE128;
	context->xofinfinity = 0;
	// to make life easier for base64, chunksize is a multiple of 12
	context->this_chunk_size = XOF_LENGTH_XOFSHAKE128;
	context->more_size = XOF_LENGTH_XOFSHAKE128;

	/* extra data for XOF */
	if (extra) {
		context->base64flag = extra->base64flag;
		context->xofflag = extra->xofflag;
		context->xoflength= extra->xoflength;
		context->more_size= extra->xoflength;
		context->xofinfinity = (context->xoflength == -1);
		// default length is 512 bytes if xoflength == 0 (unspecified)
		if (extra->xoflength == 0) {    // use default length
			context->xoflength = XOF_DEFAULT_LENGTH_XOFSHAKE128;
			context->more_size = XOF_DEFAULT_LENGTH_XOFSHAKE128;
		}
		// length is shorter than default
		if ((context->xoflength > 0) && (context->xoflength < XOF_LENGTH_XOFSHAKE128)) {
			context->more_size = context->this_chunk_size = context->xoflength;
		}
		// length is infinity
		if (extra->xoflength < 0) {		// -1, infinity
			context->xoflength= XOF_LENGTH_XOFSHAKE128;
			context->xoflength= -1;
			context->more_size = -1;
			context->xofinfinity = 1;
		}

		context->binoutflag = extra->binoutflag;	// not yet used
	}

	*state = (hashState *) context;
	return Keccak_HashInitialize_SHAKE128 (context);

}

HashReturn  XOFSHAKE128_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;

	HashReturn	retval;

    if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHAKE128)
        return BAD_ALGORITHM;

	/* check if already squeezing	*/

	if (!context->squeezeflag) {	// skip if squeezing
		retval = Keccak_HashFinal (context, context->out);
		context->squeezeflag = 1;
	}

	/* we squeeze 600 bytes (a multiple of 12 bytes) to make base64 
	 * conversion easier
	 * total length in bytes is in context->xoflength, 
	 * remaining length in context->more_size
	 * -1 means infinity	*/
    /* 600 bytes is a real hack: it is just a bit longer than the standard
     * length of 512 bytes for shake128, therefore we can use the
     * usual testsuite without stitching the output together
     */

	retval = Keccak_HashSqueeze (context, context->out, XOF_BITLENGTH_XOFSHAKE128);
	// if (hashval) memcpy (hashval, context->out, SqueezingOutputLength/8);
	if (hashval) memcpy (hashval, context->out, context->this_chunk_size);
	if (!context->xofinfinity) {
		// not last block of data
		if (context->more_size > context->this_chunk_size) {
			context->more_size -= context->this_chunk_size;
		} else {	// last block of data
			context->this_chunk_size = context->more_size;
			context->more_size = 0;
		}
	}
	// infinity means: more_size remains on -1, 
	// this_chunk_size remains on its standard value XOF_LENGTH_XOFSHAKE128
	
	return retval;
}


/* Digests a file and prints the result.
 */
HashReturn XOFSHAKE128_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE128)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHAKE128_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = XOFSHAKE128_final (context, NULL);
	fclose (in);
	return retval;
}

 /*************************** XOFSHAKE256 ************************************/

HashReturn XOFSHAKE256_init (hashState  *state, int hashbitlen, EXTRA_DATA extra)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_SHAKE256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_SHAKE256;
    context->magic = HASH_MAGIC_SHAKE256;
	context->xof_OK = 1;
	context->xoflength= XOF_LENGTH_XOFSHAKE256;
	context->xofinfinity = 0;
	// to make life easier for base64, chunksize is a multiple of 12
	context->this_chunk_size = XOF_LENGTH_XOFSHAKE256;
	context->more_size = XOF_LENGTH_XOFSHAKE256;

	/* extra data for XOF */
	if (extra) {
		context->base64flag = extra->base64flag;
		context->xofflag = extra->xofflag;
		context->xoflength= extra->xoflength;
		context->more_size= extra->xoflength;
		context->xofinfinity = (context->xoflength == -1);
		// default length is 512 bytes if xoflength == 0 (unspecified)
		if (extra->xoflength == 0) {    // use default length
			context->xoflength = XOF_DEFAULT_LENGTH_XOFSHAKE256;
			context->more_size = XOF_DEFAULT_LENGTH_XOFSHAKE256;
		}
		// length is shorter than default
		if ((context->xoflength > 0) && (context->xoflength < XOF_LENGTH_XOFSHAKE256)) {
			context->more_size = context->this_chunk_size = context->xoflength;
		}
		// length is infinity
		if (extra->xoflength < 0) {		// -1, infinity
			context->xoflength= XOF_LENGTH_XOFSHAKE256;
			context->xoflength= -1;
			context->more_size = -1;
			context->xofinfinity = 1;
		}

		context->binoutflag = extra->binoutflag;	// not yet used
	}

	*state = (hashState *) context;
	return Keccak_HashInitialize_SHAKE256 (context);

}

HashReturn  XOFSHAKE256_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;

	HashReturn	retval;

    if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_SHAKE256)
        return BAD_ALGORITHM;

	/* check if already squeezing	*/

	if (!context->squeezeflag) {
		retval = Keccak_HashFinal (context, context->out);
		context->squeezeflag = 1;
	}

	/* SqueezingOutputLength is 4096 bits, equal to HASH_BITLENGTH_SHAKE{128,256}
	 * HASH_LENGTH_SHAKE{128,256} is 512 bytes
	 * we squeeze a multiple of 12 bytes (96 bits) to make base64 conversion easier
	 * total length in bytes is in context->xoflength
	 * -1 means infinity	*/

	retval = Keccak_HashSqueeze (context, context->out, XOF_BITLENGTH_XOFSHAKE256);
	// if (hashval) memcpy (hashval, context->out, SqueezingOutputLength/8);
	if (hashval) memcpy (hashval, context->out, context->this_chunk_size);
	if (!context->xofinfinity) {
		if (context->more_size > context->this_chunk_size) {
			context->more_size -= context->this_chunk_size;
		} else {
			context->this_chunk_size = context->more_size;
			context->more_size = 0;
		}
	}

	return retval;
}


/* Digests a file and prints the result.
 */
HashReturn XOFSHAKE256_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = SHAKE256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = XOFSHAKE256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn XOFSHAKE128_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE128)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE128)
		return BAD_ALGORITHM;

	/* requested length is context->xoflength, bounded */
	size_t len = context->xoflength;
	if (len <= 0) len = XOF_LENGTH_XOFSHAKE128;
	if (len > XOF_LENGTH_XOFSHAKE128) len = XOF_LENGTH_XOFSHAKE128;

	// memcpy (out, context->out, HASH_LENGTH_SHAKE128);
	memcpy (out, context->out, len);
	return SUCCESS;
}


HashReturn XOFSHAKE256_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_SHAKE256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_SHAKE256)
		return BAD_ALGORITHM;

	/* requested length is context->xoflength, bounded */
	size_t len = context->xoflength;
	if (len <= 0) len = XOF_LENGTH_XOFSHAKE256;
	if (len > XOF_LENGTH_XOFSHAKE256) len = XOF_LENGTH_XOFSHAKE256;

	// memcpy (out, context->out, HASH_LENGTH_SHAKE256);
	memcpy (out, context->out, len);
	return SUCCESS;
}


/* 
 * parameter safe wrappers for KECCAK routines for each hash length
 */

 /*************************** 224 ************************************/

HashReturn KECCAK224_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_KECCAK_224)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_KECCAK_224;
    context->magic = HASH_MAGIC_KECCAK_224;
	*state = (hashState *) context;
	return Keccak_HashInitialize_keccak224 (context);
}

HashReturn  KECCAK224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_224)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  KECCAK224_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_224)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_224)
        return BAD_ALGORITHM;

	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_KECCAK_224);
	return retval;
}

HashReturn KECCAK224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = KECCAK224_init (&state, HASH_BITLENGTH_KECCAK_224);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK224_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_KECCAK_224);
        exit (1);
    }

    retval = KECCAK224_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK224_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = KECCAK224_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK224_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn KECCAK224_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_224)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = KECCAK224_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = KECCAK224_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn KECCAK224_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_224)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_224)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_KECCAK_224);
	return SUCCESS;
}


 /*************************** 256 ************************************/

HashReturn KECCAK256_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_KECCAK_256)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_KECCAK_256;
    context->magic = HASH_MAGIC_KECCAK_256;
	*state = (hashState *) context;
	return Keccak_HashInitialize_keccak256 (context);
}

HashReturn  KECCAK256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_256)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  KECCAK256_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_256)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_256)
        return BAD_ALGORITHM;

	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_KECCAK_256);
	return retval;
}

HashReturn KECCAK256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = KECCAK256_init (&state, HASH_BITLENGTH_KECCAK_256);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK256_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_KECCAK_256);
        exit (1);
    }

    retval = KECCAK256_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK256_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = KECCAK256_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK256_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn KECCAK256_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_256)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = KECCAK256_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = KECCAK256_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn KECCAK256_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_256)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_256)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_KECCAK_256);
	return SUCCESS;
}


 /*************************** 384 ************************************/

HashReturn KECCAK384_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_KECCAK_384)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_KECCAK_384;
    context->magic = HASH_MAGIC_KECCAK_384;
	*state = (hashState *) context;
	return Keccak_HashInitialize_keccak384 (context);
}

HashReturn  KECCAK384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_384)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  KECCAK384_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_384)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_384)
        return BAD_ALGORITHM;

	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_KECCAK_384);
	return retval;
}

HashReturn KECCAK384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = KECCAK384_init (&state, HASH_BITLENGTH_KECCAK_384);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK384_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_KECCAK_384);
        exit (1);
    }

    retval = KECCAK384_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK384_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = KECCAK384_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK384_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn KECCAK384_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_384)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = KECCAK384_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = KECCAK384_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn KECCAK384_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_384)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_384)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_KECCAK_384);
	return SUCCESS;
}


 /*************************** 512 ************************************/

HashReturn KECCAK512_init (hashState  *state, int hashbitlen)
{
    /* verify correct hash length   */
    if (hashbitlen != HASH_BITLENGTH_KECCAK_512)
        return BAD_HASHBITLEN;

    /* allocate context and fill it */
    SHA3_CTX *context = (SHA3_CTX *)malloc (sizeof (SHA3_CTX));
    memset (context, 0, sizeof (SHA3_CTX));
    context->hashbitlen = HASH_BITLENGTH_KECCAK_512;
    context->magic = HASH_MAGIC_KECCAK_512;
	*state = (hashState *) context;
	return Keccak_HashInitialize_keccak512 (context);
}

HashReturn  KECCAK512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen)      /* number of bits to process from buffer */
{
    /* can be called once or many times */
    /* verify correct hashbitlen and magic  */

    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_512)
        return BAD_ALGORITHM;

	return Keccak_HashUpdate (context, buffer, databitlen);
}

HashReturn  KECCAK512_final (hashState state, BitSequence *hashval)
{
    SHA3_CTX *context = (SHA3_CTX *) state;
    if (context->hashbitlen != HASH_BITLENGTH_KECCAK_512)
        return BAD_HASHBITLEN;

    if (context->magic != HASH_MAGIC_KECCAK_512)
        return BAD_ALGORITHM;

	HashReturn retval = Keccak_HashFinal (context, context->out);
	if (hashval) memcpy (hashval, context->out, HASH_LENGTH_KECCAK_512);
	return retval;
}

HashReturn KECCAK512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval)
{
    hashState   state;
    HashReturn  retval;

    retval = KECCAK512_init (&state, HASH_BITLENGTH_KECCAK_512);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK512_init failed, reason %d, hash length %d\n",
                 retval, HASH_BITLENGTH_KECCAK_512);
        exit (1);
    }

    retval = KECCAK512_update (state, data, databitlen);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK512_update failed, reason %d\n", retval);
        exit (1);
    }

    retval = KECCAK512_final (state, hashval);
    if (retval != SUCCESS) {
        fprintf (stderr, "KECCAK512_final failed, reason %d\n", retval);
        exit (1);
    }
    free (state);
    return retval;
}

/*
 * three functions in MD5 style for each hash length
 */

/* Digests a file and prints the result.
 */
HashReturn KECCAK512_File (hashState state, FILE *in)
{
	SHA3_CTX *context = (SHA3_CTX *) state;
	int len;
	unsigned char buffer[BUFFERSIZE];
	HashReturn retval;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_512)
		return BAD_ALGORITHM;

	while ((len = fread (buffer, 1, BUFFERSIZE, in))) {
		retval = KECCAK512_update (context, buffer, (DataLength)len << 3);
		if (retval != SUCCESS) return retval;
	}
	retval = KECCAK512_final (context, NULL);

	fclose (in);
	return retval;
}

HashReturn KECCAK512_HashToByte (hashState state, BYTE *out) 
{
	SHA3_CTX *context = (SHA3_CTX *) state;

	/* verify correct hashbitlen and magic	*/
	if (context->hashbitlen != HASH_BITLENGTH_KECCAK_512)
		return BAD_HASHBITLEN;

	if (context->magic != HASH_MAGIC_KECCAK_512)
		return BAD_ALGORITHM;

	memcpy (out, context->out, HASH_LENGTH_KECCAK_512);
	return SUCCESS;
}

