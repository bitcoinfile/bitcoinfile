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

/* integrated into fehashmac - hvf 16.08.2016 
 */

/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef _KeccakHashInterface_h_
#define _KeccakHashInterface_h_

/* retain only KeccakP1600	*/
#define KeccakP200_excluded
#define KeccakP400_excluded
#define KeccakP800_excluded
#undef  KeccakP1600_excluded

#ifndef KeccakP1600_excluded

#include "generic.h"
#include "KeccakSponge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if 0
typedef unsigned char BitSequence;
typedef size_t DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

typedef struct {
    KeccakWidth1600_SpongeInstance sponge;
    unsigned int fixedOutputLength;
    unsigned char delimitedSuffix;
} Keccak_HashInstance;
#endif


/* hash output length in bytes */
#define HASH_LENGTH_SHA3_224 28
#define HASH_LENGTH_SHA3_256 32
#define HASH_LENGTH_SHA3_384 48
#define HASH_LENGTH_SHA3_512 64
/* this is the default output length for shake128, shake256 */
#define HASH_LENGTH_SHAKE128  512
#define HASH_LENGTH_SHAKE256  512

/* XOF lengths can be arbitrary, but should a multiple of 12 for base64
 * processing. We choose 600 bytes (4800 bits) to make life in 
 * testsuite easier
 */
#define XOF_LENGTH_XOFSHAKE128	600
#define XOF_LENGTH_XOFSHAKE256	600

/* default XOF length is 512 bytes if nothing else specified    */
#define XOF_DEFAULT_LENGTH_XOFSHAKE128	512
#define XOF_DEFAULT_LENGTH_XOFSHAKE256	512

/* hash output length in bits */
#define HASH_BITLENGTH_SHA3_224  224
#define HASH_BITLENGTH_SHA3_256  256
#define HASH_BITLENGTH_SHA3_384  384
#define HASH_BITLENGTH_SHA3_512  512
/* this is again the default output length for shakeXXX in bits */
#define HASH_BITLENGTH_SHAKE128  4096
#define HASH_BITLENGTH_SHAKE256  4096
/* we squeeze 4800 bits each time for shake128, shake256 */
#define XOF_BITLENGTH_XOFSHAKE128	4800
#define XOF_BITLENGTH_XOFSHAKE256	4800

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_SHA3_224    144
#define HASH_INPUTBUFFER_SHA3_256    136
#define HASH_INPUTBUFFER_SHA3_384    104
#define HASH_INPUTBUFFER_SHA3_512    72
#define HASH_INPUTBUFFER_SHAKE128    168
#define HASH_INPUTBUFFER_SHAKE256    136

/* hash input buffer length in bits, equal to the "rate" */
#define HASH_INPUTBUFFER_BITS_SHA3_224   1152
#define HASH_INPUTBUFFER_BITS_SHA3_256   1088
#define HASH_INPUTBUFFER_BITS_SHA3_384   832
#define HASH_INPUTBUFFER_BITS_SHA3_512   576
#define HASH_INPUTBUFFER_BITS_SHAKE128   1344
#define HASH_INPUTBUFFER_BITS_SHAKE256   1088

/* hash magic values - SHA3_xxx etc in little endian notation */
#define HASH_MAGIC_SHA3_224  0x3432322d33414853ULL         /* SHA3-224   */
#define HASH_MAGIC_SHA3_256  0x3635322d33414853ULL         /* SHA3-256   */
#define HASH_MAGIC_SHA3_384  0x3438332d33414853ULL         /* SHA3-384   */
#define HASH_MAGIC_SHA3_512  0x3231352d33414853ULL         /* SHA3-512   */
#define HASH_MAGIC_SHAKE128  0x383231454b414853ULL         /* SHAKE128   */
#define HASH_MAGIC_SHAKE256  0x363532454b414853ULL         /* SHAKE256   */

/* hash output length in bytes */
#define HASH_LENGTH_KECCAK_224 28
#define HASH_LENGTH_KECCAK_256 32
#define HASH_LENGTH_KECCAK_384 48
#define HASH_LENGTH_KECCAK_512 64

/* hash output length in bits */
#define HASH_BITLENGTH_KECCAK_224  224
#define HASH_BITLENGTH_KECCAK_256  256
#define HASH_BITLENGTH_KECCAK_384  384
#define HASH_BITLENGTH_KECCAK_512  512

/* hash input buffer length in bytes */
#define HASH_INPUTBUFFER_KECCAK_224    144
#define HASH_INPUTBUFFER_KECCAK_256    136
#define HASH_INPUTBUFFER_KECCAK_384    104
#define HASH_INPUTBUFFER_KECCAK_512    72

/* hash input buffer length in bits */
#define HASH_INPUTBUFFER_BITS_KECCAK_224   1152
#define HASH_INPUTBUFFER_BITS_KECCAK_256   1088
#define HASH_INPUTBUFFER_BITS_KECCAK_384   832
#define HASH_INPUTBUFFER_BITS_KECCAK_512   576

/* hash magic values - KECCAKxxx etc in little endian notation */
#define HASH_MAGIC_KECCAK_224  0x343232414343454bULL         /* KECCA224   */
#define HASH_MAGIC_KECCAK_256  0x363532414343454bULL         /* KECCA256   */
#define HASH_MAGIC_KECCAK_384  0x343833414343454bULL         /* KECCA384   */
#define HASH_MAGIC_KECCAK_512  0x323135414343454bULL         /* KECCA512   */

/* taken over from genKAT.c	*/
/* must be equal to XOF_BITLENGTH_SHAKE128 and XOF_BITLENGTH_SHAKE256 */
#define SqueezingOutputLength 4800

typedef struct {
    /* required field: hashbitlen   */
    unsigned int    hashbitlen;

    /* magic token - SHA3-xxx in LSB notation   */
    DataLength      magic;

    /* internal state   */
    KeccakWidth1600_SpongeInstance sponge;

	/* set to hashbitlen */
    unsigned int fixedOutputLength;
    unsigned char delimitedSuffix;

    /* output buffer of hash, new 600 bytes  */
    BitSequence     out[SqueezingOutputLength/8];

	/* here come additional parameters that we may need for
	 * - producing base64 coded output
	 * - produing arbitrary long output (extendable output, XOF)
	 * - producing binary output (only if output does not go to a tty)
	 */

	/* base64 output flag	*/
	int	base64flag;

	/* extendable output function flag (XOF) and length
	 * if set, xoflength gives the requested length in bytes
	 * if cleared, default length is produced */

	int	xof_OK;		/* 1 for XOF function	*/
	int	xofflag;

	/* -1 means infinity, default is 512 bytes, HASH_LENGTH_SHAKExxx	*/
	long long	xoflength;

	/* xofinfinity makes it easier to deal with it */
	int xofinfinity;

	/* XOF means we call nnn_Final more than once
	 * squeezeflag tells we come for squeezing 
	 * this_chunk_size tells how much data we get in this call to nnn_Final
	 * more_size tells how much data still follows, 0 means end
	 * -1 means infinity
	 */

	int squeezeflag;
	int this_chunk_size;
	long long	more_size;

	/* binary output flag (not honored for output on terminal)	*/
	int	binoutflag;		// not yet implemented

} Keccak_HashInstance;

/* typedef SHA3_CTX to be aligned with other hash algos	*/
typedef	Keccak_HashInstance SHA3_CTX;

/* this is how we pass extra data to the XOF functions	*/
typedef struct	extra {

    /* magic token - SHA3-xxx in LSB notation   */
    DataLength      magic;

	/* base64 output flag	*/
	int	base64flag;

	/* extendable output function flag (XOF) and length
	 * if set, xoflength gives the requested length in bytes
	 * if cleared, default length is produced */

	int	xofflag;
	/* -1 means infinity, default is 512 bytes, HASH_LENGTH_SHAKExxx	*/
	long long	xoflength;

	/* binary output flag (not honored for output on terminal)	*/
	int	binoutflag;

	/* return parameters: this_chunk_size, more_size
	 * this_chunk_size tells how much data we get in this call to xxx_Final
	 * more_size tells how much data is still waiting after this call
	 * more_size == 0 means we are done
	 */

	size_t	this_chunk_size;
	long long	more_size;
	
} *EXTRA_DATA;

	

/**
  * Function to initialize the Keccak[r, c] sponge function instance used in sequential hashing mode.
  * @param  hashInstance    Pointer to the hash instance to be initialized.
  * @param  rate        The value of the rate r.
  * @param  capacity    The value of the capacity c.
  * @param  hashbitlen  The desired number of output bits,
  *                     or 0 for an arbitrarily-long output.
  * @param  delimitedSuffix Bits that will be automatically appended to the end
  *                         of the input message, as in domain separation.
  *                         This is a byte containing from 0 to 7 bits
  *                         formatted like the @a delimitedData parameter of
  *                         the Keccak_SpongeAbsorbLastFewBits() function.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  * @return SUCCESS if successful, FAIL otherwise.
  */
HashReturn Keccak_HashInitialize(Keccak_HashInstance *hashInstance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix);

/** Macro to initialize a SHAKE128 instance as specified in the FIPS 202 standard.
  */
#define Keccak_HashInitialize_SHAKE128(hashInstance)        Keccak_HashInitialize(hashInstance, 1344,  256,   0, 0x1F)

/** Macro to initialize a SHAKE256 instance as specified in the FIPS 202 standard.
  */
#define Keccak_HashInitialize_SHAKE256(hashInstance)        Keccak_HashInitialize(hashInstance, 1088,  512,   0, 0x1F)

/** Macro to initialize a SHA3-224 instance as specified in the FIPS 202 standard.
  */
#define Keccak_HashInitialize_SHA3_224(hashInstance)        Keccak_HashInitialize(hashInstance, 1152,  448, 224, 0x06)

/** Macro to initialize a SHA3-256 instance as specified in the FIPS 202 standard.
  */
#define Keccak_HashInitialize_SHA3_256(hashInstance)        Keccak_HashInitialize(hashInstance, 1088,  512, 256, 0x06)

/** Macro to initialize a SHA3-384 instance as specified in the FIPS 202 standard.
  */
#define Keccak_HashInitialize_SHA3_384(hashInstance)        Keccak_HashInitialize(hashInstance,  832,  768, 384, 0x06)

/** Macro to initialize a SHA3-512 instance as specified in the FIPS 202 standard.
  */
#define Keccak_HashInitialize_SHA3_512(hashInstance)        Keccak_HashInitialize(hashInstance,  576, 1024, 512, 0x06)

/** Macro to initialize a keccak224 instance as specified in the SHA3 submission.
  */
#define Keccak_HashInitialize_keccak224(hashInstance)        Keccak_HashInitialize(hashInstance, 1152,  448, 224, 0x01)

/** Macro to initialize a keccak256 instance as specified in the SHA3 submission.
  */
#define Keccak_HashInitialize_keccak256(hashInstance)        Keccak_HashInitialize(hashInstance, 1088,  512, 256, 0x01)

/** Macro to initialize a keccak384 instance as specified in the SHA3 submission.
  */
#define Keccak_HashInitialize_keccak384(hashInstance)        Keccak_HashInitialize(hashInstance,  832,  768, 384, 0x01)

/** Macro to initialize a keccak512 instance as specified in the SHA3 submission.
  */
#define Keccak_HashInitialize_keccak512(hashInstance)        Keccak_HashInitialize(hashInstance,  576, 1024, 512, 0x01)

/**
  * Function to give input data to be absorbed.
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * @param  data        Pointer to the input data.
  *                     When @a databitLen is not a multiple of 8, the last bits of data must be
  *                     in the least significant bits of the last byte (little-endian convention).
  * @param  databitLen  The number of input bits provided in the input data.
  * @pre    In the previous call to Keccak_HashUpdate(), databitlen was a multiple of 8.
  * @return SUCCESS if successful, FAIL otherwise.
  */
HashReturn Keccak_HashUpdate(Keccak_HashInstance *hashInstance, const BitSequence *data, DataLength databitlen);

/**
  * Function to call after all input blocks have been input and to get
  * output bits if the length was specified when calling Keccak_HashInitialize().
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * If @a hashbitlen was not 0 in the call to Keccak_HashInitialize(), the number of
  *     output bits is equal to @a hashbitlen.
  * If @a hashbitlen was 0 in the call to Keccak_HashInitialize(), the output bits
  *     must be extracted using the Keccak_HashSqueeze() function.
  * @param  hashval     Pointer to the buffer where to store the output data.
  * @return SUCCESS if successful, FAIL otherwise.
  */
HashReturn Keccak_HashFinal(Keccak_HashInstance *hashInstance, BitSequence *hashval);

 /**
  * Function to squeeze output data.
  * @param  hashInstance    Pointer to the hash instance initialized by Keccak_HashInitialize().
  * @param  data        Pointer to the buffer where to store the output data.
  * @param  databitlen  The number of output bits desired (must be a multiple of 8).
  * @pre    Keccak_HashFinal() must have been already called.
  * @pre    @a databitlen is a multiple of 8.
  * @return SUCCESS if successful, FAIL otherwise.
  */
HashReturn Keccak_HashSqueeze(Keccak_HashInstance *hashInstance, BitSequence *data, DataLength databitlen);

#endif


/*********** SHA3-224 definitions *********/
/* initialize context */
extern HashReturn SHA3_224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA3_224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is LSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA3_224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA3_224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA3_224_File (hashState state, FILE *in);
extern void SHA3_224_Print (SHA3_CTX *context);
extern HashReturn SHA3_224_HashToByte (hashState state, BYTE *out);


/*********** SHA3-256 definitions *********/
/* initialize context */
extern HashReturn SHA3_256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA3_256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is LSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA3_256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA3_256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA3_256_File (hashState state, FILE *in);
extern void SHA3_256_Print (SHA3_CTX *context);
extern HashReturn SHA3_256_HashToByte (hashState state, BYTE *out);


/*********** SHA3-384 definitions *********/
/* initialize context */
extern HashReturn SHA3_384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA3_384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is LSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA3_384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA3_384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA3_384_File (hashState state, FILE *in);
extern void SHA3_384_Print (SHA3_CTX *context);
extern HashReturn SHA3_384_HashToByte (hashState state, BYTE *out);

/*********** SHA3-512 definitions *********/
/* initialize context */
extern HashReturn SHA3_512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHA3_512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is LSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHA3_512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHA3_512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHA3_512_File (hashState state, FILE *in);
extern void SHA3_512_Print (SHA3_CTX *context);
extern HashReturn SHA3_512_HashToByte (hashState state, BYTE *out);


/*********** SHAKE128 definitions *********/
/* initialize context */
extern HashReturn SHAKE128_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHAKE128_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is LSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHAKE128_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHAKE128_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHAKE128_File (hashState state, FILE *in);
extern void SHAKE128_Print (SHA3_CTX *context);
extern HashReturn SHAKE128_HashToByte (hashState state, BYTE *out);

/*********** SHAKE256 definitions *********/
/* initialize context */
extern HashReturn SHAKE256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  SHAKE256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is LSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  SHAKE256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn SHAKE256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn SHAKE256_File (hashState state, FILE *in);
extern void SHAKE256_Print (SHA3_CTX *context);
extern HashReturn SHAKE256_HashToByte (hashState state, BYTE *out);

/*********** XOFSHAKE128 definitions *********/
/* initialize context */
extern HashReturn XOFSHAKE128_init (hashState  *state, int hashbitlen, EXTRA_DATA extra);
/* update context, may be called many times - same as for SHAKE128 */
#define XOFSHAKE128_update  SHAKE128_update
/* produce hash and print */
extern HashReturn  XOFSHAKE128_final (hashState state, BitSequence *hashval);
extern HashReturn  XOFSHAKE128_File  (hashState state, FILE *in);
extern HashReturn  XOFSHAKE128_HashToByte (hashState state, BYTE *out);

/* the following functions are currently not implemented:
 * XOFSHAKE128_hash
 * XOFSHAKE128_Print
 */

/*********** XOFSHAKE256 definitions *********/
/* initialize context */
extern HashReturn XOFSHAKE256_init (hashState  *state, int hashbitlen, EXTRA_DATA extra);
/* update context, may be called many times - same as for SHAKE256 */
#define XOFSHAKE256_update  SHAKE256_update
/* produce hash and print */
extern HashReturn  XOFSHAKE256_final (hashState state, BitSequence *hashval);
extern HashReturn  XOFSHAKE256_File  (hashState state, FILE *in);
extern HashReturn  XOFSHAKE256_HashToByte (hashState state, BYTE *out);

/* the following functions are currently not implemented:
 * XOFSHAKE256_hash
 * XOFSHAKE256_Print
 */

/* 
 * parameter safe wrappers for KECCAK routines for each hash length
 */

/*********** KECCAK224 definitions *********/
/* initialize context */
extern HashReturn KECCAK224_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  KECCAK224_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  KECCAK224_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn KECCAK224_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn KECCAK224_File (hashState state, FILE *in);
extern void KECCAK224_Print (SHA3_CTX *context);
extern HashReturn KECCAK224_HashToByte (hashState state, BYTE *out);

/*********** KECCAK256 definitions *********/
/* initialize context */
extern HashReturn KECCAK256_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  KECCAK256_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  KECCAK256_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn KECCAK256_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn KECCAK256_File (hashState state, FILE *in);
extern void KECCAK256_Print (SHA3_CTX *context);
extern HashReturn KECCAK256_HashToByte (hashState state, BYTE *out);

/*********** KECCAK384 definitions *********/
/* initialize context */
extern HashReturn KECCAK384_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  KECCAK384_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  KECCAK384_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn KECCAK384_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn KECCAK384_File (hashState state, FILE *in);
extern void KECCAK384_Print (SHA3_CTX *context);
extern HashReturn KECCAK384_HashToByte (hashState state, BYTE *out);

/*********** KECCAK512 definitions *********/
/* initialize context */
extern HashReturn KECCAK512_init (hashState  *state, int hashbitlen);
/* update context, may be called many times */
extern HashReturn  KECCAK512_update (
    hashState state,          /* previously initialized context */
    const BitSequence *buffer,  /* bit buffer, first bit is MSB in [0] */
    DataLength databitlen);      /* number of bits to process from buffer */
/* produce hash and return in hashval */
extern HashReturn  KECCAK512_final (hashState state, BitSequence *hashval);
/* calculate hash all-in-one */
HashReturn KECCAK512_hash (int hashbitlen, const BitSequence *data,
                      DataLength databitlen, BitSequence *hashval);

extern HashReturn KECCAK512_File (hashState state, FILE *in);
extern void KECCAK512_Print (SHA3_CTX *context);
extern HashReturn KECCAK512_HashToByte (hashState state, BYTE *out);


#endif
