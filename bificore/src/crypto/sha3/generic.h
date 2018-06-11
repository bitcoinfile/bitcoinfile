/*
 * Generic Hash and HMAC Program
 *
 * Copyright (C) 2009 Harald von Fellenberg <hvf@hvf.ch>
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

/* generic.h	some generic definitions
 * hvf 15.9.01 
 * hvf 20.6.02 -- add LARGE buffer size for file reading
 * hvf 25.02.07 add large file support for Linux on i386 arch
 * hvf 18.12.2008 add support for bitwise hashes
 * hvf 31.01.2009 align with SHA3-C-API
 */

#ifndef _GENERIC_H_
#define _GENERIC_H_

#include <ctype.h>

#ifdef i386
//#define _FILE_OFFSET_BITS 64
#define __USE_LARGEFILE64
#define __USE_FILE_OFFSET64
#endif

typedef	unsigned char	BYTE;
typedef unsigned long long uint64;

typedef unsigned int u32;
typedef unsigned int uint32;
typedef unsigned long long u64;

// SHA3 typedefs
typedef unsigned char	BitSequence;
typedef unsigned long long	DataLength;

typedef enum {
	SUCCESS	= 0,
	FAIL	= 1,
	BAD_HASHBITLEN	= 2,
	BAD_ALGORITHM	= 3,
} HashReturn;

// opaque typedef for hashState
typedef	void * hashState;

/* buffer size for file reading -- 128 kB */

#define BUFFERSIZE 131072

/* enum for tokenizer, used for bitstrings */
enum Token {
	ISEMPTY = 0,
	ISBIT,
	ISNUMBER,
	ISHEXNUMBER,
	ISSPACE,
	ISHASH,
	ISPIPE,
	ISCIRCUMFLEX,
	ISOTHER,
};

// struct token {
//     char *text;
//     enum Token token;
// };

#ifndef minex
#define minex(a,b) ((a)<(b)?(a):(b))
#endif

/* macros for bitwise hash updates	*/

#define	BITSPERBYTE		8
#define	BITSPERINT		32
#define	BITSPERLL		64

#define	BIT2BYTE		3
#define	BIT2INT			5
#define	BIT2LL			6

#define	BYTEINDEX(d)	((d)>>BIT2BYTE)
#define	INTINDEX(c)		((c)>>BIT2INT)
#define	LLINDEX(c)		((c)>>BIT2LL)

#define	BITPOSINBYTE(d)	((d) & 0x7)
#define	BITPOSININT(c)	((c) & 0x1F)
#define	BITPOSINLL(c)	((c) & 0x3F)

#define	FREEBITSINBYTE(c)	(BITSPERBYTE - BITPOSINBYTE(c))
#define	FREEBITSININT(c)	(BITSPERINT - BITPOSININT(c))
#define	FREEBITSINLL(c)		(BITSPERLL - BITPOSINLL(c))
//#define BITSUSEDINBYTE(d,e)	(minex(((e)-(d)),(BITSPERBYTE - BITPOSINBYTE(d))))
#define BITSUSEDINBYTE(d,e)	(minex(((e)-(d)), FREEBITSINBYTE(d)))

#define BYTEBITS2COPY(c,d,e)	(minex((FREEBITSINBYTE(c)), (BITSUSEDINBYTE((d),(e)))))
#define	BYTEMASK(c,d,e)	((~((~0)<<BYTEBITS2COPY((c),(d),(e))))<<(BITSPERBYTE-BITPOSINBYTE(d)-BYTEBITS2COPY((c),(d),(e))))

#define INTBITS2COPY(c,d,e)	(minex((FREEBITSININT(c)), (BITSUSEDINBYTE((d),(e)))))
#define	INTMASK(c,d,e)	((~((~0)<<INTBITS2COPY((c),(d),(e))))<<(BITSPERBYTE-BITPOSINBYTE(d)-INTBITS2COPY((c),(d),(e))))

#define LLBITS2COPY(c,d,e)	(minex((FREEBITSINLL(c)), (BITSUSEDINBYTE((d),(e)))))
#define	LLMASK(c,d,e)	((~((~0LL)<<LLBITS2COPY((c),(d),(e))))<<(BITSPERBYTE-BITPOSINBYTE(d)-LLBITS2COPY((c),(d),(e))))

#define	BYTELEFTSHIFT(c,d)	(BITPOSINBYTE(d) - BITPOSINBYTE(c))
#define	INTLEFTSHIFT(c,d)	(BITSPERINT - BITSPERBYTE + BITPOSINBYTE(d) - BITPOSININT(c))
#define	LLLEFTSHIFT(c,d)	(BITSPERLL - BITSPERBYTE + BITPOSINBYTE(d) - BITPOSINLL(c))

/* macros for MD4, MD5 - opposite byte ordering within ints */
#define BYTEPOSININTMD45(c)	(((c) >> BIT2BYTE) & 0x03)
#define BYTELEFTSHIFTMD45(c,d) (BYTELEFTSHIFT((c),(d)) + (BYTEPOSININTMD45(c))<<BIT2BYTE)



/* utility function to add bits to state buffer of ints */
extern DataLength AddBitsToArrayOfInts (
    unsigned int array[],   /* the array to which we add bits */
    int bitsusedinarray,    /* says how many bits are already stored in array */
    const BitSequence databuffer[], /* buffer containing the bits */
    DataLength  bitsindatabuffer,   /* total number of bits in the databuffer,
                                     * some may already have been consumed */
    int firstbitposindatabuffer     /* position of next bit to be consumed */
    );


/* utility function to add bits to state buffer of long longs */
extern DataLength AddBitsToArrayOfLL (
    uint64	array[],   /* the array to which we add bits */
    int bitsusedinarray,    /* says how many bits are already stored in array */
    const BitSequence databuffer[], /* buffer containing the bits */
    DataLength  bitsindatabuffer,   /* total number of bits in the databuffer,
                                     * some may already have been consumed */
    int firstbitposindatabuffer     /* position of next bit to be consumed */
    );

#endif
