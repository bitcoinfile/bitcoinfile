// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"
#include "hash.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "versionbits.h"
#include "sync.h"
#include <unordered_map>
#define							DEF_HASH_SIZE						( 32 ) 
#define							DEF_PER_PBLOCK_SIZE					( 262144 )
#define							DEF_SELECT							( 65536 )
#define							DEF_PER_BLOCK_LOTTERY_CNT			( 8192 )


std::string													g_sHashFolderRoot = "";
std::unordered_map< uint512Index, uint256, Hash512Hasher >	g_oHashCatchMap;
CCriticalSection											g_oHashCatchMapMutex;
std::unordered_map<uint512Index, uint256, Hash512Hasher>	g_oTempHashMap;
CCriticalSection											g_oTempHashMapMutex;			
char*														g_pIndexBeg = 0;
char*														g_pIndexEnd = 0;

bool CBlockHeader::ReadHashMem( uint512Index& aoHashIndex , uint256& aoHash) const{
	LOCK(g_oHashCatchMapMutex);
	std::unordered_map<uint512Index, uint256, Hash512Hasher>::iterator liIter = g_oHashCatchMap.find(aoHashIndex);
	if (liIter != g_oHashCatchMap.end()){
		aoHash = liIter->second;
		return true;
	}
	return false;
}

bool CBlockHeader::ReadHashMemTmp( uint512Index& aoHashIndex , uint256& aoHash )const{
	LOCK( g_oTempHashMapMutex );
	std::unordered_map<uint512Index, uint256, Hash512Hasher>::iterator liIter = g_oTempHashMap.find(aoHashIndex);
	if (liIter != g_oTempHashMap.end()){
		aoHash = liIter->second;
		return true;
	}
	return false;
}

bool CBlockHeader::SaveHashMemTmp( uint512Index& aoHashIndex, uint256& aoHash) const {
	LOCK(g_oTempHashMapMutex);
	if ( g_oTempHashMap.size() > 102400 ) g_oTempHashMap.clear();

	std::unordered_map< uint512Index, uint256, Hash512Hasher >::iterator liIter = g_oTempHashMap.find(aoHashIndex);
	
	if (liIter == g_oTempHashMap.end()){
		g_oTempHashMap.insert(std::make_pair(aoHashIndex, aoHash));
	}
	return true;
}

bool CBlockHeader::SaveHashMem( uint512Index& aoHashIndex, uint256& aoHash) const{
	LOCK(g_oHashCatchMapMutex);
	std::unordered_map< uint512Index, uint256, Hash512Hasher >::iterator liIter = g_oHashCatchMap.find(aoHashIndex);
	if (liIter == g_oHashCatchMap.end()){
		g_oHashCatchMap.insert(std::make_pair(aoHashIndex, aoHash));
	}
	return true;
}


bool CBlockHeader::CreateSeed( uint32_t aui32Nonce, unsigned char* apHashIn, unsigned char* apHashOut) const
{
	unsigned char lszPHash[256]								=	{0};
	unsigned char lszPHashTotal[DEF_PER_PBLOCK_SIZE]		=	{0};

	memcpy( lszPHash,  apHashIn, DEF_HASH_SIZE );

	char lsznNonce[256]										=	{0};
	sprintf( lsznNonce,"%u",  aui32Nonce );
	int liNonceLen											=	strlen(lsznNonce);
	memcpy( lszPHash + DEF_HASH_SIZE, lsznNonce, DEF_HASH_SIZE );

	unsigned char lszHashBuf[DEF_HASH_SIZE]					=	{0};
	KeccackHash256(( const unsigned char* )lszPHash, DEF_HASH_SIZE + liNonceLen, lszHashBuf);

	unsigned char lszBuf[ 500 ]		=	{0};
	for( int i = 0; i < DEF_PER_BLOCK_LOTTERY_CNT; ++i )
	{
		memcpy( lszBuf, lszHashBuf, DEF_HASH_SIZE );
		memcpy( lszBuf+DEF_HASH_SIZE, lsznNonce, liNonceLen );

		if( i == 5120 ) {
			cryptonight_hash(lszHashBuf, lszBuf, DEF_HASH_SIZE+liNonceLen );
		}
		else{
			KeccackHash256(( const unsigned char* )lszBuf, DEF_HASH_SIZE+liNonceLen, lszHashBuf);
		}
		memcpy( lszPHashTotal+i*DEF_HASH_SIZE, lszHashBuf, DEF_HASH_SIZE );
	}
	KeccackHash256(( const unsigned char* )lszPHashTotal, DEF_PER_PBLOCK_SIZE, lszHashBuf);
	unsigned int liAry[8] = {0};
	for( int j = 0; j < 8; ++j ){
		memcpy(&liAry[j], lszHashBuf+j*4, 4 );
	}
	for( int k = 0; k < 8; ++k ){
		unsigned int liValue;
		memcpy( &liValue, lszPHashTotal + nColNum*DEF_HASH_SIZE+k*4, 4 );
		liValue = liValue^liAry[k];
		memcpy( apHashOut + k*4, &liValue, 4);
	}
	return true;
}

void CBlockHeader::V2GetHeader( bool abSaveSeed ) const{
	unsigned char szHeader[120]={0};
	memcpy( szHeader + 0,		( unsigned char* )&nVersion,					4 );
	memcpy( szHeader + 4,		( unsigned char* )&nHeight,						4 );
	memcpy( szHeader + 8,		( unsigned char* )hashPrevBlock.begin(),		DEF_HASH_SIZE );
	memcpy( szHeader + 40,		( unsigned char* )hashMerkleRoot.begin(),		DEF_HASH_SIZE );
	memcpy( szHeader + 72,		( unsigned char* )hashUnique.begin(),			DEF_HASH_SIZE );
	memcpy( szHeader + 104,		( unsigned char* )&nBits,						4 );
	memcpy( szHeader + 108,		( unsigned char* )&nTime,						4 );

	uint512Index loHashIndex;
	loHashIndex.m_iHeight = nHeight;
	CSHA256 loCSha256;
	loCSha256.Reset();
	loCSha256.Write( ( const unsigned char* )szHeader, 112 );
	loCSha256.Finalize(loHashIndex.m_oLeft.begin());
	KeccackHash256( ( const unsigned char* )szHeader, 112, loHashIndex.m_oRight.begin());

	if (!ReadHashMem(loHashIndex, hashHeader)){
		if (!ReadHashMemTmp(loHashIndex, hashHeader)){
			CreateSeed( 4096, (unsigned char*)loHashIndex.m_oRight.begin(), hashHeader.begin());
			if (!abSaveSeed) SaveHashMemTmp(loHashIndex, hashHeader );
		}
		if (abSaveSeed) SaveHashMem(loHashIndex, hashHeader);
	}
}

void CBlockHeader::V2GetSeed( bool abSaveSeed, uint32_t ai32Nonce, uint256& aoSeed) const{
	unsigned char szBuffer[ 40 ]={0};
	memcpy( szBuffer,			( unsigned char* )&ai32Nonce,					4 );
	memcpy( szBuffer + 4,		( unsigned char* )&nColNum,						4 );
	memcpy( szBuffer + 8,		( unsigned char* )hashUnique.begin(),			DEF_HASH_SIZE );

	uint512Index loHashIndex;
	loHashIndex.m_iHeight = nHeight;
	CSHA256 loCSha256;
	loCSha256.Reset();
	loCSha256.Write( ( const unsigned char* )szBuffer, 40 );
	loCSha256.Finalize(loHashIndex.m_oLeft.begin());
	KeccackHash256( ( const unsigned char* )szBuffer, 40, loHashIndex.m_oRight.begin());
	
	if (!ReadHashMem(loHashIndex, aoSeed)){
		if (!ReadHashMemTmp(loHashIndex, aoSeed)){
			CreateSeed( ai32Nonce, (unsigned char*)hashUnique.begin(), aoSeed.begin());
			if (!abSaveSeed) SaveHashMemTmp(loHashIndex, aoSeed );
		}
		if (abSaveSeed) SaveHashMem(loHashIndex, aoSeed);
	}
}

uint256 CBlockHeader::GetHashImp( bool abSaveSeed , bool abIsCalSeed ) const {
	if ( nVersion & VERSIONBITS_FORK_II ){
		nColNum = hashPrevBlock.GetUint32(0)%DEF_PER_BLOCK_LOTTERY_CNT;
		if( nHeight >= BIFI_UPDATE_V2 ){
			hashBlock.SetNull();
			uint32_t luiBMove = nColNum%29;

			hashBlock.SetNull();

			if( hashUnique.IsNull())				return hashBlock;
			
			if ( abIsCalSeed ) {
				 hashSeed.SetNull();
				 hashSeedV2.SetNull();
				 hashHeader.SetNull();
			}

			if ( hashHeader.IsNull() )				V2GetHeader(abSaveSeed);
			if ( hashHeader.IsNull() ) 				return hashBlock;
	
			if ( hashSeed.IsNull() )				V2GetSeed( abSaveSeed, nNonce, hashSeed );
			if ( hashSeed.IsNull() ) 				return hashBlock;

			uint32_t luiLeft  = 0;
			uint32_t luiRight = 0;
			memcpy(&luiLeft,  hashHeader.begin(), 4 );
			memcpy(&luiRight, hashSeed.begin()+luiBMove, 4 );

			if ((luiLeft & 0xFEFEFEFE) == (luiRight & 0xFEFEFEFE)){

				 if ( hashSeedV2.IsNull() )			V2GetSeed( abSaveSeed, nNonceV2, hashSeedV2 );
				 if ( hashSeedV2.IsNull() ) 		return hashBlock;
					 
				 char lszBuf64[64], lszBuf32[32];
				 memcpy(lszBuf64,		hashSeed.begin(), 32 );
				 memcpy(lszBuf64+32,	hashHeader.begin(), 32 );
				 KeccackHash256( ( const unsigned char* )lszBuf64, 64, (unsigned char*) lszBuf32);
								 
				 memcpy(&luiLeft,  lszBuf32, 4 );
				 memcpy(&luiRight, hashSeedV2.begin()+luiBMove, 4 );

				 if ((luiLeft&0x84211248) == (luiRight&0x84211248)){
					 unsigned char lszBuf104[ 104 ] = {0};
					 memcpy( lszBuf104,				hashHeader.begin(),				DEF_HASH_SIZE );
					 memcpy( lszBuf104 + 32,		hashSeed.begin(),				DEF_HASH_SIZE );
					 memcpy( lszBuf104 + 64,		( unsigned char* )&nNonce,		4 );	
					 memcpy( lszBuf104 + 68,		hashSeedV2.begin(),				DEF_HASH_SIZE );
					 memcpy( lszBuf104 + 100,		( unsigned char* )&nNonceV2,	4 );	
					 KeccackHash256(( const unsigned char* )lszBuf104, 104, (unsigned char*) hashBlock.begin());
				 }
			}
			return hashBlock;
		} else {
			uint256  loHashResult;
			loHashResult.SetNull();
			if( hashUnique.IsNull()){
				return loHashResult;
			}

			hashSeed.SetNull();

			char lszIndex[ 150 ] = {0};
			sprintf( lszIndex,"%u_%u_%u_%u_%u_%u_%u_%u_%u_%u", 
				nColNum, hashUnique.GetUint32(0), hashUnique.GetUint32(1), hashUnique.GetUint32(2),
				hashUnique.GetUint32(3), hashUnique.GetUint32(4), hashUnique.GetUint32(5),
				hashUnique.GetUint32(6), hashUnique.GetUint32(7), nNonce );

			uint512Index loHashIndex;
			CSHA256 loCSha256;
			loCSha256.Reset();
			loCSha256.Write( ( const unsigned char* )lszIndex, 150 );
			loCSha256.Finalize(loHashIndex.m_oLeft.begin());
			KeccackHash256( ( const unsigned char* )lszIndex, 150, loHashIndex.m_oRight.begin());
			if (!ReadHashMem(loHashIndex, hashSeed)){
				if (!ReadHashMemTmp(loHashIndex, hashSeed)){
					CreateSeed( nNonce, (unsigned char*)hashUnique.begin(), hashSeed.begin());
					if (!abSaveSeed)
						SaveHashMemTmp(loHashIndex, hashSeed );
				}
				if (abSaveSeed) SaveHashMem(loHashIndex, hashSeed);
			}

			if (hashSeed.IsNull())	return loHashResult;

			if( nHeight  >= 501227 ){
				if ( ( hashSeed.GetUint32(0) % DEF_SELECT) != 
					( hashPrevBlock.GetUint32(0) % DEF_SELECT ) ){
						return loHashResult;
				}
			}
			GetHashBIFI( loHashResult, hashSeed.begin(), abSaveSeed, true  );
			return loHashResult;
		}
	}
	else return SerializeHash(*this);
}

void CBlockHeader::GetHashBIFI( uint256&  aoHashResult, unsigned char* apPrivateSeed, bool abSaveSeed, bool abIsMem) const{
	if ( hashHeader.IsNull()){
		unsigned char lszhashHeaderBuf[84] =	{0};
		memcpy( lszhashHeaderBuf,				( unsigned char* )&nVersion,					4);
		memcpy( lszhashHeaderBuf + 4,			( unsigned char* )hashPrevBlock.begin(),		32);
		memcpy( lszhashHeaderBuf + 36,			( unsigned char* )hashUnique.begin(),			32);
		memcpy( lszhashHeaderBuf + 68,			( unsigned char* )hashMerkleRoot.begin(),		4);
		memcpy( lszhashHeaderBuf + 72,			( unsigned char* )&nBits,						4);
		memcpy( lszhashHeaderBuf + 76,			( unsigned char* )&nHeight,						4);
		memcpy( lszhashHeaderBuf + 80,			( unsigned char* )&nTime,						4);
		if ( abIsMem )
		{
 			uint512Index loHashIndex;
 			CSHA256 loCSha256;
 			loCSha256.Reset();
 			loCSha256.Write(( const unsigned char* )lszhashHeaderBuf, 84);
 			loCSha256.Finalize(loHashIndex.m_oLeft.begin());
 			KeccackHash256( ( const unsigned char* )lszhashHeaderBuf, 84, loHashIndex.m_oRight.begin());
 			if ( !ReadHashMem( loHashIndex, hashHeader ) ){
 				if ( !ReadHashMemTmp( loHashIndex, hashHeader ) ) {
					char lszHash[DEF_HASH_SIZE] ={0};
 					KeccackHash256(( const unsigned char* )lszhashHeaderBuf, 84, ( unsigned char* )lszHash );
					CreateSeed(0, (unsigned char*)lszHash,  hashHeader.begin());				
					if ( !abSaveSeed ) SaveHashMemTmp(loHashIndex, hashHeader);
				}
				if (abSaveSeed) SaveHashMem(loHashIndex, hashHeader);
			}
		}
		else{
			char lszHash[DEF_HASH_SIZE] ={0};
			KeccackHash256( ( const unsigned char* )lszhashHeaderBuf, 84,(unsigned char*)lszHash);
			CreateSeed(0, ( unsigned char* )lszHash, hashHeader.begin() );
		}
	}

	if ( hashHeader.IsNull() ) {	
		aoHashResult.SetNull();
		return;
	}
	unsigned char lszHashBuf[68] =	{0};
	memcpy( lszHashBuf,			( unsigned char* )hashHeader.begin(),			32);
	memcpy( lszHashBuf + 32,	( unsigned char* )apPrivateSeed,				32);
	memcpy( lszHashBuf + 64,	( unsigned char* )&nNonce,						4);	
	KeccackHash256( ( const unsigned char* )lszHashBuf, 68 ,aoHashResult.begin() );
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, hashUnique=%s, nHeight=%u, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHashImp().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
		hashUnique.ToString(), 
		nHeight,
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
