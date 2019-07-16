// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"


static const int32_t BIFI_UPDATE_V2			= 628550;
static const int32_t VERSIONBITS_FORK_II	= 0x80000000UL;
#define DEF_INVALID_COL  ( 9999 )


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
	//static const size_t HEADER_SIZE = 4+32+32+4+4+4;
    // header
    int32_t					nVersion;
    uint256					hashPrevBlock;
    uint256					hashMerkleRoot;	
	mutable uint256			hashUnique;
	int32_t					nHeight;
	uint32_t				nTime;
    uint32_t				nBits;
    uint32_t				nNonce;

	mutable uint32_t		nColNum;
	mutable uint256			hashSeed;
	mutable uint256			hashHeader;

	uint32_t				nNonceV2;
	mutable uint256			hashSeedV2;
	mutable uint256			hashBlock;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
		if( this->nVersion & VERSIONBITS_FORK_II ){
			READWRITE( hashUnique );
			READWRITE( nHeight );
			if(this->nHeight >= BIFI_UPDATE_V2){
				READWRITE( hashSeed );
				READWRITE( hashHeader );
				READWRITE( hashSeedV2 );
				READWRITE( nNonceV2 );
				READWRITE( hashBlock );
			}
		} 
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
		hashUnique.SetNull();
		hashHeader.SetNull();
		hashSeed.SetNull();
		hashSeedV2.SetNull();
		hashBlock.SetNull();
		nHeight			=	0;
        nTime			=	0;
        nBits			=	0;
        nNonce			=	0;
		nNonceV2		=	0;
		nColNum			=	DEF_INVALID_COL;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

	uint256 GetHashImp( bool abSaveSeed = false, bool abIsCalSeed = true )																const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
	
private:
	void		GetHashBIFI( uint256& aoHashResult, 
							 unsigned char* apPrivateSeed, 
							 bool abSaveSeed = false, 
							 bool abIsMem = true )																						const;

	bool		CreateSeed( uint32_t aui32Nonce, unsigned char* apHashIn, unsigned char* apHashOut)										const;

 	bool		ReadHashMem( uint512Index& aoHashIndex, uint256& aoHash)																const;
 	bool		SaveHashMem( uint512Index& aoHashIndex, uint256& aoHash)																const;
 
 	bool		ReadHashMemTmp( uint512Index& aoHashIndex, uint256& aoHash)																const;
 	bool		SaveHashMemTmp( uint512Index& aoHashIndex, uint256& aoHash)																const;

	void		V2GetHeader( bool abSaveSeed)																							const;
	void		V2GetSeed( bool abSaveSeed, uint32_t ai32Nonce,uint256& aoHash )														const;

};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion				=	nVersion;
        block.hashPrevBlock			=	hashPrevBlock;
        block.hashMerkleRoot		=	hashMerkleRoot;
		block.hashUnique			=	hashUnique;
		block.nHeight				=	nHeight;
        block.nTime					=	nTime;
        block.nBits					=	nBits;
        block.nNonce				=	nNonce;
		block.nColNum				=	nColNum;
		block.hashSeed				=	hashSeed;
		block.hashHeader			=	hashHeader;
		block.hashSeedV2			=	hashSeedV2;
		block.nNonceV2				=	nNonceV2;
		block.hashBlock				=	hashBlock;
        return block;
    }
    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
