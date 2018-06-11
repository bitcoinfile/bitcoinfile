// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
	unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
	
	if (pindexLast == NULL)
        return nProofOfWorkLimit;

	if ( (( pindexLast->nHeight+1 ) == params.nBIFIForkHeight ) || 
		 (( pindexLast->nHeight+1 ) == params.nBIFIForkHeight+1 )){
		return UintToArith256(params.powBIFI501225Limit).GetCompact();
	}
	
    if ( pindexLast->nHeight+1 == params.nBIFIForkHeight + 2 ) 
		return UintToArith256(params.powBIFILimit).GetCompact();

    // Only change once per difficulty adjustment interval
	int liChangeH  =  pindexLast->nHeight+1; 
	int liInterval =  params.DifficultyAdjustmentInterval();
	
	if( pindexLast->nHeight > params.nBIFIForkHeight){
		liChangeH -= params.nBIFIForkHeight;
		liInterval = params.nBifiDifficultyAdjustmentInterval;
	}

	if ( ( liChangeH % liInterval ) != 0 )
	{
		if (params.fPowAllowMinDifficultyBlocks)
		{
			// Special difficulty rule for testnet:
			// If the new block's timestamp is more than 2* 10 minutes
			// then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
				return nProofOfWorkLimit;
			else
			{
				// Return the last non-special-min-difficulty-rules-block
				const CBlockIndex* pindex = pindexLast;
				while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
					pindex = pindex->pprev;
				return pindex->nBits;
			}
		}
		//EDA
		if ( pindexLast->nHeight > params.nBIFIForkHeight ){
			const CBlockIndex *pindexPrev12th = pindexLast->GetAncestor( pindexLast->nHeight - 12 );
			assert(pindexPrev12th);
			int64_t mtp12blocks = pindexLast->GetMedianTimePast() - pindexPrev12th->GetMedianTimePast();
			if ( mtp12blocks <  12 * 3600 ) {
				return pindexLast->nBits;
			}
			arith_uint256 bnNew;
			bnNew.SetCompact( pindexLast->nBits );
			bnNew += ( bnNew >> 2 );
			const arith_uint256 bnpowLimit = UintToArith256( params.powBIFILimit );
			if ( bnNew > bnpowLimit ) bnNew = bnpowLimit;
			return bnNew.GetCompact();
		}
		else{
			return pindexLast->nBits;
		}
		
	}
	// Go back by what we want to be 14 days worth of blocks()
	int nHeightFirst = pindexLast->nHeight - ( liInterval - 1);
	assert(nHeightFirst >= 0);
	const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
	assert(pindexFirst);
	return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting) return pindexLast->nBits;

	arith_uint256 bnNew;
	int64_t lnPowTargetTimespan = params.nPowTargetTimespan;
	int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
	// Limit adjustment step
	if ( pindexLast->nHeight > params.nBIFIForkHeight){
		lnPowTargetTimespan = params.nBifiDifficultyAdjustmentInterval* params.nBifiPowTargetSpacing;
		if ( nActualTimespan < lnPowTargetTimespan / 2 )	nActualTimespan = lnPowTargetTimespan / 2; 
		if ( nActualTimespan > lnPowTargetTimespan * 2 )	nActualTimespan = lnPowTargetTimespan * 2 ;
		const arith_uint256 bnPowLimit = UintToArith256(params.powBIFILimit);
		bnNew.SetCompact(pindexLast->nBits);
		bnNew *= nActualTimespan;
		bnNew /= lnPowTargetTimespan;
		if ( bnNew > bnPowLimit ) {
			bnNew = bnPowLimit;
		}
	}
	else{
		if ( nActualTimespan < (lnPowTargetTimespan)/4 )			nActualTimespan = ( lnPowTargetTimespan)/4;
		if ( nActualTimespan > (lnPowTargetTimespan)*4 )			nActualTimespan = ( lnPowTargetTimespan)*4;
		const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
		bnNew.SetCompact(pindexLast->nBits);
		bnNew *= nActualTimespan;
		bnNew /= lnPowTargetTimespan;
		if ( bnNew > bnPowLimit ) {
			bnNew = bnPowLimit;
		}
	}
	return bnNew.GetCompact();
}


bool CheckProofOfWork(int32_t nVersion, uint256 hash, unsigned int nBits, const Consensus::Params& params, int32_t nHeight)
{
	if ( hash.IsNull() ) {
		return false;
	}

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
	if(( nHeight == params.nBIFIForkHeight ) || ( nHeight == params.nBIFIForkHeight +1 )) {
		if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powBIFI501225Limit)){
			return false;
		}			
	}
	else if ( nHeight > params.nBIFIForkHeight )
	{
		if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powBIFILimit)){
			return false;
		}	
	}
	else{
		if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit)){
			return false;
		}
	}

    // Check proof of work matches claimed amount
	if (UintToArith256(hash) > bnTarget){
		return false;
	}  
	return true;
}
