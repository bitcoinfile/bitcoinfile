Bitcoin File
===============

https://www.bitcoinfile.org/

What is Bitcoinfile?
----------------

BitcoinFile(BIFI) is a point-to-point distributed file system based on blockchain technology and it 
aims to create a global decentralized file system combined with IPFS file system and bitcoin settlement 
network.The combined technology makes it more environmentally friend for the world, more fair and more 
rewarding for miners, more reliable and easier-to-use for users. It perfectly solves the problem of low 
stability in IPFS networks due to the inability of contributors to earn sufficient returns and the 
uselessness of power consumption in the process of bitcoin mining.


In the BitcoinFile network, all resource sharers (miners) can mine by sharing their own disk space and 
network bandwidth. The amount of BitcoinFile earned depends on how much disk space and network bandwidth 
it shares, and only the disk space and network bandwidth actually used by the users will be calculated 
as proof of work, thus improving the overall network performance and efficiency.



BitcoinFile is a fully self-monitored decentralized community. Resource-sharers (miners) and users are the community participants. About 17 billion of BitcoinFiles will be air dropped to the current holders of Bitcoins, and another 3 billion will be distributed to each resource sharer (miners) on a POC basis according to the community design rules. Network users have to pay BiFi when using BitcoinFile's network. The BitcoinFile foundation will mine 1.05 billion BiFi in advance, of which 0.7 billion will be used for marketing and ecological construction and the other 0.35 billion will be used for team incentives. The part used for team incentives will be locked for 4 years, unlocking 20% each year.


BitcoinFile(BIFI) is a fork of Bitcoin blockchain that occurs at block height 501225,and therewith a new 
chain will be generated as the BIFI. BIFI miners will begin creating blocks with a new proof-of-work 
algorithm, and will consecutively develop and enhance the protection for account transfer and privacy 
based on original features of BIFI.For more information, see https://www.bitcoinfile.org/

License
-------

BitcoinFile Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

proof-of-work
-------
The new proof-of-work of BiFiCore relies on SHA-3(https://en.wikipedia.org/wiki/SHA-3) and 
CryptoNight(https://en.bitcoin.it/wiki/CryptoNight) Mixed Mode. This approach is designed to 
encourage miners to use stored calculation result sets. Reuse of the result set during the 
mining process can realize the mining function, avoiding a large number of repeated operations 
and energy consumption.

#Seed generation

source                      | algorithm|target
----------------------------|----------|-------
[address]                   |Generate |[hash0]
[hash0+nNonceX]             |(sha3)|[hash1]
[hash1+nNonceX]             |(sha3)|[hash2]
...                         |... |...
[hash1+nNonceX]             |(CryptoNight)|[hash5120]
[hash5120+nNonceX]          |(sha3)|[hash5121]
...                         |
[hash8190+nNonceX]          |(sha3)|[hash8191]
[hash0 hash1... hash8191]   |(sha3)|[hashtotal]
[hash0]                     |^ [hashtotal]|[hash0_seed_nNonceX]
[hash1]		        |^ [hashtotal]|[hash1_seed_nNonceX]
...     | ...|...          
[hash8190]	        |^ [hashtotal]|[hash8190_seed_nNonceX]
[hash8191]                  |^ [hashtotal]|[hash8191_seed_nNonceX]

Each nNonce corresponds to a seed file. Each height selects 
one of the 8192 columns based on the hash value of the previous 
block and participates in the construction of a new block header.
