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

Procedures of mining configuration:
-------
1. Create the text configuration file bitcoinfile.conf.

2. Add the configuration item iiconfig in the configuration file.
iiconfig=C:\seeds\ii\;1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;120;
a. C:\seeds\ii\; [Mining Directory] represents the storage directory of mining seed which can be set up on any existed disk location (disk C is not required), the directory ahead is an example.
b. 1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; [Transfer Address] represents the mining address (i.e. a bitcoin address) associated with the seed.
c. 120; [Disk Space] represents a total size of 120G(minimum 1G, and the maximum is depending on the disk space remaining in your folder).

(Note: '\' at the end of a directory is required when configuring Windows system, and ‘/’ at the end of directory is required when configuring Linux system.
A “;” is required to separate Mining Directory, Transferr Address, Disk Space, and to end every parameter.)

3. Add item iispoc to the configuration file.
Iispoc =1 indicates starting mining.

4. Run bitcoinfiled.exe, then stop after one minute (make sure the Windows operating system disk or the /root folder disk of Ubuntu has more than 200G of remaining space).

5. Open the %appdata%\Bitcoinfile directory on Windows, or open /root/.bitcoinfile directory on Ubuntu.

6. Copy the bitcoinfile.conf which is created and configured in the first three steps to the directory opened in step 5.

7. After starting bitcoinfile-qt.exe, click the “Accept/Request Payment" button to generate a payment receiving address (or to generate a payment receiving address for other wallets like bitpie).

8. Copy the payment receiving address, and replace the invalid configuration address "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" in iiconfig to the new address, and save the file.

9. Run bitcoinfiled.exe again to start BiFi mining.

10. The bitcoinfiled.exe needs to synchronize complete full nodal data before mining (this process takes time depending on the current full nodal supply capacity and your download bandwidth).

11. If the payment receiving address needs to be replaced during mining, the mining procedure needs to be stopped and the configuration files need to be modified, which means all the documents under the "C:\seeds ii\" directory need to be deleted and the mining procedure needs to launch again.

12. By adding the configuration item prune=550 through bitcoinfile.conf, a 160G block data can be clipped to 4-5G (the download date is still more than 160G, but it can be clipped while downloading).

13. Windows version download address https://explorer.bitcoinfile.org/download/BiFiCore (Beta) _Windows_x86. Zip

14 Ubuntu version download address https://explorer.bitcoinfile.org/download/BiFiCore (Beta) _Ubuntu16_x86_64. Zip


#===========The Windows configuration file case begins===========
prune=550
iiconfig=c:\seeds\;1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;20;
iispoc=1
#===========Configuration file case ends===========


#===========Ubuntu16 configuration file case begins===========
prune=550
iiconfig=/root/seeds/;1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;20;
iispoc=1
#===========Configuration file case ends===========
