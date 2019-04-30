// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <stdexcept>
#include <string>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_GETBLOCKTEMPLATE_MAX_BLOCK_SIZE	196608 //size of block (bytes) that is the maximum that miners will produce
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_TRANSACTION_VERSION                     2
#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     0
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               60

// MONEY_SUPPLY - total number coins to be generated
#define MONEY_SUPPLY                                    ((uint64_t)(-1))
#define EMISSION_SPEED_FACTOR_PER_MINUTE                (20)
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)300000000000) // 3 * pow(10, 11)

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    10000000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    8000000 //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                12
// COIN - number of smallest units in one coin
#define COIN                                            ((uint64_t)1000000000000) // pow(10, 12)

#define FEE_PER_KB_OLD                                  ((uint64_t)10000000000) // pow(10, 10)
#define FEE_PER_KB                                      ((uint64_t)2000000000) // 2 * pow(10, 9)
#define FEE_PER_BYTE                                    ((uint64_t)300000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)2000000000) // 2 * pow(10,9)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000000) // 10 * pow(10,12)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)2000000000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT         ((uint64_t)3000)

#define ORPHANED_BLOCKS_MAX_COUNT                       100


#define DIFFICULTY_TARGET_V2                            120  // seconds
#define DIFFICULTY_TARGET_V1                            60  // seconds - before first fork
#define DIFFICULTY_WINDOW                               720 // blocks
#define DIFFICULTY_LAG                                  15  // !!!
#define DIFFICULTY_CUT                                  60  // timestamps to cut after sorting
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW + DIFFICULTY_LAG


#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET_V1 //just alias; used by tests


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20     //by default, blocks count in blocks downloading

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT           1000

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                   8
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       2048       // kB/s
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     8192       // kB/s

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define ALLOW_DEBUG_COMMANDS

#define CRYPTONOTE_NAME                         "abelian"
#define CRYPTONOTE_POOLDATA_FILENAME            "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_DYNAMIC_FEE                  4
#define HF_VERSION_MIN_MIXIN_4                  6
#define HF_VERSION_MIN_MIXIN_6                  7
#define HF_VERSION_MIN_MIXIN_10                 8
#define HF_VERSION_ENFORCE_RCT                  6
#define HF_VERSION_PER_BYTE_FEE                 8
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       10
#define HF_VERSION_SMALLER_BP                   10

#define PER_KB_FEE_QUANTIZATION_DECIMALS        8

#define HASH_OF_HASHES_STEP                     256

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096 // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3 // the higher, the more space saved
#define CRYPTONOTE_PRUNING_TIP_BLOCKS           5500 // the smaller, the more space saved
//#define CRYPTONOTE_PRUNING_DEBUG_SPOOF_SEED

// New constants are intended to go here
namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)2000000000); // 2 * pow(10, 9)
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100000000); // pow(10, 8)
  std::string const P2P_REMOTE_DEBUG_TRUSTED_PUB_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

  uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 18;
  uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 19;
  uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 42;
  uint16_t const P2P_DEFAULT_PORT = 18080;
  uint16_t const RPC_DEFAULT_PORT = 18081;
  uint16_t const ZMQ_RPC_DEFAULT_PORT = 18082;
  boost::uuids::uuid const NETWORK_ID = { {
      0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10
    } }; // Bender's nightmare
  std::string const GENESIS_TX = "";
  uint32_t const GENESIS_NONCE = 10000;

  namespace testnet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 53;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;
    uint16_t const P2P_DEFAULT_PORT = 28080;
    uint16_t const RPC_DEFAULT_PORT = 28081;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 28082;
    boost::uuids::uuid const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x11
      } }; // Bender's daydream
    std::string const GENESIS_TX = "013c01ff0006ff9fdb5802868be32bb18371b78a3925ae8289951a6f82e1c418511ada32e7c2c33d1dac1237ce446a09796634f71720f149e0d9da7d1b44292d350dfd1ce1819b1dc0cfa4039dcb3c18ec767d60998c9fbf6c9ca2216b67bd04f819077bf0fd6bfbfb0aae2313b8a599eb9f61d1eb88aa4e0fd02badd3f3a170dd774712d57183bb80349b31a68e0108ecf410b5f27e49d67e641790ab2a4edac7de4dde52c792bcc87950ad44026fc841eb99846bc4087f7abf17fd0f642bd9a4a97f457f11e5f4ad7c9401816ddd2718922e8d7e55449e2467335736fadd5ff45ce93ba85595379da57c2d66bf52ccab6c24a662e8c0aa837cc855c3c1e38399909a6cd2cae26c15bd01398d2d9b9358115234d2f216056e054f9f5e3380f8e12cf54f3e083dc8e8077563c2a13ef11b120e1781dc9fa73375772be089c177dddf2c1f2336104845b16a1387520f9c53d04c622ddec118d2963a33cd6ebdb4af5680c5fe518912bf0fb97bb9b7e30a9722a350df9304fb92d1718a7987614044fe811084eb14524eec9d80cd0f33da79f1cf87d0bf11f6e390d3e22ae37d192e873de0c9bb4b1a52d5adef5e9211b913d3889dfe65bfff6c5076fd5f1d1aa973717780f28816b40da37d16392fccc02a30207ab1989608236ed498dd78a203150df66d95e0e4fe283d069cd9cb6efe6fd71f54bfa54bad403acb5ae83343fc1b8257b2369c7e3fc5a29c76e5f7fd876525fc823ac8482c366443ecd2a71e147f55eaa184fb6b8e47fd9624e51417cf5d39b748157880979c2bdc4832141e21926c5f857ae1b85929f0be09304cdcee2fe7dd010bdbcccc141e48bbd44d0c68086110283e6c806b96a562df248a69f069dd1279062fb9396ca2fd4bcec94ff5fd32cd53507a923c2e673803837fc2effaedf5e2c5eaebb312a2e528a638f34d3affba23ce99c666b3f56dce896ebe1ba6f23fcf951f81e3f14554e72d488c56bc6fe350aabaaaa5842abfcf5229921560348351b92338f60799667d722c1d36b1c99b46dfc208d8713a7bd235660b8efcb205c800831fc4a88e05b5f3c30e819a4e003c22766c3a8ede96d9ff760c354b87fc5389904001d19beff1ac14bba3ee441f79b6fc5c06bc3431b7ba507b07dfe91bdde17164d76d08e1effa1e9d7eacde6e2ba2ef9611c6da9a2a2b454bbc440b181e5601a85d52108371cec5e421122a6c381fc83cebb1a636e5dbff4db392ff02a0bcdd1673c6fe2da0526ad34998d9453a61c9106bc122bb76ff268328b41e29976bb27d1725c343978c1f42b0152e35ada3492e8b0883dc2ff7704d6d3d4a1a0b2c96e187cbd2cc339c283ccc167726476357e4b9dcfde36720b94c0517cce257fb92b6c62bec786ee81bfe6a87cb9013a566506503b2434aa9e33371402b76d17af0c63b396e85c63dd9051fc371652b93f8cd69ce9e193fe9fdda5c864b63ee497b9373db9f823836913ae829fc49debeaf3613045e7b5f86752fbd4c0214fc31ea2fdab388ef14fc7413eab239f19aebe71a343b2e66a0152241f76e06c304d6c12f7859d08b1f2802d53d9d21d56f0fce6afcd9ca23dc0ca665fed648c0b36966e5bdbffb588f382b64a86ca14f4aa9136d0db2bf470f6da66cbe312364a6ad88f473c7c65234672ff8d22e7a71a69418ecae5da5d303152e79c23ec24fcd599f993457557c30f7c4e0d00402bfad5610557bd3d391f080a8d6b90702868be32bb18371b78a3925ae8289951a6f82e1c418511ada32e7c2c33d1dac1237ce446a09796634f71720f149e0d9da7d1b44292d350dfd1ce1819b1dc0cfa4039dcb3c18ec767d60998c9fbf6c9ca2216b67bd04f819077bf0fd6bfbfb0aae2313b8a599eb9f61d1eb88aa4e0fd02badd3f3a170dd774712d57183bb80349b31a68e0108ecf410b5f27e49d67e641790ab2a4edac7de4dde52c792bcc87950ad44026fc841eb99846bc4087f7abf17fd0f642bd9a4a97f457f11e5f4ad7c9401816ddd2718922e8d7e55449e2467335736fadd5ff45ce93ba85595379da57c2d66bf52ccab6c24a662e8c0aa837cc855c3c1e38399909a6cd2cae26c15bd01398d2d9b9358115234d2f216056e054f9f5e3380f8e12cf54f3e083dc8e8077563c2a13ef11b120e1781dc9fa73375772be089c177dddf2c1f2336104845b16a1387520f9c53d04c622ddec118d2963a33cd6ebdb4af5680c5fe518912bf0fb97bb9b7e30a9722a350df9304fb92d1718a7987614044fe811084eb14524eec9d80cd0f33da79f1cf87d0bf11f6e390d3e22ae37d192e873de0c9bb4b1a52d5adef5e9211b913d3889dfe65bfff6c5076fd5f1d1aa973717780f28816b40da37d16392fccc02a30207ab1989608236ed498dd78a203150df66d95e0e4fe283d069cd9cb6efe6fd71f54bfa54bad403acb5ae83343fc1b8257b2369c7e3fc5a29c76e5f7fd876525fc823ac8482c366443ecd2a71e147f55eaa184fb6b8e47fd9624e51417cf5d39b748157880979c2bdc4832141e21926c5f857ae1b85929f0be09304cdcee2fe7dd010bdbcccc141e48bbd44d0c68086110283e6c806b96a562df248a69f069dd1279062fb9396ca2fd4bcec94ff5fd32cd53507a923c2e673803837fc2effaedf5e2c5eaebb312a2e528a638f34d3affba23ce99c666b3f56dce896ebe1ba6f23fcf951f81e3f14554e72d488c56bc6fe350aabaaaa5842abfcf5229921560348351b92338f60799667d722c1d36b1c99b46dfc208d8713a7bd235660b8efcb205c800831fc4a88e05b5f3c30e819a4e003c22766c3a8ede96d9ff760c354b87fc5389904001d19beff1ac14bba3ee441f79b6fc5c06bc3431b7ba507b07dfe91bdde17164d76d08e1effa1e9d7eacde6e2ba2ef9611c6da9a2a2b454bbc440b181e5601a85d52108371cec5e421122a6c381fc83cebb1a636e5dbff4db392ff02a0bcdd1673c6fe2da0526ad34998d9453a61c9106bc122bb76ff268328b41e29976bb27d1725c343978c1f42b0152e35ada3492e8b0883dc2ff7704d6d3d4a1a0b2c96e187cbd2cc339c283ccc167726476357e4b9dcfde36720b94c0517cce257fb92b6c62bec786ee81bfe6a87cb9013a566506503b2434aa9e33371402b76d17af0c63b396e85c63dd9051fc371652b93f8cd69ce9e193fe9fdda5c864b63ee497b9373db9f823836913ae829fc49debeaf3613045e7b5f86752fbd4c0214fc31ea2fdab388ef14fc7413eab239f19aebe71a343b2e66a0152241f76e06c304d6c12f7859d08b1f2802d53d9d21d56f0fce6afcd9ca23dc0ca665fed648c0b36966e5bdbffb588f382b64a86ca14f4aa9136d0db2bf470f6da66cbe312364a6ad88f473c7c65234672ff8d22e7a71a69418ecae5da5d3035f0b2c4beedf42268fa1f16ad46c46a8e65e407777b188be11dfb9ac8f5784a88088aca3cf0202868be32bb18371b78a3925ae8289951a6f82e1c418511ada32e7c2c33d1dac1237ce446a09796634f71720f149e0d9da7d1b44292d350dfd1ce1819b1dc0cfa4039dcb3c18ec767d60998c9fbf6c9ca2216b67bd04f819077bf0fd6bfbfb0aae2313b8a599eb9f61d1eb88aa4e0fd02badd3f3a170dd774712d57183bb80349b31a68e0108ecf410b5f27e49d67e641790ab2a4edac7de4dde52c792bcc87950ad44026fc841eb99846bc4087f7abf17fd0f642bd9a4a97f457f11e5f4ad7c9401816ddd2718922e8d7e55449e2467335736fadd5ff45ce93ba85595379da57c2d66bf52ccab6c24a662e8c0aa837cc855c3c1e38399909a6cd2cae26c15bd01398d2d9b9358115234d2f216056e054f9f5e3380f8e12cf54f3e083dc8e8077563c2a13ef11b120e1781dc9fa73375772be089c177dddf2c1f2336104845b16a1387520f9c53d04c622ddec118d2963a33cd6ebdb4af5680c5fe518912bf0fb97bb9b7e30a9722a350df9304fb92d1718a7987614044fe811084eb14524eec9d80cd0f33da79f1cf87d0bf11f6e390d3e22ae37d192e873de0c9bb4b1a52d5adef5e9211b913d3889dfe65bfff6c5076fd5f1d1aa973717780f28816b40da37d16392fccc02a30207ab1989608236ed498dd78a203150df66d95e0e4fe283d069cd9cb6efe6fd71f54bfa54bad403acb5ae83343fc1b8257b2369c7e3fc5a29c76e5f7fd876525fc823ac8482c366443ecd2a71e147f55eaa184fb6b8e47fd9624e51417cf5d39b748157880979c2bdc4832141e21926c5f857ae1b85929f0be09304cdcee2fe7dd010bdbcccc141e48bbd44d0c68086110283e6c806b96a562df248a69f069dd1279062fb9396ca2fd4bcec94ff5fd32cd53507a923c2e673803837fc2effaedf5e2c5eaebb312a2e528a638f34d3affba23ce99c666b3f56dce896ebe1ba6f23fcf951f81e3f14554e72d488c56bc6fe350aabaaaa5842abfcf5229921560348351b92338f60799667d722c1d36b1c99b46dfc208d8713a7bd235660b8efcb205c800831fc4a88e05b5f3c30e819a4e003c22766c3a8ede96d9ff760c354b87fc5389904001d19beff1ac14bba3ee441f79b6fc5c06bc3431b7ba507b07dfe91bdde17164d76d08e1effa1e9d7eacde6e2ba2ef9611c6da9a2a2b454bbc440b181e5601a85d52108371cec5e421122a6c381fc83cebb1a636e5dbff4db392ff02a0bcdd1673c6fe2da0526ad34998d9453a61c9106bc122bb76ff268328b41e29976bb27d1725c343978c1f42b0152e35ada3492e8b0883dc2ff7704d6d3d4a1a0b2c96e187cbd2cc339c283ccc167726476357e4b9dcfde36720b94c0517cce257fb92b6c62bec786ee81bfe6a87cb9013a566506503b2434aa9e33371402b76d17af0c63b396e85c63dd9051fc371652b93f8cd69ce9e193fe9fdda5c864b63ee497b9373db9f823836913ae829fc49debeaf3613045e7b5f86752fbd4c0214fc31ea2fdab388ef14fc7413eab239f19aebe71a343b2e66a0152241f76e06c304d6c12f7859d08b1f2802d53d9d21d56f0fce6afcd9ca23dc0ca665fed648c0b36966e5bdbffb588f382b64a86ca14f4aa9136d0db2bf470f6da66cbe312364a6ad88f473c7c65234672ff8d22e7a71a69418ecae5da5d3031964944b9b36965a7a30465a9be2470ad23fd1fd7772b5a257c5d8f6933455278090cad2c60e02868be32bb18371b78a3925ae8289951a6f82e1c418511ada32e7c2c33d1dac1237ce446a09796634f71720f149e0d9da7d1b44292d350dfd1ce1819b1dc0cfa4039dcb3c18ec767d60998c9fbf6c9ca2216b67bd04f819077bf0fd6bfbfb0aae2313b8a599eb9f61d1eb88aa4e0fd02badd3f3a170dd774712d57183bb80349b31a68e0108ecf410b5f27e49d67e641790ab2a4edac7de4dde52c792bcc87950ad44026fc841eb99846bc4087f7abf17fd0f642bd9a4a97f457f11e5f4ad7c9401816ddd2718922e8d7e55449e2467335736fadd5ff45ce93ba85595379da57c2d66bf52ccab6c24a662e8c0aa837cc855c3c1e38399909a6cd2cae26c15bd01398d2d9b9358115234d2f216056e054f9f5e3380f8e12cf54f3e083dc8e8077563c2a13ef11b120e1781dc9fa73375772be089c177dddf2c1f2336104845b16a1387520f9c53d04c622ddec118d2963a33cd6ebdb4af5680c5fe518912bf0fb97bb9b7e30a9722a350df9304fb92d1718a7987614044fe811084eb14524eec9d80cd0f33da79f1cf87d0bf11f6e390d3e22ae37d192e873de0c9bb4b1a52d5adef5e9211b913d3889dfe65bfff6c5076fd5f1d1aa973717780f28816b40da37d16392fccc02a30207ab1989608236ed498dd78a203150df66d95e0e4fe283d069cd9cb6efe6fd71f54bfa54bad403acb5ae83343fc1b8257b2369c7e3fc5a29c76e5f7fd876525fc823ac8482c366443ecd2a71e147f55eaa184fb6b8e47fd9624e51417cf5d39b748157880979c2bdc4832141e21926c5f857ae1b85929f0be09304cdcee2fe7dd010bdbcccc141e48bbd44d0c68086110283e6c806b96a562df248a69f069dd1279062fb9396ca2fd4bcec94ff5fd32cd53507a923c2e673803837fc2effaedf5e2c5eaebb312a2e528a638f34d3affba23ce99c666b3f56dce896ebe1ba6f23fcf951f81e3f14554e72d488c56bc6fe350aabaaaa5842abfcf5229921560348351b92338f60799667d722c1d36b1c99b46dfc208d8713a7bd235660b8efcb205c800831fc4a88e05b5f3c30e819a4e003c22766c3a8ede96d9ff760c354b87fc5389904001d19beff1ac14bba3ee441f79b6fc5c06bc3431b7ba507b07dfe91bdde17164d76d08e1effa1e9d7eacde6e2ba2ef9611c6da9a2a2b454bbc440b181e5601a85d52108371cec5e421122a6c381fc83cebb1a636e5dbff4db392ff02a0bcdd1673c6fe2da0526ad34998d9453a61c9106bc122bb76ff268328b41e29976bb27d1725c343978c1f42b0152e35ada3492e8b0883dc2ff7704d6d3d4a1a0b2c96e187cbd2cc339c283ccc167726476357e4b9dcfde36720b94c0517cce257fb92b6c62bec786ee81bfe6a87cb9013a566506503b2434aa9e33371402b76d17af0c63b396e85c63dd9051fc371652b93f8cd69ce9e193fe9fdda5c864b63ee497b9373db9f823836913ae829fc49debeaf3613045e7b5f86752fbd4c0214fc31ea2fdab388ef14fc7413eab239f19aebe71a343b2e66a0152241f76e06c304d6c12f7859d08b1f2802d53d9d21d56f0fce6afcd9ca23dc0ca665fed648c0b36966e5bdbffb588f382b64a86ca14f4aa9136d0db2bf470f6da66cbe312364a6ad88f473c7c65234672ff8d22e7a71a69418ecae5da5d303d381eaced5ceb7876a756e5e0af5347e57ac78d30d59492948692373cd1ae9f180e08d84ddcb0102868be32bb18371b78a3925ae8289951a6f82e1c418511ada32e7c2c33d1dac1237ce446a09796634f71720f149e0d9da7d1b44292d350dfd1ce1819b1dc0cfa4039dcb3c18ec767d60998c9fbf6c9ca2216b67bd04f819077bf0fd6bfbfb0aae2313b8a599eb9f61d1eb88aa4e0fd02badd3f3a170dd774712d57183bb80349b31a68e0108ecf410b5f27e49d67e641790ab2a4edac7de4dde52c792bcc87950ad44026fc841eb99846bc4087f7abf17fd0f642bd9a4a97f457f11e5f4ad7c9401816ddd2718922e8d7e55449e2467335736fadd5ff45ce93ba85595379da57c2d66bf52ccab6c24a662e8c0aa837cc855c3c1e38399909a6cd2cae26c15bd01398d2d9b9358115234d2f216056e054f9f5e3380f8e12cf54f3e083dc8e8077563c2a13ef11b120e1781dc9fa73375772be089c177dddf2c1f2336104845b16a1387520f9c53d04c622ddec118d2963a33cd6ebdb4af5680c5fe518912bf0fb97bb9b7e30a9722a350df9304fb92d1718a7987614044fe811084eb14524eec9d80cd0f33da79f1cf87d0bf11f6e390d3e22ae37d192e873de0c9bb4b1a52d5adef5e9211b913d3889dfe65bfff6c5076fd5f1d1aa973717780f28816b40da37d16392fccc02a30207ab1989608236ed498dd78a203150df66d95e0e4fe283d069cd9cb6efe6fd71f54bfa54bad403acb5ae83343fc1b8257b2369c7e3fc5a29c76e5f7fd876525fc823ac8482c366443ecd2a71e147f55eaa184fb6b8e47fd9624e51417cf5d39b748157880979c2bdc4832141e21926c5f857ae1b85929f0be09304cdcee2fe7dd010bdbcccc141e48bbd44d0c68086110283e6c806b96a562df248a69f069dd1279062fb9396ca2fd4bcec94ff5fd32cd53507a923c2e673803837fc2effaedf5e2c5eaebb312a2e528a638f34d3affba23ce99c666b3f56dce896ebe1ba6f23fcf951f81e3f14554e72d488c56bc6fe350aabaaaa5842abfcf5229921560348351b92338f60799667d722c1d36b1c99b46dfc208d8713a7bd235660b8efcb205c800831fc4a88e05b5f3c30e819a4e003c22766c3a8ede96d9ff760c354b87fc5389904001d19beff1ac14bba3ee441f79b6fc5c06bc3431b7ba507b07dfe91bdde17164d76d08e1effa1e9d7eacde6e2ba2ef9611c6da9a2a2b454bbc440b181e5601a85d52108371cec5e421122a6c381fc83cebb1a636e5dbff4db392ff02a0bcdd1673c6fe2da0526ad34998d9453a61c9106bc122bb76ff268328b41e29976bb27d1725c343978c1f42b0152e35ada3492e8b0883dc2ff7704d6d3d4a1a0b2c96e187cbd2cc339c283ccc167726476357e4b9dcfde36720b94c0517cce257fb92b6c62bec786ee81bfe6a87cb9013a566506503b2434aa9e33371402b76d17af0c63b396e85c63dd9051fc371652b93f8cd69ce9e193fe9fdda5c864b63ee497b9373db9f823836913ae829fc49debeaf3613045e7b5f86752fbd4c0214fc31ea2fdab388ef14fc7413eab239f19aebe71a343b2e66a0152241f76e06c304d6c12f7859d08b1f2802d53d9d21d56f0fce6afcd9ca23dc0ca665fed648c0b36966e5bdbffb588f382b64a86ca14f4aa9136d0db2bf470f6da66cbe312364a6ad88f473c7c65234672ff8d22e7a71a69418ecae5da5d30351ac3207777505f2e2ef8bef9d0d2fcb87433ff175f40a4f046a3bc4a8df97f880c0caf384a30202868be32bb18371b78a3925ae8289951a6f82e1c418511ada32e7c2c33d1dac1237ce446a09796634f71720f149e0d9da7d1b44292d350dfd1ce1819b1dc0cfa4039dcb3c18ec767d60998c9fbf6c9ca2216b67bd04f819077bf0fd6bfbfb0aae2313b8a599eb9f61d1eb88aa4e0fd02badd3f3a170dd774712d57183bb80349b31a68e0108ecf410b5f27e49d67e641790ab2a4edac7de4dde52c792bcc87950ad44026fc841eb99846bc4087f7abf17fd0f642bd9a4a97f457f11e5f4ad7c9401816ddd2718922e8d7e55449e2467335736fadd5ff45ce93ba85595379da57c2d66bf52ccab6c24a662e8c0aa837cc855c3c1e38399909a6cd2cae26c15bd01398d2d9b9358115234d2f216056e054f9f5e3380f8e12cf54f3e083dc8e8077563c2a13ef11b120e1781dc9fa73375772be089c177dddf2c1f2336104845b16a1387520f9c53d04c622ddec118d2963a33cd6ebdb4af5680c5fe518912bf0fb97bb9b7e30a9722a350df9304fb92d1718a7987614044fe811084eb14524eec9d80cd0f33da79f1cf87d0bf11f6e390d3e22ae37d192e873de0c9bb4b1a52d5adef5e9211b913d3889dfe65bfff6c5076fd5f1d1aa973717780f28816b40da37d16392fccc02a30207ab1989608236ed498dd78a203150df66d95e0e4fe283d069cd9cb6efe6fd71f54bfa54bad403acb5ae83343fc1b8257b2369c7e3fc5a29c76e5f7fd876525fc823ac8482c366443ecd2a71e147f55eaa184fb6b8e47fd9624e51417cf5d39b748157880979c2bdc4832141e21926c5f857ae1b85929f0be09304cdcee2fe7dd010bdbcccc141e48bbd44d0c68086110283e6c806b96a562df248a69f069dd1279062fb9396ca2fd4bcec94ff5fd32cd53507a923c2e673803837fc2effaedf5e2c5eaebb312a2e528a638f34d3affba23ce99c666b3f56dce896ebe1ba6f23fcf951f81e3f14554e72d488c56bc6fe350aabaaaa5842abfcf5229921560348351b92338f60799667d722c1d36b1c99b46dfc208d8713a7bd235660b8efcb205c800831fc4a88e05b5f3c30e819a4e003c22766c3a8ede96d9ff760c354b87fc5389904001d19beff1ac14bba3ee441f79b6fc5c06bc3431b7ba507b07dfe91bdde17164d76d08e1effa1e9d7eacde6e2ba2ef9611c6da9a2a2b454bbc440b181e5601a85d52108371cec5e421122a6c381fc83cebb1a636e5dbff4db392ff02a0bcdd1673c6fe2da0526ad34998d9453a61c9106bc122bb76ff268328b41e29976bb27d1725c343978c1f42b0152e35ada3492e8b0883dc2ff7704d6d3d4a1a0b2c96e187cbd2cc339c283ccc167726476357e4b9dcfde36720b94c0517cce257fb92b6c62bec786ee81bfe6a87cb9013a566506503b2434aa9e33371402b76d17af0c63b396e85c63dd9051fc371652b93f8cd69ce9e193fe9fdda5c864b63ee497b9373db9f823836913ae829fc49debeaf3613045e7b5f86752fbd4c0214fc31ea2fdab388ef14fc7413eab239f19aebe71a343b2e66a0152241f76e06c304d6c12f7859d08b1f2802d53d9d21d56f0fce6afcd9ca23dc0ca665fed648c0b36966e5bdbffb588f382b64a86ca14f4aa9136d0db2bf470f6da66cbe312364a6ad88f473c7c65234672ff8d22e7a71a69418ecae5da5d303097892a7269b568d65acc0acebf7d64842abb5dc07cf2a8987f619b83fb15a2fa109010b91d85b95ff8da2e00c6eff77359d5692364a42e1cd4a003255e0bcd7e3469e17b18e585f4a88472f76f07f8990b7e95c6f740191b0e7071e3ca881952c2bfcf5f6a9a1ace79b83d6908f1c3c95f4630ba3350e8a0054219297fe99761782f9f0104daf5334472b30ae929b558cc573dd68b0b4e745f6afdc49743ecc78efa89da702157c80a2eb2570f9b3f9ee882bf457d173ec77011d74ce2035a7a7410f74a333cdefee32449d432afe25257d06bd2ca786bfce078b533504037e3847bd6b5c2f68942dd5fdb8b48777ea5240c30ee265aa60ea9bdf425b5dccc6981dcb9d87aa15861c61c995b69d238798e87cac5033063a22e598df9f09cd03d10a3864e67ffd027c765862557fec7dfb361b33624602f1a7e6077fde1435e636321db0ffec795184f1f5ddf1fb5c0bffd02d5da7cdadbbd4e760deb3543658dbf849f6bdf766256acba750e6ba220495286dd0926f88b0fbabad9bafaafa22fddc499ab6f6009df69d2988483acffcfae3cd12f437b85336b5a86b8817c3e36908f30afc7440763b9002ebfbf825719644462e78fa4b6fc824ea0219ce53919b8d91fb9c3611345eb0c6daedb05e84428d73e3bcd710c68b7ef1ccde7c7274fd0763da8af1a1587703458a91f9ce216b52b610439db32ff0df09ea33cdeeab6ea9882131117a72fc2585178d353df7a26d2ce18967ec020ebd5867a85a8822193620516e57650c962a39d610820befefb74c1849f6ce988239af742690a58d4f9ca285fe809bfb58c733f49e440471d17dc1ac05d4d97b9a7019870e12aaf8bbffcb051a942b16f9e139f4eb7c83669dd0f20ed3c16802b139043085c24f9d3cde3203e007b957d6e90c8fbf648d4553fecfa80af9cebe637ecdeced5159d2fc6a7a56f3272987056a5b0a1363e93518548ca080bde98111b229de4393189989c6406ac53bcdac973d933e5ec91ebe77cb9c039e3391740858cb2e0532bf29ebdb7b87c97c988f0bf252585177c253bcdea13760cd7eb792715b21051b2cac329f1353604b389693c3b21662dae21886bf4abd4a7cb5c4413e8f5897c8c4fcfb92404227afa86f183889c9879b85606415c6d9cb073bc51ae368d1bc03887fb867ed742c5edf4fac14885d781ed0cdab8daeaa1a16125f895363f31485804d18b666cabff79d26bbcd0accab362a5ea500cef0ea16393578d42350b9cd15300840133f73270f96a76197667beb496d36a527eda976527bb404ba716cab1988d15e93c14ad4e1e6873302defe18528ac912f4c75c94ba6ed9c82193cfa9c59bff960e638285c589f9ecaeb6428f91071c7379f1d6d59b4a3f055c65b12fe03e5a8478238cf52137012670aa7b5559d012a0035746c1fb51d7265d7d4ef949e085c2cb7a31fbc688176e83f925ec200678f40b6ff9ea6336664d9179a1f1fdc01c0a59be48cdbf0378eba3d502826fe98aa44d5d20c17e6cb6e480e2aab21f941d873b77a0c8085a2f11ee7f086b11f85f85c17c5d36d1427668754a340a268c16b20bdc68796814a680eaba1b04411bed65a7b01aee29fdf664e186a505365949b8efa3cc97076fca2b5b2262feb9991e67be0b837215677f0b2126843380a6d9250d3b4f9aa9e1897c06a8245575293c47d5acfd007efa8a13b91676e96059e43f9a";
    uint32_t const GENESIS_NONCE = 10001;
  }

  namespace stagenet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 24;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 36;
    uint16_t const P2P_DEFAULT_PORT = 38080;
    uint16_t const RPC_DEFAULT_PORT = 38081;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 38082;
    boost::uuids::uuid const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x12
      } }; // Bender's daydream
    std::string const GENESIS_TX = "";
    uint32_t const GENESIS_NONCE = 10002;
  }
}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN,
    UNDEFINED = 255
  };
  struct config_t
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t const P2P_DEFAULT_PORT;
    uint16_t const RPC_DEFAULT_PORT;
    uint16_t const ZMQ_RPC_DEFAULT_PORT;
    boost::uuids::uuid const NETWORK_ID;
    std::string const GENESIS_TX;
    uint32_t const GENESIS_NONCE;
  };
  inline const config_t& get_config(network_type nettype)
  {
    static const config_t mainnet = {
      ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::P2P_DEFAULT_PORT,
      ::config::RPC_DEFAULT_PORT,
      ::config::ZMQ_RPC_DEFAULT_PORT,
      ::config::NETWORK_ID,
      ::config::GENESIS_TX,
      ::config::GENESIS_NONCE
    };
    static const config_t testnet = {
      ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::testnet::P2P_DEFAULT_PORT,
      ::config::testnet::RPC_DEFAULT_PORT,
      ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
      ::config::testnet::NETWORK_ID,
      ::config::testnet::GENESIS_TX,
      ::config::testnet::GENESIS_NONCE
    };
    static const config_t stagenet = {
      ::config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::stagenet::P2P_DEFAULT_PORT,
      ::config::stagenet::RPC_DEFAULT_PORT,
      ::config::stagenet::ZMQ_RPC_DEFAULT_PORT,
      ::config::stagenet::NETWORK_ID,
      ::config::stagenet::GENESIS_TX,
      ::config::stagenet::GENESIS_NONCE
    };
    switch (nettype)
    {
      case MAINNET: return mainnet;
      case TESTNET: return testnet;
      case STAGENET: return stagenet;
      case FAKECHAIN: return mainnet;
      default: throw std::runtime_error("Invalid network type");
    }
  };
}
