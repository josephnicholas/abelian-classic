// Copyright (c) 2014-2018, The Monero Project
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

#include <string>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_BLOCK_SIZE                       500000000  // block header blob limit, never used!
#define CRYPTONOTE_GETBLOCKTEMPLATE_MAX_BLOCK_SIZE	196608 //size of block (bytes) that is the maximum that miners will produce
#define CRYPTONOTE_MAX_TX_SIZE                          1000000000
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
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    60000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    600000 //size of block (bytes) after which reward for block calculated using block size - before first fork, used by Abelian need to change and calculate
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
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2

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
  uint16_t const P2P_DEFAULT_PORT = 19090;
  uint16_t const RPC_DEFAULT_PORT = 19091;
  uint16_t const ZMQ_RPC_DEFAULT_PORT = 19092;
  boost::uuids::uuid const NETWORK_ID = { {
      0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x10
    } }; // Bender's nightmare
  std::string const GENESIS_TX =
          "013c01ff0006ff9fdb5802e47a8825ced8d5e9f791edaf20bad22335f04fd80ee24800f37745154c097fdcda3315c9a83e6e0638a8cd8bdeb6bc32e7366809d76eb78a57941ca3105bbdc6d590d5d3be340e5b62dd0a0c9ceac88b73d8f917af6a269b9418dd92a22bad22f8aaa78ec5b1e685f0b671b86f18cf1dda6827b6a824eef335041f66dab563b813bd103004d6124ee06de436fbe6514eaed64d36d9e6205a5465d17c5dd12c407191a7987885d14bb0ac25f4fc74c9e1b60fabffd275db1935c3c4267c3c68ee6e26ccd91e51294c57131a6d900dfcd5a6a42531944de7c40e8dd7f95f5a591a7fbc7fa9c46a2f5d04dcc36542f58b90f7491ad8f2347663a7850898058371b8dcb4e42b5f46a393ea52fc1fc248cd9e40cc0746144173136f7bfd042ea5a9c8ea770fd9fc6e9c3fb992bfbd7a38676f12faddfcaa63be5ad93b1214786232bbc483e7e799601f187e74776d9877a01972d0702d9e421fea488f32e817304167aa3b11f71143cc9cbc41a488c4532539b62941027ddaa7d2aa107c6fad6349fa210bc676f5293dca89d86358c1e9b81c9ca19d37bbfab4ac098405e99d1dd36b8a21dbe37f09502e718873c52dbd903395adfffcfc6a40647493d448eb3232ea8253bffa3bc96ce19b9cfbb91c9cd0be127a218e0f0dbde9f72b1cf044ba5265f6706a4ee4cd2fbdd4de1b7a9de7237034d07c1505a1f5139fe3e78835152a47ddbfce03e03b4dd12483972ed8b42518da9c931c3ad6d87fb6bd3178584dc9e28386361b6f3ebf54f68d4428de603767b63af69a5144f37ff5ae4338f807e4e4d02073532efc60a2abb59c24a9596a673dda1cbcd4e2a1d544b5f7765e020d894f2ab28041cebb855f235854efca70e9973c3578d07209c2b57b050732b02900c7ea9e5caee69138f9d2a711405b53d5fbddaee06d592536ca00a3fce7871568f3a87215fcbd01e3a6bd9c8ddf5170a566a59b937be6eeb62c993c337bb82f7c588358ed78709fc964a829dd4d087514e450c304125e0c6308c99b0c39bff643ba010e875dc9dd73ecb0fc00acf250b483e33072ce0430062347bf1ba4e442175a9b78b4c7855e35e0150089b3f966a0064583dd36a62027cbab325175f2c6616dccb2728ae490592605f391890dea53387f13c917ffbf27c8f2d8402013e1a8359c3e0343de37b8689a0295a852da5de9860880d10896f8e6eb1cfdd7bedc1853cf4f2e413902ae0b3cfa44f8fcd071dd614c01537f9556710e6c8b4e28406c530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d1880a8d6b90702e47a8825ced8d5e9f791edaf20bad22335f04fd80ee24800f37745154c097fdcda3315c9a83e6e0638a8cd8bdeb6bc32e7366809d76eb78a57941ca3105bbdc6d590d5d3be340e5b62dd0a0c9ceac88b73d8f917af6a269b9418dd92a22bad22f8aaa78ec5b1e685f0b671b86f18cf1dda6827b6a824eef335041f66dab563b813bd103004d6124ee06de436fbe6514eaed64d36d9e6205a5465d17c5dd12c407191a7987885d14bb0ac25f4fc74c9e1b60fabffd275db1935c3c4267c3c68ee6e26ccd91e51294c57131a6d900dfcd5a6a42531944de7c40e8dd7f95f5a591a7fbc7fa9c46a2f5d04dcc36542f58b90f7491ad8f2347663a7850898058371b8dcb4e42b5f46a393ea52fc1fc248cd9e40cc0746144173136f7bfd042ea5a9c8ea770fd9fc6e9c3fb992bfbd7a38676f12faddfcaa63be5ad93b1214786232bbc483e7e799601f187e74776d9877a01972d0702d9e421fea488f32e817304167aa3b11f71143cc9cbc41a488c4532539b62941027ddaa7d2aa107c6fad6349fa210bc676f5293dca89d86358c1e9b81c9ca19d37bbfab4ac098405e99d1dd36b8a21dbe37f09502e718873c52dbd903395adfffcfc6a40647493d448eb3232ea8253bffa3bc96ce19b9cfbb91c9cd0be127a218e0f0dbde9f72b1cf044ba5265f6706a4ee4cd2fbdd4de1b7a9de7237034d07c1505a1f5139fe3e78835152a47ddbfce03e03b4dd12483972ed8b42518da9c931c3ad6d87fb6bd3178584dc9e28386361b6f3ebf54f68d4428de603767b63af69a5144f37ff5ae4338f807e4e4d02073532efc60a2abb59c24a9596a673dda1cbcd4e2a1d544b5f7765e020d894f2ab28041cebb855f235854efca70e9973c3578d07209c2b57b050732b02900c7ea9e5caee69138f9d2a711405b53d5fbddaee06d592536ca00a3fce7871568f3a87215fcbd01e3a6bd9c8ddf5170a566a59b937be6eeb62c993c337bb82f7c588358ed78709fc964a829dd4d087514e450c304125e0c6308c99b0c39bff643ba010e875dc9dd73ecb0fc00acf250b483e33072ce0430062347bf1ba4e442175a9b78b4c7855e35e0150089b3f966a0064583dd36a62027cbab325175f2c6616dccb2728ae490592605f391890dea53387f13c917ffbf27c8f2d8402013e1a8359c3e0343de37b8689a0295a852da5de9860880d10896f8e6eb1cfdd7bedc1853cf4f2e413902ae0b3cfa44f8fcd071dd614c01537f9556710e6c8b4e28406c2115a78259b2dd38d3dbc36f2c62bca7e24cbe0225765e1685802e89627ac26b8088aca3cf0202e47a8825ced8d5e9f791edaf20bad22335f04fd80ee24800f37745154c097fdcda3315c9a83e6e0638a8cd8bdeb6bc32e7366809d76eb78a57941ca3105bbdc6d590d5d3be340e5b62dd0a0c9ceac88b73d8f917af6a269b9418dd92a22bad22f8aaa78ec5b1e685f0b671b86f18cf1dda6827b6a824eef335041f66dab563b813bd103004d6124ee06de436fbe6514eaed64d36d9e6205a5465d17c5dd12c407191a7987885d14bb0ac25f4fc74c9e1b60fabffd275db1935c3c4267c3c68ee6e26ccd91e51294c57131a6d900dfcd5a6a42531944de7c40e8dd7f95f5a591a7fbc7fa9c46a2f5d04dcc36542f58b90f7491ad8f2347663a7850898058371b8dcb4e42b5f46a393ea52fc1fc248cd9e40cc0746144173136f7bfd042ea5a9c8ea770fd9fc6e9c3fb992bfbd7a38676f12faddfcaa63be5ad93b1214786232bbc483e7e799601f187e74776d9877a01972d0702d9e421fea488f32e817304167aa3b11f71143cc9cbc41a488c4532539b62941027ddaa7d2aa107c6fad6349fa210bc676f5293dca89d86358c1e9b81c9ca19d37bbfab4ac098405e99d1dd36b8a21dbe37f09502e718873c52dbd903395adfffcfc6a40647493d448eb3232ea8253bffa3bc96ce19b9cfbb91c9cd0be127a218e0f0dbde9f72b1cf044ba5265f6706a4ee4cd2fbdd4de1b7a9de7237034d07c1505a1f5139fe3e78835152a47ddbfce03e03b4dd12483972ed8b42518da9c931c3ad6d87fb6bd3178584dc9e28386361b6f3ebf54f68d4428de603767b63af69a5144f37ff5ae4338f807e4e4d02073532efc60a2abb59c24a9596a673dda1cbcd4e2a1d544b5f7765e020d894f2ab28041cebb855f235854efca70e9973c3578d07209c2b57b050732b02900c7ea9e5caee69138f9d2a711405b53d5fbddaee06d592536ca00a3fce7871568f3a87215fcbd01e3a6bd9c8ddf5170a566a59b937be6eeb62c993c337bb82f7c588358ed78709fc964a829dd4d087514e450c304125e0c6308c99b0c39bff643ba010e875dc9dd73ecb0fc00acf250b483e33072ce0430062347bf1ba4e442175a9b78b4c7855e35e0150089b3f966a0064583dd36a62027cbab325175f2c6616dccb2728ae490592605f391890dea53387f13c917ffbf27c8f2d8402013e1a8359c3e0343de37b8689a0295a852da5de9860880d10896f8e6eb1cfdd7bedc1853cf4f2e413902ae0b3cfa44f8fcd071dd614c01537f9556710e6c8b4e28406cca6275ff3c696d796caaac4306171448b1c9f9e8482726ab6c6986d77cfc4d1f8090cad2c60e02e47a8825ced8d5e9f791edaf20bad22335f04fd80ee24800f37745154c097fdcda3315c9a83e6e0638a8cd8bdeb6bc32e7366809d76eb78a57941ca3105bbdc6d590d5d3be340e5b62dd0a0c9ceac88b73d8f917af6a269b9418dd92a22bad22f8aaa78ec5b1e685f0b671b86f18cf1dda6827b6a824eef335041f66dab563b813bd103004d6124ee06de436fbe6514eaed64d36d9e6205a5465d17c5dd12c407191a7987885d14bb0ac25f4fc74c9e1b60fabffd275db1935c3c4267c3c68ee6e26ccd91e51294c57131a6d900dfcd5a6a42531944de7c40e8dd7f95f5a591a7fbc7fa9c46a2f5d04dcc36542f58b90f7491ad8f2347663a7850898058371b8dcb4e42b5f46a393ea52fc1fc248cd9e40cc0746144173136f7bfd042ea5a9c8ea770fd9fc6e9c3fb992bfbd7a38676f12faddfcaa63be5ad93b1214786232bbc483e7e799601f187e74776d9877a01972d0702d9e421fea488f32e817304167aa3b11f71143cc9cbc41a488c4532539b62941027ddaa7d2aa107c6fad6349fa210bc676f5293dca89d86358c1e9b81c9ca19d37bbfab4ac098405e99d1dd36b8a21dbe37f09502e718873c52dbd903395adfffcfc6a40647493d448eb3232ea8253bffa3bc96ce19b9cfbb91c9cd0be127a218e0f0dbde9f72b1cf044ba5265f6706a4ee4cd2fbdd4de1b7a9de7237034d07c1505a1f5139fe3e78835152a47ddbfce03e03b4dd12483972ed8b42518da9c931c3ad6d87fb6bd3178584dc9e28386361b6f3ebf54f68d4428de603767b63af69a5144f37ff5ae4338f807e4e4d02073532efc60a2abb59c24a9596a673dda1cbcd4e2a1d544b5f7765e020d894f2ab28041cebb855f235854efca70e9973c3578d07209c2b57b050732b02900c7ea9e5caee69138f9d2a711405b53d5fbddaee06d592536ca00a3fce7871568f3a87215fcbd01e3a6bd9c8ddf5170a566a59b937be6eeb62c993c337bb82f7c588358ed78709fc964a829dd4d087514e450c304125e0c6308c99b0c39bff643ba010e875dc9dd73ecb0fc00acf250b483e33072ce0430062347bf1ba4e442175a9b78b4c7855e35e0150089b3f966a0064583dd36a62027cbab325175f2c6616dccb2728ae490592605f391890dea53387f13c917ffbf27c8f2d8402013e1a8359c3e0343de37b8689a0295a852da5de9860880d10896f8e6eb1cfdd7bedc1853cf4f2e413902ae0b3cfa44f8fcd071dd614c01537f9556710e6c8b4e28406c0d437cce91ed1ed896eb4befc95f82c4a6c33d0b812cf3c01b7551cd43b706be80e08d84ddcb0102e47a8825ced8d5e9f791edaf20bad22335f04fd80ee24800f37745154c097fdcda3315c9a83e6e0638a8cd8bdeb6bc32e7366809d76eb78a57941ca3105bbdc6d590d5d3be340e5b62dd0a0c9ceac88b73d8f917af6a269b9418dd92a22bad22f8aaa78ec5b1e685f0b671b86f18cf1dda6827b6a824eef335041f66dab563b813bd103004d6124ee06de436fbe6514eaed64d36d9e6205a5465d17c5dd12c407191a7987885d14bb0ac25f4fc74c9e1b60fabffd275db1935c3c4267c3c68ee6e26ccd91e51294c57131a6d900dfcd5a6a42531944de7c40e8dd7f95f5a591a7fbc7fa9c46a2f5d04dcc36542f58b90f7491ad8f2347663a7850898058371b8dcb4e42b5f46a393ea52fc1fc248cd9e40cc0746144173136f7bfd042ea5a9c8ea770fd9fc6e9c3fb992bfbd7a38676f12faddfcaa63be5ad93b1214786232bbc483e7e799601f187e74776d9877a01972d0702d9e421fea488f32e817304167aa3b11f71143cc9cbc41a488c4532539b62941027ddaa7d2aa107c6fad6349fa210bc676f5293dca89d86358c1e9b81c9ca19d37bbfab4ac098405e99d1dd36b8a21dbe37f09502e718873c52dbd903395adfffcfc6a40647493d448eb3232ea8253bffa3bc96ce19b9cfbb91c9cd0be127a218e0f0dbde9f72b1cf044ba5265f6706a4ee4cd2fbdd4de1b7a9de7237034d07c1505a1f5139fe3e78835152a47ddbfce03e03b4dd12483972ed8b42518da9c931c3ad6d87fb6bd3178584dc9e28386361b6f3ebf54f68d4428de603767b63af69a5144f37ff5ae4338f807e4e4d02073532efc60a2abb59c24a9596a673dda1cbcd4e2a1d544b5f7765e020d894f2ab28041cebb855f235854efca70e9973c3578d07209c2b57b050732b02900c7ea9e5caee69138f9d2a711405b53d5fbddaee06d592536ca00a3fce7871568f3a87215fcbd01e3a6bd9c8ddf5170a566a59b937be6eeb62c993c337bb82f7c588358ed78709fc964a829dd4d087514e450c304125e0c6308c99b0c39bff643ba010e875dc9dd73ecb0fc00acf250b483e33072ce0430062347bf1ba4e442175a9b78b4c7855e35e0150089b3f966a0064583dd36a62027cbab325175f2c6616dccb2728ae490592605f391890dea53387f13c917ffbf27c8f2d8402013e1a8359c3e0343de37b8689a0295a852da5de9860880d10896f8e6eb1cfdd7bedc1853cf4f2e413902ae0b3cfa44f8fcd071dd614c01537f9556710e6c8b4e28406cc30678fa1dbce0a9ec0e4ba6095302d692da8b6c6c4a97c1bd07880f72c80e5580c0caf384a30202e47a8825ced8d5e9f791edaf20bad22335f04fd80ee24800f37745154c097fdcda3315c9a83e6e0638a8cd8bdeb6bc32e7366809d76eb78a57941ca3105bbdc6d590d5d3be340e5b62dd0a0c9ceac88b73d8f917af6a269b9418dd92a22bad22f8aaa78ec5b1e685f0b671b86f18cf1dda6827b6a824eef335041f66dab563b813bd103004d6124ee06de436fbe6514eaed64d36d9e6205a5465d17c5dd12c407191a7987885d14bb0ac25f4fc74c9e1b60fabffd275db1935c3c4267c3c68ee6e26ccd91e51294c57131a6d900dfcd5a6a42531944de7c40e8dd7f95f5a591a7fbc7fa9c46a2f5d04dcc36542f58b90f7491ad8f2347663a7850898058371b8dcb4e42b5f46a393ea52fc1fc248cd9e40cc0746144173136f7bfd042ea5a9c8ea770fd9fc6e9c3fb992bfbd7a38676f12faddfcaa63be5ad93b1214786232bbc483e7e799601f187e74776d9877a01972d0702d9e421fea488f32e817304167aa3b11f71143cc9cbc41a488c4532539b62941027ddaa7d2aa107c6fad6349fa210bc676f5293dca89d86358c1e9b81c9ca19d37bbfab4ac098405e99d1dd36b8a21dbe37f09502e718873c52dbd903395adfffcfc6a40647493d448eb3232ea8253bffa3bc96ce19b9cfbb91c9cd0be127a218e0f0dbde9f72b1cf044ba5265f6706a4ee4cd2fbdd4de1b7a9de7237034d07c1505a1f5139fe3e78835152a47ddbfce03e03b4dd12483972ed8b42518da9c931c3ad6d87fb6bd3178584dc9e28386361b6f3ebf54f68d4428de603767b63af69a5144f37ff5ae4338f807e4e4d02073532efc60a2abb59c24a9596a673dda1cbcd4e2a1d544b5f7765e020d894f2ab28041cebb855f235854efca70e9973c3578d07209c2b57b050732b02900c7ea9e5caee69138f9d2a711405b53d5fbddaee06d592536ca00a3fce7871568f3a87215fcbd01e3a6bd9c8ddf5170a566a59b937be6eeb62c993c337bb82f7c588358ed78709fc964a829dd4d087514e450c304125e0c6308c99b0c39bff643ba010e875dc9dd73ecb0fc00acf250b483e33072ce0430062347bf1ba4e442175a9b78b4c7855e35e0150089b3f966a0064583dd36a62027cbab325175f2c6616dccb2728ae490592605f391890dea53387f13c917ffbf27c8f2d8402013e1a8359c3e0343de37b8689a0295a852da5de9860880d10896f8e6eb1cfdd7bedc1853cf4f2e413902ae0b3cfa44f8fcd071dd614c01537f9556710e6c8b4e28406cffbe3bc8be47bee228b2e81f99717a84d44fe5eb24bbb70c588a973e872f82c38107011adacfb58efea94dc3f2f876a4a04759eaccea0b906abb5aa4ac06a1458bde117b17dce5c82cd19135292b205be45466814d507a0faa2c577b32465b06580f39e9bc8a3205d7e9f287585dae77972fb7361c9cb831d8c21013b14273b56466abec4f6b0f431d7eda50e14c377fd61413e1b6c03a0a41286dafda4eaf208f84ef0377f8912566b9b0b8fe9b2dfd512ba0d34ae74acf914f3a89f8901643aff21487d4f31718fbe6eacbcd22d0b65fbebb8d486e28a4f302b73fdaf6b29b72b48af69dd750583d1532eef66cee6bf091c83d7f7188ed5359ad12d85e484185a2871cb8e0d4b4314469dd3b35b4dd6ed7944debd6bd2b53d322884d74fee6460316090106182aefd648f6d9d3ef9c3a461541c5f9feb238027ec7f57b0832dfb22cb55746992298e9b4931d0e0cf456fb10424d9206a316e8a67b55e4529fb01e731cda5c0b9ef4154231b73ea02e04e33d9d0d766ea15dcca7152ea4588022190396134fdf54ba333f570d989e88dcf984aa2e22b9ccace855a772cbb68e20712e782a2dad3493d74e299f313587048c79474fa13b028a562e04133eaed9974791f9723399cd4d7043adc5d43d7f06e0193d7fa46c3f7e402982ef125335f24b8dae67a969f3781c65cec956825602ce5712f082bf41474a7be0d3db880aced1c029258c2926030146ceea6def8f0ed5bee356dc460754a69c2254c014000b54cb70f58b17f5826821a3166f1065f712d060349755cb967cf46be1727e17bbac0d6183dfa7bdf0379140f21e0120d50d66e87b0f3acf36f3be0e9b1b8ca6dd82b439415eaf79a1c79d6f756b63b03fb3cb0e72cabbcd21d4a9a76081c46e9d13f77c80ec9858ad4b1c6cefb60f77331a525525542746df0db184ea17f86be5875450694f136a4f0fee3e8c9f3ee770786f7675b7d3810ff466b8a10b8f9cbe7c7f61ba6535f4e18c351812f59ed6c1f9b9a423a61b16de78cee758f4d9f82834a2f53e5af5bedcdb9aaf3bca882b6f38ec65edb58fd5597b17cf159cd16f39c06508d6794aab628503cdd0594c447967833e9188177e25a12a7354bae647ee551992b38e33bf7cf5b3837bc58cefc1ce592d71e3eab4034f44052eec8441227dce3c19c27eddba7ac3efe04cbf2780615573dc5a72aba46ec053bbe4a766abd86805d9145bafda7e89d33aa51246b4d19b10e2a527bcd00b7ff70b464b8689067ba6bb0f46df19aa311ab5d56402b47b6a22508db0709600ae6755188396667a6b";
  uint32_t const GENESIS_NONCE = 10000;

  namespace testnet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 53;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 63;
    uint16_t const P2P_DEFAULT_PORT = 29090;
    uint16_t const RPC_DEFAULT_PORT = 29091;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 29092;
    boost::uuids::uuid const NETWORK_ID = { {
        0x12 ,0x30, 0xF1, 0x71 , 0x61, 0x04 , 0x41, 0x61, 0x17, 0x31, 0x00, 0x82, 0x16, 0xA1, 0xA1, 0x11
      } }; // Bender's daydream
      std::string const GENESIS_TX =
              "013c01ff0006ff9fdb5802c7bee0b474ce59c4ffaeee1e47aa063e0a02b12fac464e96833798b0faf3a694488200980b55c53ed26fe9979a33850a4d13b132a8aa48cf72c5927bc408036a7064189bc504d6ca381211bc606de317765278f96b72f55d5db8c8004754e4771678208bc04bcfe4b0968b4088879e38bb89ca4b706d7c3f1a6e2374d3ec6e4a3a6997ce880cc1bcafaa869544ed4338a24e86bdfab639ca9cfd4e0635a8f166c2bfacc157e1c473bace330974430360f173a4bd6e851921427ec624202f8098ccbed6a7b6c2b699c878b1cdd5ec99e9d5f9e1f64cbd1aedb2fb5e59759a6e3e729ed466484b9761ea2449d0b1a31fdedc8abdc81bafda7c469680bd1b842744822eca7f5e8bbca7a4dbf144ba92969b1cb2fbf799b867b0ec05601d90bcf294c7bd281b2714f44d92e68479179daf290fcf241444dea0aacf2385934a13651e126828aeaa3dd6a9b118c8a32c64b4da15694ad8d1f7eb1941808cf5fe45418823797aac9d9e4b86d570952b263d71af3d6f2c7981eeec02a20cb8daa29afc1142747fcef9b14737b0aa2a6a852a18e14fddf00c1d1162fab2e4f4db2eab22467b855f33aa5fdcc1ce6e1064c86d8626cda9b653487d37b06c2f7e60144ad28d5858279da65b9f546bd226c39fdb6119e7f39dfda5aaae09c9df1ee35e2974be4a2619dadaf1190a4d28e6b9accf917c612adae5e7da64b67dfc99f6771bdf78a8dcff19150b85d63f0945c5146643a8ba2a43d8eb9acad2917071e9ae9f0eeb644c5e6ea3438342fe89e4f1df159647735d90b0c9e39fcd24c21c53ab107327f3a04a1f6bc4955dde9016d932b0926c9c6c146eb38928ab12c088d1c270497d32523061606204a3b2db41c5cbda53e7a875b0c18e232e3f8974e47dba72448d3f3df3e6e7316aed99872f5b4ecbed86b60068db8547704ce256322d5ec5a2c8f8b4d9e384829806e7b56d6fa179ef6598098d9410a3c2f270f329ae3eec8c0d8b8ca8af6b1290e8a89a8bbf49215a6738a777a7230ee7cf6ac5cc5959316e8625b763c1697303674fb50bbcb435128ac00181afc01a21665f8f5bc922a2e334fd4f3e1ebbacc444e0c207473446312be804481e92cadeb910f94e517808960b602bb67b7c24628f0435bdb563abee79a845a99ff29b9588fbf0aa40faa81224bd9db1039249af9bc9c045a28094f292f70a0bc480b788f370e2034ffd7773bbc4161087585e62996f8c9df60466be5c1e1624fda208051b2e196cb006022119530f8afbc74536b9a963b4f1c4cb738bcea7403d4d606b6e074ec5d3baf39d1880a8d6b90702c7bee0b474ce59c4ffaeee1e47aa063e0a02b12fac464e96833798b0faf3a694488200980b55c53ed26fe9979a33850a4d13b132a8aa48cf72c5927bc408036a7064189bc504d6ca381211bc606de317765278f96b72f55d5db8c8004754e4771678208bc04bcfe4b0968b4088879e38bb89ca4b706d7c3f1a6e2374d3ec6e4a3a6997ce880cc1bcafaa869544ed4338a24e86bdfab639ca9cfd4e0635a8f166c2bfacc157e1c473bace330974430360f173a4bd6e851921427ec624202f8098ccbed6a7b6c2b699c878b1cdd5ec99e9d5f9e1f64cbd1aedb2fb5e59759a6e3e729ed466484b9761ea2449d0b1a31fdedc8abdc81bafda7c469680bd1b842744822eca7f5e8bbca7a4dbf144ba92969b1cb2fbf799b867b0ec05601d90bcf294c7bd281b2714f44d92e68479179daf290fcf241444dea0aacf2385934a13651e126828aeaa3dd6a9b118c8a32c64b4da15694ad8d1f7eb1941808cf5fe45418823797aac9d9e4b86d570952b263d71af3d6f2c7981eeec02a20cb8daa29afc1142747fcef9b14737b0aa2a6a852a18e14fddf00c1d1162fab2e4f4db2eab22467b855f33aa5fdcc1ce6e1064c86d8626cda9b653487d37b06c2f7e60144ad28d5858279da65b9f546bd226c39fdb6119e7f39dfda5aaae09c9df1ee35e2974be4a2619dadaf1190a4d28e6b9accf917c612adae5e7da64b67dfc99f6771bdf78a8dcff19150b85d63f0945c5146643a8ba2a43d8eb9acad2917071e9ae9f0eeb644c5e6ea3438342fe89e4f1df159647735d90b0c9e39fcd24c21c53ab107327f3a04a1f6bc4955dde9016d932b0926c9c6c146eb38928ab12c088d1c270497d32523061606204a3b2db41c5cbda53e7a875b0c18e232e3f8974e47dba72448d3f3df3e6e7316aed99872f5b4ecbed86b60068db8547704ce256322d5ec5a2c8f8b4d9e384829806e7b56d6fa179ef6598098d9410a3c2f270f329ae3eec8c0d8b8ca8af6b1290e8a89a8bbf49215a6738a777a7230ee7cf6ac5cc5959316e8625b763c1697303674fb50bbcb435128ac00181afc01a21665f8f5bc922a2e334fd4f3e1ebbacc444e0c207473446312be804481e92cadeb910f94e517808960b602bb67b7c24628f0435bdb563abee79a845a99ff29b9588fbf0aa40faa81224bd9db1039249af9bc9c045a28094f292f70a0bc480b788f370e2034ffd7773bbc4161087585e62996f8c9df60466be5c1e1624fda208051b2e196cb0060221192115a78259b2dd38d3dbc36f2c62bca7e24cbe0225765e1685802e89627ac26b8088aca3cf0202c7bee0b474ce59c4ffaeee1e47aa063e0a02b12fac464e96833798b0faf3a694488200980b55c53ed26fe9979a33850a4d13b132a8aa48cf72c5927bc408036a7064189bc504d6ca381211bc606de317765278f96b72f55d5db8c8004754e4771678208bc04bcfe4b0968b4088879e38bb89ca4b706d7c3f1a6e2374d3ec6e4a3a6997ce880cc1bcafaa869544ed4338a24e86bdfab639ca9cfd4e0635a8f166c2bfacc157e1c473bace330974430360f173a4bd6e851921427ec624202f8098ccbed6a7b6c2b699c878b1cdd5ec99e9d5f9e1f64cbd1aedb2fb5e59759a6e3e729ed466484b9761ea2449d0b1a31fdedc8abdc81bafda7c469680bd1b842744822eca7f5e8bbca7a4dbf144ba92969b1cb2fbf799b867b0ec05601d90bcf294c7bd281b2714f44d92e68479179daf290fcf241444dea0aacf2385934a13651e126828aeaa3dd6a9b118c8a32c64b4da15694ad8d1f7eb1941808cf5fe45418823797aac9d9e4b86d570952b263d71af3d6f2c7981eeec02a20cb8daa29afc1142747fcef9b14737b0aa2a6a852a18e14fddf00c1d1162fab2e4f4db2eab22467b855f33aa5fdcc1ce6e1064c86d8626cda9b653487d37b06c2f7e60144ad28d5858279da65b9f546bd226c39fdb6119e7f39dfda5aaae09c9df1ee35e2974be4a2619dadaf1190a4d28e6b9accf917c612adae5e7da64b67dfc99f6771bdf78a8dcff19150b85d63f0945c5146643a8ba2a43d8eb9acad2917071e9ae9f0eeb644c5e6ea3438342fe89e4f1df159647735d90b0c9e39fcd24c21c53ab107327f3a04a1f6bc4955dde9016d932b0926c9c6c146eb38928ab12c088d1c270497d32523061606204a3b2db41c5cbda53e7a875b0c18e232e3f8974e47dba72448d3f3df3e6e7316aed99872f5b4ecbed86b60068db8547704ce256322d5ec5a2c8f8b4d9e384829806e7b56d6fa179ef6598098d9410a3c2f270f329ae3eec8c0d8b8ca8af6b1290e8a89a8bbf49215a6738a777a7230ee7cf6ac5cc5959316e8625b763c1697303674fb50bbcb435128ac00181afc01a21665f8f5bc922a2e334fd4f3e1ebbacc444e0c207473446312be804481e92cadeb910f94e517808960b602bb67b7c24628f0435bdb563abee79a845a99ff29b9588fbf0aa40faa81224bd9db1039249af9bc9c045a28094f292f70a0bc480b788f370e2034ffd7773bbc4161087585e62996f8c9df60466be5c1e1624fda208051b2e196cb006022119ca6275ff3c696d796caaac4306171448b1c9f9e8482726ab6c6986d77cfc4d1f8090cad2c60e02c7bee0b474ce59c4ffaeee1e47aa063e0a02b12fac464e96833798b0faf3a694488200980b55c53ed26fe9979a33850a4d13b132a8aa48cf72c5927bc408036a7064189bc504d6ca381211bc606de317765278f96b72f55d5db8c8004754e4771678208bc04bcfe4b0968b4088879e38bb89ca4b706d7c3f1a6e2374d3ec6e4a3a6997ce880cc1bcafaa869544ed4338a24e86bdfab639ca9cfd4e0635a8f166c2bfacc157e1c473bace330974430360f173a4bd6e851921427ec624202f8098ccbed6a7b6c2b699c878b1cdd5ec99e9d5f9e1f64cbd1aedb2fb5e59759a6e3e729ed466484b9761ea2449d0b1a31fdedc8abdc81bafda7c469680bd1b842744822eca7f5e8bbca7a4dbf144ba92969b1cb2fbf799b867b0ec05601d90bcf294c7bd281b2714f44d92e68479179daf290fcf241444dea0aacf2385934a13651e126828aeaa3dd6a9b118c8a32c64b4da15694ad8d1f7eb1941808cf5fe45418823797aac9d9e4b86d570952b263d71af3d6f2c7981eeec02a20cb8daa29afc1142747fcef9b14737b0aa2a6a852a18e14fddf00c1d1162fab2e4f4db2eab22467b855f33aa5fdcc1ce6e1064c86d8626cda9b653487d37b06c2f7e60144ad28d5858279da65b9f546bd226c39fdb6119e7f39dfda5aaae09c9df1ee35e2974be4a2619dadaf1190a4d28e6b9accf917c612adae5e7da64b67dfc99f6771bdf78a8dcff19150b85d63f0945c5146643a8ba2a43d8eb9acad2917071e9ae9f0eeb644c5e6ea3438342fe89e4f1df159647735d90b0c9e39fcd24c21c53ab107327f3a04a1f6bc4955dde9016d932b0926c9c6c146eb38928ab12c088d1c270497d32523061606204a3b2db41c5cbda53e7a875b0c18e232e3f8974e47dba72448d3f3df3e6e7316aed99872f5b4ecbed86b60068db8547704ce256322d5ec5a2c8f8b4d9e384829806e7b56d6fa179ef6598098d9410a3c2f270f329ae3eec8c0d8b8ca8af6b1290e8a89a8bbf49215a6738a777a7230ee7cf6ac5cc5959316e8625b763c1697303674fb50bbcb435128ac00181afc01a21665f8f5bc922a2e334fd4f3e1ebbacc444e0c207473446312be804481e92cadeb910f94e517808960b602bb67b7c24628f0435bdb563abee79a845a99ff29b9588fbf0aa40faa81224bd9db1039249af9bc9c045a28094f292f70a0bc480b788f370e2034ffd7773bbc4161087585e62996f8c9df60466be5c1e1624fda208051b2e196cb0060221190d437cce91ed1ed896eb4befc95f82c4a6c33d0b812cf3c01b7551cd43b706be80e08d84ddcb0102c7bee0b474ce59c4ffaeee1e47aa063e0a02b12fac464e96833798b0faf3a694488200980b55c53ed26fe9979a33850a4d13b132a8aa48cf72c5927bc408036a7064189bc504d6ca381211bc606de317765278f96b72f55d5db8c8004754e4771678208bc04bcfe4b0968b4088879e38bb89ca4b706d7c3f1a6e2374d3ec6e4a3a6997ce880cc1bcafaa869544ed4338a24e86bdfab639ca9cfd4e0635a8f166c2bfacc157e1c473bace330974430360f173a4bd6e851921427ec624202f8098ccbed6a7b6c2b699c878b1cdd5ec99e9d5f9e1f64cbd1aedb2fb5e59759a6e3e729ed466484b9761ea2449d0b1a31fdedc8abdc81bafda7c469680bd1b842744822eca7f5e8bbca7a4dbf144ba92969b1cb2fbf799b867b0ec05601d90bcf294c7bd281b2714f44d92e68479179daf290fcf241444dea0aacf2385934a13651e126828aeaa3dd6a9b118c8a32c64b4da15694ad8d1f7eb1941808cf5fe45418823797aac9d9e4b86d570952b263d71af3d6f2c7981eeec02a20cb8daa29afc1142747fcef9b14737b0aa2a6a852a18e14fddf00c1d1162fab2e4f4db2eab22467b855f33aa5fdcc1ce6e1064c86d8626cda9b653487d37b06c2f7e60144ad28d5858279da65b9f546bd226c39fdb6119e7f39dfda5aaae09c9df1ee35e2974be4a2619dadaf1190a4d28e6b9accf917c612adae5e7da64b67dfc99f6771bdf78a8dcff19150b85d63f0945c5146643a8ba2a43d8eb9acad2917071e9ae9f0eeb644c5e6ea3438342fe89e4f1df159647735d90b0c9e39fcd24c21c53ab107327f3a04a1f6bc4955dde9016d932b0926c9c6c146eb38928ab12c088d1c270497d32523061606204a3b2db41c5cbda53e7a875b0c18e232e3f8974e47dba72448d3f3df3e6e7316aed99872f5b4ecbed86b60068db8547704ce256322d5ec5a2c8f8b4d9e384829806e7b56d6fa179ef6598098d9410a3c2f270f329ae3eec8c0d8b8ca8af6b1290e8a89a8bbf49215a6738a777a7230ee7cf6ac5cc5959316e8625b763c1697303674fb50bbcb435128ac00181afc01a21665f8f5bc922a2e334fd4f3e1ebbacc444e0c207473446312be804481e92cadeb910f94e517808960b602bb67b7c24628f0435bdb563abee79a845a99ff29b9588fbf0aa40faa81224bd9db1039249af9bc9c045a28094f292f70a0bc480b788f370e2034ffd7773bbc4161087585e62996f8c9df60466be5c1e1624fda208051b2e196cb006022119c30678fa1dbce0a9ec0e4ba6095302d692da8b6c6c4a97c1bd07880f72c80e5580c0caf384a30202c7bee0b474ce59c4ffaeee1e47aa063e0a02b12fac464e96833798b0faf3a694488200980b55c53ed26fe9979a33850a4d13b132a8aa48cf72c5927bc408036a7064189bc504d6ca381211bc606de317765278f96b72f55d5db8c8004754e4771678208bc04bcfe4b0968b4088879e38bb89ca4b706d7c3f1a6e2374d3ec6e4a3a6997ce880cc1bcafaa869544ed4338a24e86bdfab639ca9cfd4e0635a8f166c2bfacc157e1c473bace330974430360f173a4bd6e851921427ec624202f8098ccbed6a7b6c2b699c878b1cdd5ec99e9d5f9e1f64cbd1aedb2fb5e59759a6e3e729ed466484b9761ea2449d0b1a31fdedc8abdc81bafda7c469680bd1b842744822eca7f5e8bbca7a4dbf144ba92969b1cb2fbf799b867b0ec05601d90bcf294c7bd281b2714f44d92e68479179daf290fcf241444dea0aacf2385934a13651e126828aeaa3dd6a9b118c8a32c64b4da15694ad8d1f7eb1941808cf5fe45418823797aac9d9e4b86d570952b263d71af3d6f2c7981eeec02a20cb8daa29afc1142747fcef9b14737b0aa2a6a852a18e14fddf00c1d1162fab2e4f4db2eab22467b855f33aa5fdcc1ce6e1064c86d8626cda9b653487d37b06c2f7e60144ad28d5858279da65b9f546bd226c39fdb6119e7f39dfda5aaae09c9df1ee35e2974be4a2619dadaf1190a4d28e6b9accf917c612adae5e7da64b67dfc99f6771bdf78a8dcff19150b85d63f0945c5146643a8ba2a43d8eb9acad2917071e9ae9f0eeb644c5e6ea3438342fe89e4f1df159647735d90b0c9e39fcd24c21c53ab107327f3a04a1f6bc4955dde9016d932b0926c9c6c146eb38928ab12c088d1c270497d32523061606204a3b2db41c5cbda53e7a875b0c18e232e3f8974e47dba72448d3f3df3e6e7316aed99872f5b4ecbed86b60068db8547704ce256322d5ec5a2c8f8b4d9e384829806e7b56d6fa179ef6598098d9410a3c2f270f329ae3eec8c0d8b8ca8af6b1290e8a89a8bbf49215a6738a777a7230ee7cf6ac5cc5959316e8625b763c1697303674fb50bbcb435128ac00181afc01a21665f8f5bc922a2e334fd4f3e1ebbacc444e0c207473446312be804481e92cadeb910f94e517808960b602bb67b7c24628f0435bdb563abee79a845a99ff29b9588fbf0aa40faa81224bd9db1039249af9bc9c045a28094f292f70a0bc480b788f370e2034ffd7773bbc4161087585e62996f8c9df60466be5c1e1624fda208051b2e196cb006022119ffbe3bc8be47bee228b2e81f99717a84d44fe5eb24bbb70c588a973e872f82c38107017e5b3aa8334b2dca20e7e1f8442dc693e50ff6604bf14dd28ea45ccbbaac93c90f8cf5cf2982aee74b131ce0645497fa727f534b7c81c9d1b85433113f4bdeee2cc3accb57eeabebad6cce8b5fdfe892e073f5d04009cf88238d42a80ee80bba1d1f943902a5f2f005ab51f0b8afd71481f48bd5d3e285f277b2bde5a391d008caee3bb34ff4501e22769764a142d617b9ac53e8e9d2745dcefd6097d48b1436a012ef5faeb4a90dd77f1f3b7d7bc3b83252487f98e20d68af7d5498e0436d4bb9d1b3326d050daccfd7bba8da8a0d1c39ea8c3b3b2aba6fa12df553cc0de703a9929acf54dd12255a8dcb5151d10a8a8acf8aa2c46b218ed264c76609c48613f17fc41af76afd889068a069d676f91ed285ef40a1516e2add133280fad46353ac6aacdcd61ecf30ead8a3e268302899ae7b1088acf7df3c2a19827ad0f4132689f97997b575bcd1d86adab5f53b3ab7ab952bd0f17a7407bfb484f584e5948e8763010f32cd7ecd3805bb31ca5d6a2c0b813687c432d759ccfaca0d20e6789719f39e851ec4e87e96268a025165e1b6fcf8ebe3427ddd44562eedc1c1bfc700d41c252d82f298c0c011ae6630f280a7b3c175a6a406b232ed86976b73fc3daffa91ae51880da5ebbedee2e13478fa419a3365390a79d8b9f7d69b5d2c9549ab9384c454846c78340c2f9444b14b25517cacb5d2d0a3d659be38a008f0b1ad506d67f555207192d47fbabb528fad0891d3c94df00171430d8ee05d77e64eab65b24dfd5fa193884cc8e38ac3d52f2b9ddd05d92316e13c109ed9c01aefb5b27ae5c53f110190f0ad435075f1023935f37c33d13c2dfc6a4647ecd7211d09fe11334db7274c27e99ba09be4ee7d0a47bd4a44c362b0f621c141cb5229dec7d04b03375681074f12ae5bea7371f2946614a35b77e435c8f6e213516fcb2a54268991e2d7e4a2ac7f3017d9b44fb4c98f7614a7a0190f3468769cd3a7975b6ce14393470b9d5190f0f878d49852965e77e3be1906f92e82a2ecd504ff51dd446d1621715474f8198db1b06982bab909e2e881e73e56f7519a5ba96975e519e5361cd5ab0cde6f3b7ce58913383068a2a556716ff1ffef1e2eb9fa44ba9120683892c52631cceee9b087054edef8af59baca5a10d37e449a0d855cf2db57b18663be42b32142d64f9052ef78c8663c89163ee448db75f8400ea4405bf83b0b9a58a3216c26a1753aaac34f3a45eba9a488736b9ce0d7c8237b5cc1c11c49770d684f";
    uint32_t const GENESIS_NONCE = 10001;
  }

  namespace stagenet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 24;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 36;
    uint16_t const P2P_DEFAULT_PORT = 39090;
    uint16_t const RPC_DEFAULT_PORT = 39091;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 39092;
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
