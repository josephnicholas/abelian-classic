// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list
//    of conditions and the following disclaimer in the documentation and/or
//    other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote
// developers

#pragma once

#include <boost/optional.hpp>
#include <crypto/salrs/src/polyvec_salrs.h>
#include <cstddef>
#include <iostream>
#include <random>
#include <type_traits>
#include <vector>

#include "common/pod-class.h"
#include "generic-ops.h"
#include "hash.h"
#include "hex.h"
#include "memwipe.h"
#include "mlocker.h"
#include "span.h"

namespace crypto {

extern "C" {
#include "salrs/src/params_salrs.h"
}

#pragma pack(push, 1)
POD_CLASS ec_point { std::array<char, SIZE_MPK> buffer; };

POD_CLASS ec_scalar { std::array<char, SIZE_MSK> buffer; };

POD_CLASS public_key : ec_point { friend class crypto_ops; };

// Randomness data type
POD_CLASS random_key {
  char data[32]; // We need to agree on this!
};

POD_CLASS derived_public_key { std::array<char, SIZE_DPK> buffer; };

using secret_key = epee::mlocked<tools::scrubbed<ec_scalar>>;
using rand_key = epee::mlocked<tools::scrubbed<random_key>>;

POD_CLASS secret_keyV {
  std::vector<secret_key> keys;
  int rows;
};

POD_CLASS key_image {
  std::array<char, 1152> buffer;
  friend class crypto_ops;
};

POD_CLASS signature {
  std::array<char, 4712> buffer;
  friend class crypto_ops;
};
#pragma pack(pop)

void hash_to_scalar(
    const void *data, size_t length,
    ec_scalar &res); // TODO: need to clarify for the output to be 32
void random32_unbiased(unsigned char *bytes);

/*static_assert(sizeof(ec_point) == 32 && sizeof(ec_scalar) == 32 &&
  sizeof(public_key) == 32 && sizeof(secret_key) == 32 &&
  sizeof(key_derivation) == 32 && sizeof(key_image) == 32 &&
  sizeof(signature) == 64, "Invalid structure size");*/

class crypto_ops {
  crypto_ops();
  crypto_ops(const crypto_ops &);
  void operator=(const crypto_ops &);
  ~crypto_ops();

  static rand_key generate_keys(public_key &pub, secret_key &sec,
                                const rand_key &recovery_key = rand_key(),
                                bool recover = false);
  friend rand_key generate_keys(public_key &pub, secret_key &sec,
                                const rand_key &recovery_key, bool recover);
  static bool check_derived_public_key(const derived_public_key &key);
  friend bool check_derived_public_key(const derived_public_key &key);
  static bool secret_key_to_public_key(const secret_key &, public_key &);
  friend bool secret_key_to_public_key(const secret_key &, public_key &);
  static bool generate_key_derivation(const public_key &, const secret_key &,
                                      derived_public_key &);
  friend bool generate_key_derivation(const public_key &, const secret_key &,
                                      derived_public_key &);
  static void derivation_to_scalar(const derived_public_key &derivation,
                                   size_t output_index, ec_scalar &res);
  friend void derivation_to_scalar(const derived_public_key &derivation,
                                   size_t output_index, ec_scalar &res);
  static bool derive_public_key(const derived_public_key &, std::size_t,
                                const public_key &, public_key &);
  friend bool derive_public_key(const derived_public_key &, std::size_t,
                                const public_key &, public_key &);

  // SALRS
  static bool derive_master_public_key(const public_key &,
                                       derived_public_key &);
  friend bool derive_master_public_key(const public_key &,
                                       derived_public_key &);

  static bool check_derived_key_ownersip(const derived_public_key &,
                                         const secret_key &,
                                         const public_key &);
  friend bool check_derived_key_ownersip(const derived_public_key &,
                                         const secret_key &,
                                         const public_key &);

  static void derive_secret_key(const derived_public_key &, std::size_t,
                                const secret_key &, secret_key &);
  friend void derive_secret_key(const derived_public_key &, std::size_t,
                                const secret_key &, secret_key &);
  static bool derive_subaddress_public_key(const public_key &,
                                           const derived_public_key &,
                                           std::size_t, public_key &);
  friend bool derive_subaddress_public_key(const public_key &,
                                           const derived_public_key &,
                                           std::size_t, public_key &);
  static void generate_signature(const hash &, const public_key &,
                                 const secret_key &, signature &);
  friend void generate_signature(const hash &, const public_key &,
                                 const secret_key &, signature &);
  static bool check_signature(const hash &, const public_key &,
                              const signature &);
  friend bool check_signature(const hash &, const public_key &,
                              const signature &);
  static void generate_tx_proof(const hash &, const public_key &,
                                const public_key &,
                                const boost::optional<public_key> &,
                                const public_key &, const secret_key &,
                                signature &);
  friend void generate_tx_proof(const hash &, const public_key &,
                                const public_key &,
                                const boost::optional<public_key> &,
                                const public_key &, const secret_key &,
                                signature &);
  static bool check_tx_proof(const hash &, const public_key &,
                             const public_key &,
                             const boost::optional<public_key> &,
                             const public_key &, const signature &);
  friend bool check_tx_proof(const hash &, const public_key &,
                             const public_key &,
                             const boost::optional<public_key> &,
                             const public_key &, const signature &);
  static void generate_key_image(const public_key &, const secret_key &,
                                 key_image &);
  friend void generate_key_image(const public_key &, const secret_key &,
                                 key_image &);

  // Changing for SALRS use
  static void generate_ring_signature(const hash &, const std::size_t &,
                                      const derived_public_key *const *,
                                      std::size_t, const derived_public_key &,
                                      const public_key &, const secret_key &,
                                      key_image &, polyvecl &, signature *);
  friend void generate_ring_signature(const hash &, const std::size_t &,
                                      const derived_public_key *const *,
                                      std::size_t, const derived_public_key &,
                                      const public_key &, const secret_key &,
                                      key_image &img, polyvecl &, signature *);

  static bool check_ring_signature(const hash &, const key_image &,
                                   const public_key *const *, std::size_t,
                                   const signature *);
  friend bool check_ring_signature(const hash &, const key_image &,
                                   const public_key *const *, std::size_t,
                                   const signature *);
};

void generate_random_bytes_thread_safe(size_t _N, uint8_t *bytes);

/* Generate N random bytes
 */
inline void rand(size_t _N, uint8_t *bytes) {
  generate_random_bytes_thread_safe(_N, bytes);
}

/* Generate a value filled with random bytes.
 */
template <typename T>
typename std::enable_if<std::is_pod<T>::value, T>::type rand() {
  typename std::remove_cv<T>::type res;
  generate_random_bytes_thread_safe(sizeof(T), (uint8_t *)&res);
  return res;
}

/* UniformRandomBitGenerator using crypto::rand<uint64_t>()
 */
struct random_device {
  typedef uint64_t result_type;
  static constexpr result_type min() { return 0; }
  static constexpr result_type max() { return result_type(-1); }
  result_type operator()() const { return crypto::rand<result_type>(); }
};

/* Generate a random value between range_min and range_max
 */
template <typename T>
typename std::enable_if<std::is_integral<T>::value, T>::type
rand_range(T range_min, T range_max) {
  crypto::random_device rd;
  std::uniform_int_distribution<T> dis(range_min, range_max);
  return dis(rd);
}

/* Generate a random index between 0 and sz-1
 */
template <typename T>
typename std::enable_if<std::is_unsigned<T>::value, T>::type rand_idx(T sz) {
  return crypto::rand_range<T>(0, sz - 1);
}

/* Generate a new key pair
 */
inline rand_key generate_keys(public_key &pub, secret_key &sec,
                              const rand_key &recovery_key = rand_key(),
                              bool recover = false) {
  return crypto_ops::generate_keys(pub, sec, recovery_key, recover);
}

/* Check a public key. Returns true if it is valid, false otherwise.
 */
inline bool check_derived_public_key(const derived_public_key &key) {
  return crypto_ops::check_derived_public_key(key);
}

/* Checks a private key and computes the corresponding public key.
 */
inline bool secret_key_to_public_key(const secret_key &sec, public_key &pub) {
  return crypto_ops::secret_key_to_public_key(sec, pub);
}

/* To generate an ephemeral key used to send money to:
 * * The sender generates a new key pair, which becomes the transaction key. The
 * public transaction key is included in "extra" field.
 * * Both the sender and the receiver generate key derivation from the
 * transaction key, the receivers' "view" key and the output index.
 * * The sender uses key derivation and the receivers' "spend" key to derive an
 * ephemeral public key.
 * * The receiver can either derive the public key (to check that the
 * transaction is addressed to him) or the private key (to spend the money).
 */
inline bool generate_key_derivation(const public_key &key1,
                                    const secret_key &key2,
                                    derived_public_key &derivation) {
  return crypto_ops::generate_key_derivation(key1, key2, derivation);
}

inline bool derive_public_key(const derived_public_key &derivation,
                              std::size_t output_index, const public_key &base,
                              public_key &derived_key) {
  return crypto_ops::derive_public_key(derivation, output_index, base,
                                       derived_key);
}

// SALRS
inline bool derive_master_public_key(const public_key &mPK,
                                     derived_public_key &dPK) {
  return crypto_ops::derive_master_public_key(mPK, dPK);
}

inline bool check_derived_key_ownersip(const derived_public_key &dPK,
                                       const secret_key &mSK,
                                       const public_key &mPK) {
  return crypto_ops::check_derived_key_ownersip(dPK, mSK, mPK);
}

inline void derivation_to_scalar(const derived_public_key &derivation,
                                 size_t output_index, ec_scalar &res) {
  return crypto_ops::derivation_to_scalar(derivation, output_index, res);
}
inline void derive_secret_key(const derived_public_key &derivation,
                              std::size_t output_index, const secret_key &base,
                              secret_key &derived_key) {
  crypto_ops::derive_secret_key(derivation, output_index, base, derived_key);
}
inline bool derive_subaddress_public_key(const public_key &out_key,
                                         const derived_public_key &derivation,
                                         std::size_t output_index,
                                         public_key &result) {
  return crypto_ops::derive_subaddress_public_key(out_key, derivation,
                                                  output_index, result);
}

/* Generation and checking of a standard signature.
 */
inline void generate_signature(const hash &prefix_hash, const public_key &pub,
                               const secret_key &sec, signature &sig) {
  crypto_ops::generate_signature(prefix_hash, pub, sec, sig);
}
inline bool check_signature(const hash &prefix_hash, const public_key &pub,
                            const signature &sig) {
  return crypto_ops::check_signature(prefix_hash, pub, sig);
}

/* Generation and checking of a tx proof; given a tx pubkey R, the recipient's
 * view pubkey A, and the key derivation D, the signature proves the knowledge
 * of the tx secret key r such that R=r*G and D=r*A When the recipient's address
 * is a subaddress, the tx pubkey R is defined as R=r*B where B is the
 * recipient's spend pubkey
 */
inline void generate_tx_proof(const hash &prefix_hash, const public_key &R,
                              const public_key &A,
                              const boost::optional<public_key> &B,
                              const public_key &_D, const secret_key &r,
                              signature &sig) {
  crypto_ops::generate_tx_proof(prefix_hash, R, A, B, _D, r, sig);
}
inline bool check_tx_proof(const hash &prefix_hash, const public_key &R,
                           const public_key &A,
                           const boost::optional<public_key> &B,
                           const public_key &_D, const signature &sig) {
  return crypto_ops::check_tx_proof(prefix_hash, R, A, B, _D, sig);
}

/* To send money to a key:
 * * The sender generates an ephemeral key and includes it in transaction
 * output.
 * * To spend the money, the receiver generates a key image from it.
 * * Then he selects a bunch of outputs, including the one he spends, and uses
 * them to generate a ring signature. To check the signature, it is necessary to
 * collect all the keys that were used to generate it. To detect double spends,
 * it is necessary to check that each key image is used at most once.
 */
inline void generate_key_image(const public_key &pub, const secret_key &sec,
                               key_image &image) {
  crypto_ops::generate_key_image(pub, sec, image);
}
inline void
generate_ring_signature(const hash &prefix_hash, const std::size_t &hash_len,
                        const derived_public_key *const *derived_pubs,
                        std::size_t pubs_count, const derived_public_key &dpk,
                        const public_key &mpk, const secret_key &msk,
                        key_image &img, polyvecl &z, signature *sigs) {
  crypto_ops::generate_ring_signature(prefix_hash, hash_len, derived_pubs,
                                      pubs_count, dpk, mpk, msk, img, z, sigs);
}

inline bool check_ring_signature(const hash &prefix_hash,
                                 const key_image &image,
                                 const public_key *const *pubs,
                                 std::size_t pubs_count, const signature *sig) {
  return crypto_ops::check_ring_signature(prefix_hash, image, pubs, pubs_count,
                                          sig);
}

/* Variants with vector<const public_key *> parameters.
 */
inline void generate_ring_signature(
    const hash &prefix_hash,
    const std::vector<const derived_public_key *> &derived_pubs,
    const derived_public_key &dpk, const public_key &mpk, const secret_key &msk,
    key_image &img, signature *sigs) {
  polyvecl z;
  generate_ring_signature(prefix_hash, sizeof(prefix_hash), derived_pubs.data(),
                          derived_pubs.size(), dpk, mpk, msk, img, z, sigs);
}

inline bool check_ring_signature(const hash &prefix_hash,
                                 const key_image &image,
                                 const std::vector<const public_key *> &pubs,
                                 const signature *sig) {
  return check_ring_signature(prefix_hash, image, pubs.data(), pubs.size(),
                              sig);
}

inline std::ostream &operator<<(std::ostream &o, const crypto::public_key &v) {
  epee::to_hex::formatted(o, epee::as_byte_span(v));
  return o;
}
inline std::ostream &operator<<(std::ostream &o, const crypto::secret_key &v) {
  epee::to_hex::formatted(o, epee::as_byte_span(v));
  return o;
}
inline std::ostream &operator<<(std::ostream &o,
                                const crypto::derived_public_key &v) {
  epee::to_hex::formatted(o, epee::as_byte_span(v));
  return o;
}
inline std::ostream &operator<<(std::ostream &o, const crypto::key_image &v) {
  epee::to_hex::formatted(o, epee::as_byte_span(v));
  return o;
}
inline std::ostream &operator<<(std::ostream &o, const crypto::signature &v) {
  epee::to_hex::formatted(o, epee::as_byte_span(v));
  return o;
}

const extern crypto::public_key null_pkey;
const extern crypto::secret_key null_skey;
const extern crypto::derived_public_key null_dPkey;
} // namespace crypto

CRYPTO_MAKE_HASHABLE(derived_public_key)
CRYPTO_MAKE_HASHABLE(public_key)
CRYPTO_MAKE_HASHABLE_CONSTANT_TIME(secret_key)
CRYPTO_MAKE_HASHABLE(key_image)
CRYPTO_MAKE_COMPARABLE(signature)
