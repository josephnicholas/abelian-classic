// Copyright (c) 2014-2019, The Monero Project
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

#include <db_cxx.h>

#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/blobdatatype.h" // for type blobdata

#include <unordered_map>
#include <condition_variable>

// ND: Enables multi-threaded bulk reads for when getting indices.
//     TODO: Disabled for now, as it doesn't seem to provide noticeable improvements (??. Reason: TBD.
// #define BDB_BULK_CAN_THREAD
namespace cryptonote
{

typedef struct txindex {
  crypto::hash key;
  tx_data_t data;
} txindex;

struct bdb_txn_safe
{
  bdb_txn_safe() : m_txn(NULL) { }
  ~bdb_txn_safe()
  {
    LOG_PRINT_L3("bdb_txn_safe: destructor");

    if (m_txn != NULL)
      abort();
  }

  void commit(std::string message = "")
  {
    if (message.size() == 0)
    {
      message = "Failed to commit a transaction to the db";
    }

    if (m_txn->commit(0))
    {
      m_txn = NULL;
      LOG_PRINT_L0(message);
      throw DB_ERROR(message.c_str());
    }
    m_txn = NULL;
  }

  void abort()
  {
    LOG_PRINT_L3("bdb_txn_safe: abort()");
    if(m_txn != NULL)
    {
      m_txn->abort();
      m_txn = NULL;
    }
    else
    {
      LOG_PRINT_L0("WARNING: bdb_txn_safe: abort() called, but m_txn is NULL");
    }
  }

  operator DbTxn*()
  {
    return m_txn;
  }

  operator DbTxn**()
  {
    return &m_txn;
  }
private:
  DbTxn* m_txn;
};

// ND: Class to handle buffer management when doing bulk queries
// (DB_MULTIPLE). Allocates buffers then handles thread queuing
// so a fixed set of buffers can be used (instead of allocating
// every time a bulk query is needed).
template <typename T>
class bdb_safe_buffer
{
  // limit the number of buffers to 8
  const size_t MaxAllowedBuffers = 8;
public:
    bdb_safe_buffer(size_t num_buffers, size_t count)
    {
      if(num_buffers > MaxAllowedBuffers)
        num_buffers = MaxAllowedBuffers;

      set_count(num_buffers);
      for (size_t i = 0; i < num_buffers; i++)
        m_buffers.push_back((T) malloc(sizeof(T) * count));
      m_buffer_count = count;
    }

    ~bdb_safe_buffer()
    {
        for (size_t i = 0; i < m_buffers.size(); i++)
        {
            if (m_buffers[i])
            {
                free(m_buffers[i]);
                m_buffers[i] = nullptr;
            }
        }

        m_buffers.resize(0);
    }

    T acquire_buffer()
    {
        boost::unique_lock<boost::mutex> lock(m_lock);
        m_cv.wait(lock, [&]{ return m_count > 0; });

        --m_count;
        size_t index = -1;
        for (size_t i = 0; i < m_open_slot.size(); i++)
        {
            if (m_open_slot[i])
            {
                m_open_slot[i] = false;
                index = i;
                break;
            }
        }

        assert(index >= 0);

        T buffer = m_buffers[index];
        m_buffer_map.emplace(buffer, index);
        return buffer;
    }

    void release_buffer(T buffer)
    {
        boost::unique_lock<boost::mutex> lock(m_lock);

        assert(buffer != nullptr);
        auto it = m_buffer_map.find(buffer);
        if (it != m_buffer_map.end())
        {
            auto index = it->second;

            assert(index < m_open_slot.size());
            assert(m_open_slot[index] == false);
            assert(m_count < m_open_slot.size());

            ++m_count;
            m_open_slot[index] = true;
            m_buffer_map.erase(it);
            m_cv.notify_one();
        }
    }

    size_t get_buffer_size() const
    {
        return m_buffer_count * sizeof(T);
    }

    size_t get_buffer_count() const
    {
        return m_buffer_count;
    }

    typedef T type;

private:
    void set_count(size_t count)
    {
        assert(count > 0);
        m_open_slot.resize(count, true);
        m_count = count;
    }

    std::vector<T> m_buffers;
    std::unordered_map<T, size_t> m_buffer_map;

    boost::condition_variable m_cv;
    std::vector<bool> m_open_slot;
    size_t m_count;
    boost::mutex m_lock;

    size_t m_buffer_count;
};

template <typename T>
class bdb_safe_buffer_autolock
{
public:
    bdb_safe_buffer_autolock(T &safe_buffer, typename T::type &buffer) :
        m_safe_buffer(safe_buffer), m_buffer(nullptr)
    {
        m_buffer = m_safe_buffer.acquire_buffer();
        buffer = m_buffer;
    }

    ~bdb_safe_buffer_autolock()
    {
        if (m_buffer != nullptr)
        {
            m_safe_buffer.release_buffer(m_buffer);
            m_buffer = nullptr;
        }
    }
private:
    T &m_safe_buffer;
    typename T::type m_buffer;
};

class BlockchainBDB : public BlockchainDB
{
public:
  BlockchainBDB(bool batch_transactions=false);
  ~BlockchainBDB();

  void open(const std::string& filename, const int db_flags) override ;

  void close() override ;

  void sync() override ;

  void safesyncmode(const bool onoff) override ;

  void reset() override ;

  std::vector<std::string> get_filenames() const override ;

  bool remove_data_file(const std::string& folder) const override ;

  std::string get_db_name() const override ;

  bool lock() override ;

  void unlock() override ;

  bool block_exists(const crypto::hash& h, uint64_t *height = nullptr) const override ;

  uint64_t get_block_height(const crypto::hash& h) const override ;

  block_header get_block_header(const crypto::hash& h) const override;

  cryptonote::blobdata get_block_blob(const crypto::hash& h) const override;

  cryptonote::blobdata get_block_blob_from_height(const uint64_t& height) const override ;

  std::vector<uint64_t> get_block_cumulative_rct_outputs(const std::vector<uint64_t> &heights) const override ;

  uint64_t get_block_timestamp(const uint64_t& height) const override ;

  uint64_t get_top_block_timestamp() const override ;

  size_t get_block_weight(const uint64_t& height) const override;

  std::vector<uint64_t> get_block_weights(uint64_t start_height, size_t count) const override;

  difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const override;

  difficulty_type get_block_difficulty(const uint64_t& height) const override;

  uint64_t get_block_already_generated_coins(const uint64_t& height) const override;

  uint64_t get_block_long_term_weight(const uint64_t& height) const override ;

  std::vector<uint64_t> get_long_term_block_weights(uint64_t start_height, size_t count) const override ;

  crypto::hash get_block_hash_from_height(const uint64_t& height) const override ;

  std::vector<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const override ;

  std::vector<crypto::hash> get_hashes_range(const uint64_t& h1, const uint64_t& h2) const override;

  crypto::hash top_block_hash(uint64_t *block_height) const override ;

  block get_top_block() const override ;

  uint64_t height() const override ;

  bool tx_exists(const crypto::hash& h) const override;
  bool tx_exists(const crypto::hash& h, uint64_t& tx_index) const override;

  uint64_t get_tx_unlock_time(const crypto::hash& h) const override ;

  bool get_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const override;
  bool get_pruned_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const override;
  bool get_prunable_tx_blob(const crypto::hash& h, cryptonote::blobdata &tx) const override;
  bool get_prunable_tx_hash(const crypto::hash& tx_hash, crypto::hash &prunable_hash) const override;

  uint64_t get_tx_count() const override;

  std::vector<transaction> get_tx_list(const std::vector<crypto::hash>& hlist) const override ;

  uint64_t get_tx_block_height(const crypto::hash& h) const override;

  uint64_t get_num_outputs(const uint64_t& amount) const override;

  output_data_t get_output_key(const uint64_t& amount, const uint64_t& index, bool include_commitmemt) const override ;
  void get_output_key(const epee::span<const uint64_t> &amounts, const std::vector<uint64_t> &offsets, std::vector<output_data_t> &outputs, bool allow_partial = false) const override ;

  tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const override ;
  virtual void get_output_tx_and_index_from_global(const std::vector<uint64_t> &global_indices, std::vector<tx_out_index> &tx_out_indices) const;

  tx_out_index get_output_tx_and_index(const uint64_t& amount, const uint64_t& index) const override;
  void get_output_tx_and_index(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<tx_out_index> &indices) const override ;

  std::vector<std::vector<uint64_t>> get_tx_amount_output_indices(const uint64_t tx_id, size_t n_txes) const override ;

  bool has_key_image(const crypto::key_image& img) const override ;

  void add_txpool_tx(const crypto::hash &txid, const cryptonote::blobdata &blob, const txpool_tx_meta_t& meta) override ;

  void update_txpool_tx(const crypto::hash &txid, const txpool_tx_meta_t& meta) override;
  uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const override;
  bool txpool_has_tx(const crypto::hash &txid) const override;
  void remove_txpool_tx(const crypto::hash& txid) override;
  bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t &meta) const override;
  bool get_txpool_tx_blob(const crypto::hash& txid, cryptonote::blobdata &bd) const override;
  cryptonote::blobdata get_txpool_tx_blob(const crypto::hash& txid) const override;
  uint32_t get_blockchain_pruning_seed() const override;
  bool prune_blockchain(uint32_t pruning_seed = 0) override;
  bool update_pruning() override;
  bool check_pruning() override;

   bool for_all_txpool_txes(std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const cryptonote::blobdata*)> f, bool include_blob = false, bool include_unrelayed_txes = true) const override ;

  bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const override ;

  bool for_blocks_range(const uint64_t& h1, const uint64_t& h2, std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)>) const override ;
  bool for_all_transactions(std::function<bool(const crypto::hash&, const cryptonote::transaction&)>, bool pruned) const override ;
  bool for_all_outputs(std::function<bool(uint64_t amount, const crypto::hash &tx_hash, uint64_t height, size_t tx_idx)> f) const override ;
  bool for_all_outputs(uint64_t amount, const std::function<bool(uint64_t height)> &f) const override ;

  uint64_t add_block( const std::pair<block, blobdata>& blk
                    , size_t block_weight
                    , uint64_t long_term_block_weight
                    , const difficulty_type& cumulative_difficulty
                    , const uint64_t& coins_generated
                    , const std::vector<std::pair<transaction, blobdata>>& txs
                    ) override;

  void set_batch_transactions(bool batch_transactions) override ;
  bool batch_start(uint64_t batch_num_blocks=0, uint64_t batch_bytes=0) override ;
  virtual void batch_commit();
  void batch_stop() override;
  void batch_abort() override ;

  void block_wtxn_start() override;
  void block_wtxn_stop() override;
  void block_wtxn_abort() override;
  bool block_rtxn_start() const override;
  void block_rtxn_stop() const override;
  void block_rtxn_abort() const override;

  void pop_block(block& blk, std::vector<transaction>& txs) override;

#if defined(BDB_BULK_CAN_THREAD)
  virtual bool can_thread_bulk_indices() const { return true; }
#else
  bool can_thread_bulk_indices() const override { return false; }
#endif

  /**
   * @brief return a histogram of outputs on the blockchain
   *
   * @param amounts optional set of amounts to lookup
   * @param unlocked whether to restrict count to unlocked outputs
   * @param recent_cutoff timestamp to determine which outputs are recent
   * @param min_count return only amounts with at least that many instances
   *
   * @return a set of amount/instances
   */
  std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(const std::vector<uint64_t> &amounts, bool unlocked, uint64_t recent_cutoff, uint64_t min_count) const override;

  bool get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, std::vector<uint64_t> &distribution, uint64_t &base) const override ;

private:

  virtual void add_block( const block& blk
              , size_t block_weight
              , uint64_t long_term_block_weight
              , const difficulty_type& cumulative_difficulty
              , const uint64_t& coins_generated
              , uint64_t num_rct_outs
              , const crypto::hash& block_hash
              ) override;

  void remove_block() override;

  uint64_t add_transaction_data(const crypto::hash& blk_hash, const std::pair<transaction, blobdata>& tx, const crypto::hash& tx_hash, const crypto::hash& tx_prunable_hash) override ;

  void remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx) override ;

  uint64_t add_output(const crypto::hash& tx_hash,
                              const tx_out& tx_output,
                              const uint64_t& local_index,
                              const uint64_t unlock_time,
                              const rct::key *commitment
  ) override ;

  void add_tx_amount_output_indices(const uint64_t tx_id,
                                            const std::vector<uint64_t>& amount_output_indices
  ) override ;

  void remove_output(const uint64_t &amount, const uint64_t& out_index);

  void remove_tx_outputs(const uint64_t &tx_id, const transaction& tx);

  void remove_amount_output_index(const uint64_t amount, const uint64_t global_output_index);

  void prune_outputs(uint64_t amount) override;

  void add_spent_key(const crypto::key_image& k_image) override;

  void remove_spent_key(const crypto::key_image& k_image) override;

  void get_output_global_indices(const uint64_t& amount, const std::vector<uint64_t> &offsets, std::vector<uint64_t> &global_indices);

  uint64_t num_outputs() const;

  // Hard fork related storage
  void set_hard_fork_version(uint64_t height, uint8_t version) override;
  uint8_t get_hard_fork_version(uint64_t height) const override;
  void check_hard_fork_info() override;
  void drop_hard_fork_info() override;

  /**
   * @brief get the global index of the index-th output of the given amount
   *
   * @param amount the output amount
   * @param index the index into the set of outputs of that amount
   *
   * @return the global index of the desired output
   */
  uint64_t get_output_global_index(const uint64_t& amount, const uint64_t& index);

  void checkpoint_worker() const;
  void check_open() const;

  virtual bool is_read_only() const;

  virtual uint64_t get_database_size() const;

  //
  // fix up anything that may be wrong due to past bugs
  virtual void fixup();

  uint64_t get_max_block_size() override;
  void add_max_block_size(uint64_t sz) override;

  bool m_run_checkpoint;
  std::unique_ptr<boost::thread> m_checkpoint_thread;
  typedef bdb_safe_buffer<void *> bdb_safe_buffer_t;
  bdb_safe_buffer_t m_buffer;

private:
  DbEnv* m_env;

  typedef struct bdb_txn_cursors
  {
    Dbc *m_txc_blocks;
    Dbc *m_txc_block_heights;
    Dbc *m_txc_block_info;

    Dbc *m_txc_output_txs;
    Dbc *m_txc_output_amounts;

    Dbc *m_txc_txs;
    Dbc *m_txc_txs_pruned;
    Dbc *m_txc_txs_prunable;
    Dbc *m_txc_txs_prunable_hash;
    Dbc *m_txc_txs_prunable_tip;
    Dbc *m_txc_tx_indices;
    Dbc *m_txc_tx_outputs;

    Dbc *m_txc_spent_keys;

    Dbc *m_txc_txpool_meta;
    Dbc *m_txc_txpool_blob;

    Dbc *m_txc_hf_versions;

    Dbc *m_txc_properties;
  } bdb_txn_cursors;

  #define m_cur_blocks	                m_cursors->m_txc_blocks
  #define m_cur_block_heights	        m_cursors->m_txc_block_heights
  #define m_cur_block_info	            m_cursors->m_txc_block_info
  #define m_cur_output_txs	            m_cursors->m_txc_output_txs
  #define m_cur_output_amounts	        m_cursors->m_txc_output_amounts
  #define m_cur_txs	                    m_cursors->m_txc_txs
  #define m_cur_txs_pruned	            m_cursors->m_txc_txs_pruned
  #define m_cur_txs_prunable	        m_cursors->m_txc_txs_prunable
  #define m_cur_txs_prunable_hash	    m_cursors->m_txc_txs_prunable_hash
  #define m_cur_txs_prunable_tip	    m_cursors->m_txc_txs_prunable_tip
  #define m_cur_tx_indices	            m_cursors->m_txc_tx_indices
  #define m_cur_tx_outputs	            m_cursors->m_txc_tx_outputs
  #define m_cur_spent_keys	            m_cursors->m_txc_spent_keys
  #define m_cur_txpool_meta	            m_cursors->m_txc_txpool_meta
  #define m_cur_txpool_blob	            m_cursors->m_txc_txpool_blob
  #define m_cur_hf_versions	            m_cursors->m_txc_hf_versions
  #define m_cur_properties	            m_cursors->m_txc_properties

  Db* m_blocks;
  Db* m_block_info;
  Db* m_block_heights;
  Db* m_block_hashes;
  Db* m_block_timestamps;
  Db* m_block_sizes;
  Db* m_block_diffs;
  Db* m_block_coins;

  Db* m_txs;
  Db* m_tx_unlocks;
  Db* m_tx_heights;
  Db* m_tx_outputs;

  Db* m_txs_indices;
  Db* m_txs_pruned;
  Db* m_txs_prunable;
  Db* m_txs_prunable_hash;
  Db* m_txs_prunable_tip;

  Db* m_output_txs;
  Db* m_output_indices;
  Db* m_output_amounts;
  Db* m_output_keys;

  Db* m_spent_keys;

  Db* m_hf_starting_heights;
  Db* m_hf_versions;

  Db* m_properties;

  uint64_t m_height;
  uint64_t m_num_outputs;
  std::string m_folder;
  bdb_txn_safe *m_write_txn;

  mutable uint64_t m_cum_size;	// used in batch size estimation
  mutable unsigned int m_cum_count;

  bool m_batch_transactions; // support for batch transactions

  bdb_txn_cursors m_wcursors;
};

}  // namespace cryptonote
