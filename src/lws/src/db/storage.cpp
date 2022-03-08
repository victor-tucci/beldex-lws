#include "storage.h"

#include <boost/container/static_vector.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/iterator_range.hpp>
#include <cassert>
#include <chrono>
#include <limits>
#include <string>
#include <utility>

#include "checkpoints/checkpoints.h"
#include "config.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/expect.h"   //beldex/src
#include "error.h"
#include "epee/hex.h"
#include "data.h"
#include "lmdb/database.h"   //beldex/src
#include "lmdb/error.h"
#include "lmdb/key_stream.h"
#include "lmdb/table.h"
#include "lmdb/util.h"
#include "lmdb/value_stream.h"
#include "epee/span.h"


namespace lws
{
namespace db
{
  namespace
  {
    struct account_lookup
    {
      account_id id;
      account_status status;
      char reserved[3];
    };
    
    struct account_by_address
    {
      account_address address; //!< Must be first for LMDB optimizations
      account_lookup lookup;
    };

    constexpr const unsigned blocks_version = 0;
    constexpr const unsigned by_address_version = 0;
    
    template<typename T>
    int less(epee::span<const std::uint8_t> left, epee::span<const std::uint8_t> right) noexcept
    {
      if (left.size() < sizeof(T))
      {
        assert(left.empty());
        return -1;
      }
      if (right.size() < sizeof(T))
      {
        assert(right.empty());
        return 1;
      }

      T left_val;
      T right_val;
      // uint8_t left_val;
      // uint8_t right_val;
      std::memcpy(std::addressof(left_val), left.data(), sizeof(T));
      std::memcpy(std::addressof(right_val), right.data(), sizeof(T));

      return (left_val < right_val) ? -1 : int(right_val < left_val);
    }

    int compare_32bytes(epee::span<const std::uint8_t> left, epee::span<const std::uint8_t> right) noexcept
    {
      if (left.size() < 32)
      {
        assert(left.empty());
        return -1;
      }
      if (right.size() < 32)
      {
        assert(right.empty());
        return 1;
      }

      return std::memcmp(left.data(), right.data(), 32);
    }

    int output_compare(MDB_val const* left, MDB_val const* right) noexcept
    {
      if (left == nullptr || right == nullptr)
      {
        assert("MDB_val nullptr" == 0);
        return -1;
      }

      auto left_bytes = lmdb::to_byte_span(*left);
      auto right_bytes = lmdb::to_byte_span(*right);

      int diff = less<lmdb::native_type<block_id>>(left_bytes, right_bytes);
      if (diff)
        return diff;

      left_bytes.remove_prefix(sizeof(block_id));
      right_bytes.remove_prefix(sizeof(block_id));

      static_assert(sizeof(crypto::hash) == 32, "bad memcmp below");
      diff = compare_32bytes(left_bytes, right_bytes);
      if (diff)
        return diff;

      left_bytes.remove_prefix(sizeof(crypto::hash));
      right_bytes.remove_prefix(sizeof(crypto::hash));
      return less<output_id>(left_bytes, right_bytes);
    }
    int spend_compare(MDB_val const* left, MDB_val const* right) noexcept
    {
      if (left == nullptr || right == nullptr)
      {
        assert("MDB_val nullptr" == 0);
        return -1;
      }

      auto left_bytes = lmdb::to_byte_span(*left);
      auto right_bytes = lmdb::to_byte_span(*right);

      int diff = less<lmdb::native_type<block_id>>(left_bytes, right_bytes);
      if (diff)
        return diff;

      left_bytes.remove_prefix(sizeof(block_id));
      right_bytes.remove_prefix(sizeof(block_id));

      static_assert(sizeof(crypto::hash) == 32, "bad memcmp below");
      diff = compare_32bytes(left_bytes, right_bytes);
      if (diff)
        return diff;

      left_bytes.remove_prefix(sizeof(crypto::hash));
      right_bytes.remove_prefix(sizeof(crypto::hash));

      static_assert(sizeof(crypto::key_image) == 32, "bad memcmp below");
      return compare_32bytes(left_bytes, right_bytes);
    }

    constexpr const lmdb::basic_table<unsigned, block_info> blocks{
      "blocks_by_id", (MDB_CREATE | MDB_DUPSORT), MONERO_SORT_BY(block_info, id)
    };
    constexpr const lmdb::basic_table<account_status, account> accounts{
      "accounts_by_status,id", (MDB_CREATE | MDB_DUPSORT), MONERO_SORT_BY(account, id)
    };
    constexpr const lmdb::basic_table<unsigned, account_by_address> accounts_by_address(
      "accounts_by_address", (MDB_CREATE | MDB_DUPSORT), MONERO_COMPARE(account_by_address, address.view_public)
    );
    constexpr const lmdb::basic_table<block_id, account_lookup> accounts_by_height(
      "accounts_by_height,id", (MDB_CREATE | MDB_DUPSORT), MONERO_SORT_BY(account_lookup, id)
    );
    constexpr const lmdb::basic_table<account_id, output> outputs{
      "outputs_by_account_id,block_id,tx_hash,output_id", (MDB_CREATE | MDB_DUPSORT), &output_compare
    };
    constexpr const lmdb::basic_table<account_id, spend> spends{
      "spends_by_account_id,block_id,tx_hash,image", (MDB_CREATE | MDB_DUPSORT), &spend_compare
    };
    constexpr const lmdb::basic_table<output_id, db::key_image> images{
      "key_images_by_output_id,image", (MDB_CREATE | MDB_DUPSORT), MONERO_COMPARE(db::key_image, value)
    };
    constexpr const lmdb::basic_table<request, request_info> requests{
      "requests_by_type,address", (MDB_CREATE | MDB_DUPSORT), MONERO_COMPARE(request_info, address.spend_public)
    };

    template<typename D>
    expect<void> check_cursor(MDB_txn& txn, MDB_dbi tbl, std::unique_ptr<MDB_cursor, D>& cur) noexcept
    {
      if (cur)
      {
        MONERO_LMDB_CHECK(mdb_cursor_renew(&txn, cur.get()));
      }
      else
      {
        auto new_cur = lmdb::open_cursor<D>(txn, tbl);
        if (!new_cur)
          return new_cur.error();
        cur = std::move(*new_cur);
      }
      return success();
    }

    template<typename K, typename V>
    expect<void> bulk_insert(MDB_cursor& cur, K const& key, epee::span<V> values) noexcept
    {
      // std::cout << " values.size() : " << values.size() << std::endl;
      while (!values.empty())
      {
        void const* const data = reinterpret_cast<void const*>(values.data());
        MDB_val key_bytes = lmdb::to_val(key);
        MDB_val value_bytes[2] = {
          MDB_val{sizeof(V), const_cast<void*>(data)}, MDB_val{values.size(), nullptr}
        };
        // std::cout << " before the mdb_cursor_put " << std::endl;
        int err = mdb_cursor_put(
          &cur, &key_bytes, value_bytes, (MDB_NODUPDATA | MDB_MULTIPLE)
        );
        if (err && err != MDB_KEYEXIST)
          return {lmdb::error(err)};

        values.remove_prefix(value_bytes[1].mv_size + (err == MDB_KEYEXIST ? 1 : 0));
      }
      // std::cout << " inside the bulk insert function" << std::endl;
      return success();
    }

    cryptonote::checkpoints const& get_checkpoints()
    {
      struct initializer
      {
        cryptonote::checkpoints data;

        initializer()
          : data()
        {
          data.init_default_checkpoints(lws::config::network);

          std::string_view genesis_tx ;
          std::uint32_t genesis_nonce = 0;

          switch (lws::config::network)
          {
          // case cryptonote::TESTNET:
          //   genesis_tx = std::addressof(::config::testnet::GENESIS_TX);
          //   genesis_nonce = ::config::testnet::GENESIS_NONCE;
          //   break;

          // case cryptonote::STAGENET:
          //   genesis_tx = std::addressof(::config::stagenet::GENESIS_TX);
          //   genesis_nonce = ::config::stagenet::GENESIS_NONCE;
          //   break;

          case cryptonote::MAINNET:
            genesis_tx = ::config::GENESIS_TX;
            genesis_nonce = ::config::GENESIS_NONCE;
            break;

          default:
            MONERO_THROW(lws::error::bad_blockchain, "Unsupported net type");
          }
          cryptonote::block b;
          cryptonote::generate_genesis_block(b,cryptonote::MAINNET);
          crypto::hash block_hash = cryptonote::get_block_hash(b);
          if (!data.add_checkpoint(0, epee::to_hex::string(epee::as_byte_span(block_hash))))
            MONERO_THROW(lws::error::bad_blockchain, "Genesis tx and checkpoints file mismatch");
        }
      };
      static const initializer instance;
      return instance.data;
    }
    expect<crypto::hash> do_get_block_hash(MDB_cursor& cur, block_id id) noexcept
    {
      MDB_val key = lmdb::to_val(blocks_version);
      MDB_val value = lmdb::to_val(id);
      MONERO_LMDB_CHECK(mdb_cursor_get(&cur, &key, &value, MDB_GET_BOTH));
      return blocks.get_value<MONERO_FIELD(block_info, hash)>(value);
    }

    void check_blockchain(MDB_txn& txn, MDB_dbi tbl)
    {
      std::cout << "check point function called : "<<__FILE__ << std::endl;
      cursor::blocks cur = MONERO_UNWRAP(lmdb::open_cursor<cursor::close_blocks>(txn, tbl));
      std::cout << "check point function called two : "<<__FILE__ << std::endl;
      std::map<std::uint64_t, crypto::hash> const& points =
        get_checkpoints().get_points();
         std::cout <<"points.size() : "<< points.size()<< std::endl;
        for(auto it = points.begin();it!=points.end();it++)
        {
          std::cout <<"check_points : " << it->first << " " << it->second << std::endl;
        }

      if (points.empty() || points.begin()->first != 0)
        MONERO_THROW(lws::error::bad_blockchain, "Checkpoints are empty/expected genesis hash");

      MDB_val key = lmdb::to_val(blocks_version);
      int err = mdb_cursor_get(cur.get(), &key, nullptr, MDB_SET);
      if (err)
      {
        if (err != MDB_NOTFOUND)
          MONERO_THROW(lmdb::error(err), "Unable to retrieve blockchain hashes");

        // new database
        block_info checkpoint{
          block_id(points.begin()->first), points.begin()->second
        };

        MDB_val value = lmdb::to_val(checkpoint);
        err = mdb_cursor_put(cur.get(), &key, &value, MDB_NODUPDATA);
        if (err)
          MONERO_THROW(lmdb::error(err), "Unable to add hash to local blockchain");

        if (1 < points.size())
        {
          checkpoint = block_info{
            block_id(points.rbegin()->first), points.rbegin()->second
          };

          value = lmdb::to_val(checkpoint);
          err = mdb_cursor_put(cur.get(), &key, &value, MDB_NODUPDATA);
          if (err)
            MONERO_THROW(lmdb::error(err), "Unable to add hash to local blockchain");
        }
      }
      else // inspect existing database
      {
        ///
        /// TODO Trim blockchain after a checkpoint has been reached
        ///
        std::cout << " inside the checkpoint else condition " << std::endl;
        const crypto::hash genesis = MONERO_UNWRAP(do_get_block_hash(*cur, block_id(0)));
        if (genesis != points.begin()->second)
        {
          MONERO_THROW(
            lws::error::bad_blockchain, "Genesis hash mismatch"
          );
        }
      }
    }
    
    template<typename T>
    expect<T> get_blocks(MDB_cursor& cur, std::size_t max_internal)
    {
      T out{};

      //max_internal = std::min(std::size_t(64), max_internal);
      //out.reserve(12 + max_internal);
      std::cout << " block version : " << blocks_version << std::endl;

      MDB_val key = lmdb::to_val(blocks_version);
      MDB_val value{};
      MONERO_LMDB_CHECK(mdb_cursor_get(&cur, &key, &value, MDB_SET));
      MONERO_LMDB_CHECK(mdb_cursor_get(&cur, &key, &value, MDB_LAST_DUP));

      //const expect<block_id> height = blocks.get_value<MONERO_FIELD(block_info,id)>(value);
      expect<block_info> next = blocks.get_value<block_info>(value);
      if(!next)
        return next.error();
      
      out.push_back(std::move(*next));
      return out;
      //for (unsigned i = 0; i < 10; ++i)
      //{
        // expect<block_info> next = blocks.get_value<block_info>(value);
        // if (!next)
        //   return next.error();

        // out.push_back(std::move(*next));
        // std::cout <<" out.back().id : " <<  out.back().id << std::endl;

        // const int err = mdb_cursor_get(&cur, &key, &value, MDB_PREV_DUP);
        // if (err)
        // {
        //   if (err != MDB_NOTFOUND)
        //     return {lmdb::error(err)};
        //   if (out.back().id != block_id(0))
        //     return {lws::error::bad_blockchain};
        //   return out;
        // }
      //}

      // const auto add_block = [&cur, &out] (std::uint64_t id) -> expect<void>
      // {
      //   expect<crypto::hash> next = do_get_block_hash(cur, block_id(id));
      //   if (!next)
      //     return next.error();
      //   out.push_back(block_info{block_id(id), std::move(*next)});
      //   const std::uint64_t start_height_from_db = lmdb::to_native(out.back().id);
      //   std::cout << "start_height_from_db : " << start_height_from_db << std::endl;
      //   return success();
      // };

      // const std::uint64_t checkpoint = get_checkpoints().get_max_height();
      // const std::uint64_t anchor = lmdb::to_native(out.back().id);

      // std::cout << "anchor : " << anchor << std::endl;

      // for (unsigned i = 1; i <= max_internal; ++i)
      // {
      //   const std::uint64_t offset = 2 << i;
      //   if (anchor < offset || anchor - offset < checkpoint)
      //     break;
      //   MONERO_CHECK(add_block(anchor - offset));
      // }

      // if (block_id(checkpoint) < out.back().id)
      //   MONERO_CHECK(add_block(checkpoint));
      // if (out.back().id != block_id(0))
      //   MONERO_CHECK(add_block(0));
      // return out;
    }
  }// anonymous
  struct storage_internal : lmdb::database
  {
    struct tables_
    {
      MDB_dbi blocks;
      MDB_dbi accounts;
      MDB_dbi accounts_ba;
      MDB_dbi accounts_bh;
      MDB_dbi outputs;
      MDB_dbi spends;
      MDB_dbi images;
      MDB_dbi requests;
    } tables;
    const unsigned create_queue_max;

    explicit storage_internal(lmdb::environment env, unsigned create_queue_max)
      : lmdb::database(std::move(env)), tables{}, create_queue_max(create_queue_max)
    {
      std::cout <<" storage-internal function called : " << __FILE__ << std::endl;

      lmdb::write_txn txn = this->create_write_txn().value();
      assert(txn != nullptr);

      tables.blocks      = blocks.open(*txn).value();
      tables.accounts    = accounts.open(*txn).value();
      tables.accounts_ba = accounts_by_address.open(*txn).value();
      tables.accounts_bh = accounts_by_height.open(*txn).value();
      tables.outputs     = outputs.open(*txn).value();
      tables.spends      = spends.open(*txn).value();
      tables.images      = images.open(*txn).value();
      tables.requests    = requests.open(*txn).value();

    //  check_blockchain(*txn, tables.blocks);

      MONERO_UNWRAP(this->commit(std::move(txn)));
    }
  };

  storage_reader::~storage_reader() noexcept
  {}

  expect<int> storage_reader::get_chain_sync()
  {
    MONERO_PRECOND(txn != nullptr);
    assert(db != nullptr);
    MONERO_CHECK(check_cursor(*txn, db->tables.blocks, curs.blocks_cur));
    auto blocks = get_blocks<std::vector<block_info>>(*curs.blocks_cur, 64);
    if (!blocks)
      return blocks.error();

    // std::list<crypto::hash> out{};
    std::vector<block_info> out{};
    for (block_info const& block : *blocks)
    {
       out.push_back(block);
    }
    const std::uint64_t anchor = lmdb::to_native(out.back().id);
    std::cout << anchor << std::endl;
    return anchor;
  }

  expect<lmdb::key_stream<account_status, account, cursor::close_accounts>>
  storage_reader::get_accounts(cursor::accounts cur) noexcept
  {
    MONERO_PRECOND(txn != nullptr);
    assert(db != nullptr); // both are moved in pairs
    MONERO_CHECK(check_cursor(*txn, db->tables.accounts, cur));
    return accounts.get_key_stream(std::move(cur));
  }

  expect<lmdb::value_stream<account, cursor::close_accounts>>
  storage_reader::get_accounts(account_status status, cursor::accounts cur) noexcept
  {
    MONERO_PRECOND(txn != nullptr);
    assert(db != nullptr); // both are moved in pairs
    MONERO_CHECK(check_cursor(*txn, db->tables.accounts, cur));
    return accounts.get_value_stream(status, std::move(cur));
  }
  
  expect<lmdb::value_stream<output, cursor::close_outputs>>
  storage_reader::get_outputs(account_id id, cursor::outputs cur) noexcept
  {
    MONERO_PRECOND(txn != nullptr);
    assert(db != nullptr);
    MONERO_CHECK(check_cursor(*txn, db->tables.outputs, cur));
    return outputs.get_value_stream(id, std::move(cur));
  }

  lmdb::suspended_txn storage_reader::finish_read() noexcept
  {
    if (txn != nullptr)
    {
      assert(db != nullptr);
      auto suspended = db->reset_txn(std::move(txn));
      if (suspended) // errors not currently logged
        return {std::move(*suspended)};
    }
    return nullptr;
  }

  storage storage::open(const char* path, unsigned create_queue_max)
  {
    return {
      std::make_shared<storage_internal>(
        MONERO_UNWRAP(lmdb::open_environment(path, 20)), create_queue_max
        )
      };
  }

  storage::~storage() noexcept{}

  storage storage::clone() const noexcept
  {
    return storage{db};
  }

  expect<storage_reader> storage::start_read(lmdb::suspended_txn txn) const
  {
    MONERO_PRECOND(db != nullptr);

    expect<lmdb::read_txn> reader = db->create_read_txn(std::move(txn));
    if (!reader)
      return reader.error();

    assert(*reader != nullptr);
    return storage_reader{db, std::move(*reader)};
  }


  // sub functions for `sync_chain(...)`
  namespace 
  {
  //   expect<void>rollback_spends(account_id user, block_id height, MDB_cursor& spends_cur, MDB_cursor& images_cur) noexcept
  //   {
  //     MDB_val key = lmdb::to_val(user);
  //     MDB_val value = lmdb::to_val(height);
  //     const int err = mdb_cursor_get(&spends_cur, &key, &value, MDB_GET_BOTH_RANGE);
  //     if (err == MDB_NOTFOUND)
  //       return success();
  //     if (err)
  //       return {lmdb::error(err)};
  //     for (;;)
  //     {
  //       const expect<output_id> out = spends.get_value<MONERO_FIELD(spend, source)>(value);
  //       if (!out)
  //         return out.error();
  //       const expect<crypto::key_image> image =
  //         spends.get_value<MONERO_FIELD(spend, image)>(value);
  //       if (!image)
  //         return image.error();
  //       key = lmdb::to_val(*out);
  //       value = lmdb::to_val(*image);
  //       MONERO_LMDB_CHECK(mdb_cursor_get(&images_cur, &key, &value, MDB_GET_BOTH));
  //       MONERO_LMDB_CHECK(mdb_cursor_del(&images_cur, 0));
  //       MONERO_LMDB_CHECK(mdb_cursor_del(&spends_cur, 0));
  //       const int err = mdb_cursor_get(&spends_cur, &key, &value, MDB_NEXT_DUP);
  //       if (err == MDB_NOTFOUND)
  //         break;
  //       if (err)
  //         return {lmdb::error(err)};
  //     }
  //     return success();
  //   }
    
  //   expect<void>rollback_outputs(account_id user, block_id height, MDB_cursor& outputs_cur) noexcept
  //   {
  //     MDB_val key = lmdb::to_val(user);
  //     MDB_val value = lmdb::to_val(height);
  //     const int err = mdb_cursor_get(&outputs_cur, &key, &value, MDB_GET_BOTH_RANGE);
  //     if (err == MDB_NOTFOUND)
  //       return success();
  //     if (err)
  //       return {lmdb::error(err)};
  //     for (;;)
  //     {
  //       MONERO_LMDB_CHECK(mdb_cursor_del(&outputs_cur, 0));
  //       const int err = mdb_cursor_get(&outputs_cur, &key, &value, MDB_NEXT_DUP);
  //       if (err == MDB_NOTFOUND)
  //         break;
  //       if (err)
  //         return {lmdb::error(err)};
  //     }
  //     return success();
  //   }
  
  //   expect<void> rollback_accounts(storage_internal::tables_ const& tables, MDB_txn& txn, block_id height)
  //   {
  //     cursor::accounts_by_height accounts_bh_cur;
  //     MONERO_CHECK(check_cursor(txn, tables.accounts_bh, accounts_bh_cur));
  //     MDB_val key = lmdb::to_val(height);
  //     MDB_val value{};
  //     const int err = mdb_cursor_get(accounts_bh_cur.get(), &key, &value, MDB_SET_RANGE);
  //     if (err == MDB_NOTFOUND)
  //       return success();
  //     if (err)
  //       return {lmdb::error(err)};
  //     std::vector<account_lookup> new_by_heights{};
  //     cursor::accounts accounts_cur;
  //     cursor::outputs outputs_cur;
  //     cursor::spends spends_cur;
  //     cursor::images images_cur;
  //     MONERO_CHECK(check_cursor(txn, tables.accounts, accounts_cur));
  //     MONERO_CHECK(check_cursor(txn, tables.outputs, outputs_cur));
  //     MONERO_CHECK(check_cursor(txn, tables.spends, spends_cur));
  //     MONERO_CHECK(check_cursor(txn, tables.images, images_cur));
  //     const std::uint64_t new_height = std::uint64_t(std::max(height, block_id(1))) - 1;
  //     // rollback accounts
  //     for (;;)
  //     {
  //       const expect<account_lookup> lookup =
  //         accounts_by_height.get_value<account_lookup>(value);
  //       if (!lookup)
  //         return lookup.error();
  //       key = lmdb::to_val(lookup->status);
  //       value = lmdb::to_val(lookup->id);
  //       MONERO_LMDB_CHECK(mdb_cursor_get(accounts_cur.get(), &key, &value, MDB_GET_BOTH));
  //       expect<account> user = accounts.get_value<account>(value);
  //       if (!user)
  //         return user.error();
  //       user->scan_height = block_id(new_height);
  //       user->start_height = std::min(user->scan_height, user->start_height);
  //       value = lmdb::to_val(*user);
  //       MONERO_LMDB_CHECK(mdb_cursor_put(accounts_cur.get(), &key, &value, MDB_CURRENT));
  //       new_by_heights.push_back(account_lookup{user->id, lookup->status});
  //       MONERO_CHECK(rollback_outputs(user->id, height, *outputs_cur));
  //       MONERO_CHECK(rollback_spends(user->id, height, *spends_cur, *images_cur));
  //       MONERO_LMDB_CHECK(mdb_cursor_del(accounts_bh_cur.get(), 0));
  //       int err = mdb_cursor_get(accounts_bh_cur.get(), &key, &value, MDB_NEXT_DUP);
  //       if (err == MDB_NOTFOUND)
  //       {
  //         err = mdb_cursor_get(accounts_bh_cur.get(), &key, &value, MDB_NEXT_NODUP);
  //         if (err == MDB_NOTFOUND)
  //           break;
  //       }
  //       if (err)
  //         return {lmdb::error(err)};
  //     }
  //     return bulk_insert(*accounts_bh_cur, new_height, epee::to_span(new_by_heights));
  //   }
  
  //   expect<void> rollback_chain(storage_internal::tables_ const& tables, MDB_txn& txn, MDB_cursor& cur, block_id height)
  //   {
  //     MDB_val key;
  //     MDB_val value;
  //     // rollback chain
  //     int err = 0;
  //     do
  //     {
  //       MONERO_LMDB_CHECK(mdb_cursor_del(&cur, 0));
  //       err = mdb_cursor_get(&cur, &key, &value, MDB_NEXT_DUP);
  //     } while (err == 0);
  //     if (err != MDB_NOTFOUND)
  //       return {lmdb::error(err)};
  //     return rollback_accounts(tables, txn,  height);
  //   }

    template<typename T>
    expect<void> append_block_hashes(MDB_cursor& cur, db::block_id first, T const& chain)
    {
      std::uint64_t height = std::uint64_t(first);
      boost::container::static_vector<block_info, 25> hashes{};
      static_assert(sizeof(hashes) <= 1024, "using more stack space than expected");
      for (auto current = chain.begin() ;; ++current)
      {
        if (current == chain.end() || hashes.size() == hashes.capacity())
        {
          // std::cout << "hashes.size() in append : " << hashes.size() << std::endl;
          MONERO_CHECK(bulk_insert(cur, blocks_version, epee::to_span(hashes)));
          if (current == chain.end())
            return success();
          hashes.clear();
        }

        hashes.push_back(block_info{db::block_id(height), *current});
        ++height;
      }
      std::cout << " inside the append function" << std::endl;
    }
  } //anonymus

  expect<void> storage::sync_chain(block_id height, epee::span<const crypto::hash> hashes)
  {
    MONERO_PRECOND(!hashes.empty());
    MONERO_PRECOND(db != nullptr);

    return db->try_write([this, height, hashes] (MDB_txn& txn) -> expect<void>
    {
      cursor::blocks blocks_cur;
      MONERO_CHECK(check_cursor(txn, this->db->tables.blocks, blocks_cur));

      expect<crypto::hash> hash = do_get_block_hash(*blocks_cur, height);

      MDB_val key{};
      MDB_val value{};

      std::uint64_t current = std::uint64_t(height) + 1;
      auto first = hashes.begin();
      auto chain = boost::make_iterator_range(++first, hashes.end());
      std::cout << "hashes.size() : " << hashes.size() << std::endl;
      std::cout << "chain.size() : " << chain.size() << std::endl;
      static int a = 0;
      // for ( ; !chain.empty(); chain.advance_begin(1), ++current)
      // {
      //   a++;
      //   // const int err = mdb_cursor_get(blocks_cur.get(), &key, &value, MDB_NEXT_DUP);
      //   // if (err == MDB_NOTFOUND)
      //   //   break;
      //   // if (err)
      //   //   return {lmdb::error(err)};

      //   hash = blocks.get_value<MONERO_FIELD(block_info, hash)>(value);
      //   // if (!hash)
      //   //   return hash.error();

      //   // if (*hash != chain.front())
      //   // {
      //   //   MONERO_CHECK(rollback_chain(this->db->tables, txn, *blocks_cur, db::block_id(current)));
      //   //   break;
      //   // }
      // }
      std::cout <<" no of loops : " << a << std::endl;
      std::cout << "chain.size() : " << chain.size() << std::endl;
      std::cout <<"current : " << current << std::endl;
      return append_block_hashes(*blocks_cur, db::block_id(current), chain);
    });
  }
} //db
} //lws