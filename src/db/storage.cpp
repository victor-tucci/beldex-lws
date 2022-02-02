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

#include "config.h"
#include "error.h"
#include "data.h"
#include "checkpoints/checkpoints.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/expect.h"   //beldex/src

#include "lmdb/database.h"   //beldex/src
#include "lmdb/error.h"
#include "lmdb/key_stream.h"
#include "lmdb/table.h"
#include "lmdb/util.h"
#include "lmdb/value_stream.h"

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

    constexpr const unsigned blocks_version = 0;
    constexpr const unsigned by_address_version = 0;

    // constexpr const lmdb::basic_table<unsigned, block_info> blocks{
    //   "blocks_by_id", (MDB_CREATE | MDB_DUPSORT), MONERO_SORT_BY(block_info, id)
    // };
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

      std::map<std::uint64_t, crypto::hash> const& points =
        get_checkpoints().get_points();

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

      check_blockchain(*txn, tables.blocks);

      MONERO_UNWRAP(this->commit(std::move(txn)));
    }
  };
     
    storage storage::open(const char* path, unsigned create_queue_max)
    {
     return {
      std::make_shared<storage_internal>(
        MONERO_UNWRAP(lmdb::open_environment(path, 20)), create_queue_max
        )
      };
    }

  
} //db
} //lws