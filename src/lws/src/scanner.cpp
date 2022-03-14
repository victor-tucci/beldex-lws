#include "scanner.h"

#include <algorithm>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/range/combine.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/thread.hpp>
#include <cassert>
#include <chrono>
#include <cstring>
#include <type_traits>
#include <utility>

#include "common/error.h"   
#include "common/hex.h"                                 // beldex/src
#include "crypto/crypto.h"                              // beldex/src
#include "crypto/wallet/crypto.h"                       // beldex/src
#include "cryptonote_basic/cryptonote_format_utils.h"   // beldex/src
#include "cryptonote_basic/cryptonote_basic.h"          // beldex/src
#include "ringct/rctOps.h"                              // beldex/src
#include "cryptonote_core/cryptonote_tx_utils.h"        // beldex/src
#include "wallet/wallet2.h"                             // beldex/src
#include "error.h"
#include "scanner.h"
#include "db/account.h"
#include <nlohmann/json.hpp>
// #include <oxenc/hex.h>
#include "oxenmq/oxenmq.h"
#include "oxenmq/connections.h"
#include "epee/span.h"
#include "epee/misc_log_ex.h"
#include "lmdb/util.h"
using namespace oxenmq;
using json = nlohmann::json;
namespace lws
{
    std::atomic<bool> scanner::running{true};


   namespace
   {
    constexpr const std::chrono::seconds account_poll_interval{10};
    constexpr const std::chrono::minutes block_rpc_timeout{2};
    constexpr const std::chrono::seconds send_timeout{30};
    constexpr const std::chrono::seconds sync_rpc_timeout{30};

    struct thread_sync
    {
      boost::mutex sync;
      boost::condition_variable user_poll;
      std::atomic<bool> update;
    };
    struct thread_data
    {
      explicit thread_data(db::storage disk, std::vector<lws::account> users)
        : disk(std::move(disk)), users(std::move(users))
      {}

      // rpc::client client;
      db::storage disk;
      std::vector<lws::account> users;
    };
    
    // until we have a signal-handler safe notification system
    void checked_wait(const std::chrono::nanoseconds wait)
    {
      static constexpr const std::chrono::milliseconds interval{500};

      const auto start = std::chrono::steady_clock::now();
      while (scanner::is_running())
      {
        const auto current = std::chrono::steady_clock::now() - start;
        if (wait <= current)
          break;
        const auto sleep_time = std::min(wait - current, std::chrono::nanoseconds{interval});
        std::this_thread::sleep_for(std::chrono::nanoseconds{sleep_time.count()});
      }
    }

    struct by_height
    {
      bool operator()(account const& left, account const& right) const noexcept
      {
        return left.scan_height() < right.scan_height();
      }
    };

    void scan_transaction(
      epee::span<lws::account> users,
      const db::block_id height,
      const std::uint64_t timestamp,
      crypto::hash const& tx_hash,
      cryptonote::transaction const& tx,
      std::vector<std::uint64_t> const& out_ids)
    {
      std::cout << " timestamp : " << timestamp << std::endl;
      std::cout << " tx_hash : " << tx_hash << std::endl;
      // std::cout << "tx : " << tx << std::endl;
      for(auto it :out_ids)
      {
        std::cout << " out_ids : " << it << std::endl;
      }
      std::cout <<"-------------------------------------------------" << std::endl;
      if (cryptonote::txversion::v2_ringct < tx.version)
        throw std::runtime_error{"Unsupported tx version"};

      cryptonote::tx_extra_pub_key key;
      boost::optional<crypto::hash> prefix_hash;
      boost::optional<cryptonote::tx_extra_nonce> extra_nonce;
      std::pair<std::uint8_t, db::output::payment_id_> payment_id;

      {
        std::vector<cryptonote::tx_extra_field> extra;
        cryptonote::parse_tx_extra(tx.extra, extra);
        // allow partial parsing of tx extra (similar to wallet2.cpp)

        if (!cryptonote::find_tx_extra_field_by_type(extra, key))
          return;

        extra_nonce.emplace();
        if (cryptonote::find_tx_extra_field_by_type(extra, *extra_nonce))
        {
          if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce->nonce, payment_id.second.long_))
            payment_id.first = sizeof(crypto::hash);
        }
        else
          extra_nonce = boost::none;
      } // destruct `extra` vector

      for (account& user : users)
      {
        if (height <= user.scan_height())
          continue; // to next user

        crypto::key_derivation derived;
        if (!crypto::wallet::generate_key_derivation(key.pub_key, user.view_key(), derived))
          continue; // to next user

        db::extra ext{};
        std::uint32_t mixin = 0;
        for (auto const& in : tx.vin)
        {
          cryptonote::txin_to_key const* const in_data =
            std::get_if<cryptonote::txin_to_key>(std::addressof(in));
          if (in_data)
          {
            mixin = boost::numeric_cast<std::uint32_t>(
              std::max(std::size_t(1), in_data->key_offsets.size()) - 1
            );

            std::uint64_t goffset = 0;
            for (std::uint64_t offset : in_data->key_offsets)
            {
              goffset += offset;
              if (user.has_spendable(db::output_id{in_data->amount, goffset}))
              {
                user.add_spend(
                  db::spend{
                    db::transaction_link{height, tx_hash},
                    in_data->k_image,
                    db::output_id{in_data->amount, goffset},
                    timestamp,
                    tx.unlock_time,
                    mixin,
                    {0, 0, 0}, // reserved
                    payment_id.first,
                    payment_id.second.long_
                  }
                );
              }
            }
          }
          else if (std::get_if<cryptonote::txin_gen>(std::addressof(in)))
            ext = db::extra(ext | db::coinbase_output);
        }

        std::size_t index = -1;
        for (auto const& out : tx.vout)
        {
          ++index;

          cryptonote::txout_to_key const* const out_data =
            std::get_if<cryptonote::txout_to_key>(std::addressof(out.target));
          if (!out_data)
            continue; // to next output

          crypto::public_key derived_pub;
          const bool received =
            crypto::wallet::derive_subaddress_public_key(out_data->key, derived, index, derived_pub) &&
            derived_pub == user.spend_public();

          if (!received)
            continue; // to next output

          if (!prefix_hash)
          {
            prefix_hash.emplace();
            cryptonote::get_transaction_prefix_hash(tx, *prefix_hash);
          }

          std::uint64_t amount = out.amount;
          rct::key mask = rct::identity();
          if (!amount && !(ext & db::coinbase_output) && cryptonote::txversion::v1 < tx.version)
          {
            const bool bulletproof2 = (rct::RCTType::Bulletproof2 <= tx.rct_signatures.type);
            const auto decrypted = lws::decode_amount(
              tx.rct_signatures.outPk.at(index).mask, tx.rct_signatures.ecdhInfo.at(index), derived, index, bulletproof2
            );
            if (!decrypted)
            {
              MWARNING(user.address() << " failed to decrypt amount for tx " << tx_hash << ", skipping output");
              continue; // to next output
            }
            amount = decrypted->first;
            mask = decrypted->second;
            ext = db::extra(ext | db::ringct_output);
          }

          if (extra_nonce)
          {
            if (!payment_id.first && cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce->nonce, payment_id.second.short_))
            {
              payment_id.first = sizeof(crypto::hash8);
              lws::decrypt_payment_id(payment_id.second.short_, derived);
            }
          }

          const bool added = user.add_out(
            db::output{
              db::transaction_link{height, tx_hash},
              db::output::spend_meta_{
                db::output_id{out.amount, out_ids.at(index)},
                amount,
                mixin,
                boost::numeric_cast<std::uint32_t>(index),
                key.pub_key
              },
              timestamp,
              tx.unlock_time,
              *prefix_hash,
              out_data->key,
              mask,
              {0, 0, 0, 0, 0, 0, 0}, // reserved bytes
              db::pack(ext, payment_id.first),
              payment_id.second
            }
          );

          if (!added)
            MWARNING("Output not added, duplicate public key encountered");
        } // for all tx outs
      } // for all users
    }

    void scan_loop(thread_sync& self, std::shared_ptr<thread_data> data) noexcept
    {
      try
      {
        // boost::thread doesn't support move-only types + attributes
        // rpc::client client{std::move(data->client)};
        db::storage disk{std::move(data->disk)};
        std::vector<lws::account> users{std::move(data->users)};

        assert(!users.empty());
        assert(std::is_sorted(users.begin(), users.end(), by_height{}));

        data.reset();

        struct stop_
        {
          thread_sync& self;
          ~stop_() noexcept
          {
            self.update = true;
            self.user_poll.notify_one();
          }
        } stop{self};

        // RPC server assumes that `start_height == 0` means use
        // block ids. This technically skips genesis block.
        // cryptonote::rpc::GetBlocksFast::Request req{};
        auto start_height = std::uint64_t(users.begin()->scan_height());
        std::cout << "start_height : " << start_height << std::endl;
        std::cout << "thread_id : " << std::this_thread::get_id()<<std::endl;
      //   req.start_height = std::max(std::uint64_t(1), req.start_height);
      //   req.prune = true;

      //   epee::byte_slice block_request = rpc::client::make_message("get_blocks_fast", req);
      //   if (!send(client, block_request.clone()))
      //     return;

        std::vector<crypto::hash> blockchain{};

        while (!self.update && scanner::is_running())
        {
          blockchain.clear();

      //     auto resp = client.get_message(block_rpc_timeout);
      //     if (!resp)
      //     {
      //       const bool timeout = resp.matches(std::errc::timed_out);
      //       if (timeout)
      //         MWARNING("Block retrieval timeout, resetting scanner");
      //       if (timeout || resp.matches(std::errc::interrupted))
      //         return;
      //       MONERO_THROW(resp.error(), "Failed to retrieve blocks from daemon");
      //     }

      //     auto fetched = MONERO_UNWRAP(wire::json::from_bytes<rpc::json<rpc::get_blocks_fast>::response>(std::move(*resp)));
      //     if (fetched.result.blocks.empty())
      //       throw std::runtime_error{"Daemon unexpectedly returned zero blocks"};

      //     if (fetched.result.start_height != req.start_height)
      //     {
      //       MWARNING("Daemon sent wrong blocks, resetting state");
      //       return;
      //     }

      //     // prep for next blocks retrieval
      //     req.start_height = fetched.result.start_height + fetched.result.blocks.size() - 1;
      //     block_request = rpc::client::make_message("get_blocks_fast", req);

      //     if (fetched.result.blocks.size() <= 1)
      //     {
      //       // synced to top of chain, wait for next blocks
      //       for (;;)
      //       {
      //         const expect<rpc::minimal_chain_pub> new_block = client.wait_for_block();
      //         if (new_block.matches(std::errc::interrupted))
      //           return;
      //         if (!new_block || is_new_block(disk, users.front(), *new_block))
      //           break;
      //       }

      //       // request next chunk of blocks
      //       if (!send(client, block_request.clone()))
      //         return;
      //       continue; // to next get_blocks_fast read
      //     }

      //     // request next chunk of blocks
      //     if (!send(client, block_request.clone()))
      //       return;

      //     if (fetched.result.blocks.size() != fetched.result.output_indices.size())
      //       throw std::runtime_error{"Bad daemon response - need same number of blocks and indices"};

      //     blockchain.push_back(cryptonote::get_block_hash(fetched.result.blocks.front().block));

      //     auto blocks = epee::to_span(fetched.result.blocks);
      //     auto indices = epee::to_span(fetched.result.output_indices);

      //     if (fetched.result.start_height != 1)
      //     {
      //       // skip overlap block
      //       blocks.remove_prefix(1);
      //       indices.remove_prefix(1);
      //     }
      //     else
      //       fetched.result.start_height = 0;

      //     for (auto block_data : boost::combine(blocks, indices))
      //     {
      //       ++(fetched.result.start_height);

      //       cryptonote::block const& block = boost::get<0>(block_data).block;
      //       auto const& txes = boost::get<0>(block_data).transactions;

      //       if (block.tx_hashes.size() != txes.size())
      //         throw std::runtime_error{"Bad daemon response - need same number of txes and tx hashes"};

      //       auto indices = epee::to_span(boost::get<1>(block_data));
      //       if (indices.empty())
      //         throw std::runtime_error{"Bad daemon response - missing /coinbase tx indices"};

      //       crypto::hash miner_tx_hash;
      //       if (!cryptonote::get_transaction_hash(block.miner_tx, miner_tx_hash))
      //         throw std::runtime_error{"Failed to calculate miner tx hash"};

      //       scan_transaction(
      //         epee::to_mut_span(users),
      //         db::block_id(fetched.result.start_height),
      //         block.timestamp,
      //         miner_tx_hash,
      //         block.miner_tx,
      //         *(indices.begin())
      //       );

      //       indices.remove_prefix(1);
      //       if (txes.size() != indices.size())
      //         throw std::runtime_error{"Bad daemon respnse - need same number of txes and indices"};

      //       for (auto tx_data : boost::combine(block.tx_hashes, txes, indices))
      //       {
      //         scan_transaction(
      //           epee::to_mut_span(users),
      //           db::block_id(fetched.result.start_height),
      //           block.timestamp,
      //           boost::get<0>(tx_data),
      //           boost::get<1>(tx_data),
      //           boost::get<2>(tx_data)
      //         );
      //       }

      //       blockchain.push_back(cryptonote::get_block_hash(block));
      //     } // for each block

      //     expect<std::size_t> updated = disk.update(
      //       users.front().scan_height(), epee::to_span(blockchain), epee::to_span(users)
      //     );
      //     if (!updated)
      //     {
      //       if (updated == lws::error::blockchain_reorg)
      //       {
      //         epee::byte_stream dest{};
      //         {
      //           rapidjson::Writer<epee::byte_stream> out{dest};
      //           cryptonote::json::toJsonValue(out, blocks[998]);
      //         }
      //         MINFO("Blockchain reorg detected, resetting state");
      //         return;
      //       }
      //       MONERO_THROW(updated.error(), "Failed to update accounts on disk");
      //     }

      //     MINFO("Processed " << blocks.size() << " block(s) against " << users.size() << " account(s)");
      //     if (*updated != users.size())
      //     {
      //       MWARNING("Only updated " << *updated << " account(s) out of " << users.size() << ", resetting");
      //       return;
      //     }

      //     for (account& user : users)
      //       user.updated(db::block_id(fetched.result.start_height));
        }
      }
      catch (std::exception const& e)
      {
      //   scanner::stop();
      //   MERROR(e.what());
      }
      catch (...)
      {
      //   scanner::stop();
      //   MERROR("Unknown exception");
      }
    }

    /*!
      Launches `thread_count` threads to run `scan_loop`, and then polls for
      active account changes in background
    */
    void check_loop(db::storage disk, std::size_t thread_count, std::vector<lws::account> users, std::vector<db::account_id> active)
    {
      assert(0 < thread_count);
      assert(0 < users.size());

      thread_sync self{};
      std::vector<boost::thread> threads{};

      struct join_
      {
        thread_sync& self;
        std::vector<boost::thread>& threads;
        // rpc::context& ctx;

        ~join_() noexcept
        {
          self.update = true;
          // ctx.raise_abort_scan();
          for (auto& thread : threads)
            thread.join();
        }
      } join{self, threads/*, ctx*/};

      /*
        The algorithm here is extremely basic. Users are divided evenly amongst
        the configurable thread count, and grouped by scan height. If an old
        account appears, some accounts (grouped on that thread) will be delayed
        in processing waiting for that account to catch up. Its not the greatest,
        but this "will have to do" for the first cut.
        Its not expected that many people will be running
        "enterprise level" of nodes where accounts are constantly added.

        Another "issue" is that each thread works independently instead of more
        cooperatively for scanning. This requires a bit more synchronization, so
        was left for later. Its likely worth doing to reduce the number of
        transfers from the daemon, and the bottleneck on the writes into LMDB.

        If the active user list changes, all threads are stopped/joined, and
        everything is re-started.
      */

      boost::thread::attributes attrs;
      attrs.set_stack_size(THREAD_STACK_SIZE);

      threads.reserve(thread_count);
      std::sort(users.begin(), users.end(), by_height{});

      MINFO("Starting scan loops on " << std::min(thread_count, users.size()) << " thread(s) with " << users.size() << " account(s)");

      while (!users.empty() && --thread_count)
      {
        const std::size_t per_thread = std::max(std::size_t(1), users.size() / (thread_count + 1));
        const std::size_t count = std::min(per_thread, users.size());
        std::vector<lws::account> thread_users{
          std::make_move_iterator(users.end() - count), std::make_move_iterator(users.end())
        };
        users.erase(users.end() - count, users.end());

      //   rpc::client client = MONERO_UNWRAP(ctx.connect());
      //   client.watch_scan_signals();

        auto data = std::make_shared<thread_data>(disk.clone(), std::move(thread_users)
        );
        threads.emplace_back(attrs, std::bind(&scan_loop, std::ref(self), std::move(data)));
      }

      if (!users.empty())
      {
        // rpc::client client = MONERO_UNWRAP(ctx.connect());
        // client.watch_scan_signals();

        auto data = std::make_shared<thread_data>(disk.clone(), std::move(users));
        threads.emplace_back(attrs, std::bind(&scan_loop, std::ref(self), std::move(data)));
      }

      auto last_check = std::chrono::steady_clock::now();

      lmdb::suspended_txn read_txn{};
      db::cursor::accounts accounts_cur{};
      boost::unique_lock<boost::mutex> lock{self.sync};

      while (scanner::is_running())
      {
      //   update_rates(ctx);

        for (;;)
        {
          //! \TODO use signalfd + ZMQ? Windows is the difficult case...
          // self.user_poll.wait_for(lock, boost::chrono::seconds{1});
          std::this_thread::sleep_for(1s);
          if (self.update || !scanner::is_running())
            return;
          auto this_check = std::chrono::steady_clock::now();
          if (account_poll_interval <= (this_check - last_check))
          {
            last_check = this_check;
            break;
          }
        }

        auto reader = disk.start_read(std::move(read_txn));
        if (!reader)
        {
          if (reader.matches(std::errc::no_lock_available))
          {
            MWARNING("Failed to open DB read handle, retrying later");
            continue;
          }
          MONERO_THROW(reader.error(), "Failed to open DB read handle");
        }

        auto current_users = MONERO_UNWRAP(
          reader->get_accounts(db::account_status::active, std::move(accounts_cur))
        );
        if (current_users.count() != active.size())
        {
          MINFO("Change in active user accounts detected, stopping scan threads...");
          return;
        }

        for (auto user = current_users.make_iterator(); !user.is_end(); ++user)
        {
          const db::account_id user_id = user.get_value<MONERO_FIELD(db::account, id)>();
          if (!std::binary_search(active.begin(), active.end(), user_id))
          {
            MINFO("Change in active user accounts detected, stopping scan threads...");
            return;
          }
        }

        read_txn = reader->finish_read();
        accounts_cur = current_users.give_cursor();
      } // while scanning
    }

   }//anonymous
    void scanner::sync(db::storage disk)
    {
      MINFO("Starting blockchain sync with daemon");
      using LMQ_ptr = std::shared_ptr<oxenmq::OxenMQ>;
    
      LMQ_ptr m_LMQ = std::make_shared<oxenmq::OxenMQ>(); 
      m_LMQ->start();

      auto c = m_LMQ->connect_remote("tcp://127.0.0.1:4567",
      [](ConnectionID conn) { std::cout << "Connected \n";},
      [](ConnectionID conn, std::string_view f) { std::cout << "connect failed: \n";} 
      );
      // std::this_thread::sleep_for(5s);
      json details;
      int a =0;
      std::vector<crypto::hash> blk_ids;

     {
      auto reader = disk.start_read();
      if (!reader)
      {
        // return reader.error(); 
      }

      auto chain = reader->get_chain_sync();
      std::cout << *chain << std::endl;
      if (!chain)
      {
        // return chain.error();
      }

      // req.known_hashes = std::move(*chain);
      a = *chain;
      
     }
     std::cout << " value of a : " << a << std::endl;
      for(;;)
      {
         break;
          m_LMQ->request(c,"rpc.get_hashes",[&details,a,&blk_ids](bool s , auto data){
          if(s==1 && data[0]=="200"){
            //  std::cout << " get_hashes is : " << data[1] << "\n";
            std::cout << " a : " << a << std::endl;
             json jf = json::parse(data[1]);
             details = jf;
             for (auto block_data : details["m_block_ids"])
             {
               std::string id = block_data;
               tools::hex_to_type(id, blk_ids.emplace_back());
             }
           }
          else
            std::cout << "timeout fetching get_hashes !";
          },"{\"start_height\": \"" + std::to_string(a) + "\"}");

           std::this_thread::sleep_for(3s);
           int block_ids_size = details["m_block_ids"].size();
           int start_height = details["start_height"];
           int current_height = details["current_height"];

        //   MONERO_CHECK(disk.sync_chain(db::block_id(details["start_height"]), details["m_block_ids"]));

         disk.sync_chain(db::block_id(details["start_height"]), epee::to_span(blk_ids));
           a = block_ids_size + start_height;

           if (a>=current_height)
           {
                 std::cout <<"the current_height details : " << details["current_height"] << std::endl;
                 std::cout <<" the size of the blockchain data    : " << a << std::endl;
                 break;
            }
            std::cout << a << std::endl;
      }
           std::this_thread::sleep_for(5s);
           std::cout <<"the current_height details : " <<details["current_height"] << std::endl;
           std::cout << " connection end " << std::endl;
    }

   void scanner::run(db::storage disk, std::size_t thread_count)
   {
    thread_count = std::max(std::size_t(1), thread_count);

    // rpc::client client{};
    for (;;)
    {
      const auto last = std::chrono::steady_clock::now();
      // update_rates(ctx);

      std::vector<db::account_id> active;
      std::vector<lws::account> users;

      {
        MINFO("Retrieving current active account list");

        auto reader = MONERO_UNWRAP(disk.start_read());
        auto accounts = MONERO_UNWRAP(
          reader.get_accounts(db::account_status::active)
        );

        for (db::account user : accounts.make_range())
        {
          std::vector<db::output_id> receives{};
          std::vector<crypto::public_key> pubs{};
          auto receive_list = MONERO_UNWRAP(reader.get_outputs(user.id));

          const std::size_t elems = receive_list.count();
          receives.reserve(elems);
          pubs.reserve(elems);

          for (auto output = receive_list.make_iterator(); !output.is_end(); ++output)
          {
            receives.emplace_back(output.get_value<MONERO_FIELD(db::output, spend_meta.id)>());
            pubs.emplace_back(output.get_value<MONERO_FIELD(db::output, pub)>());
          }

          users.emplace_back(user, std::move(receives), std::move(pubs));
          active.insert(
            std::lower_bound(active.begin(), active.end(), user.id), user.id
          );
        }

        reader.finish_read();
      } // cleanup DB reader
      
      std::cout << " thread count : " << thread_count << std::endl;

      if (users.empty())
      {
        MINFO("No active accounts");
        checked_wait(account_poll_interval - (std::chrono::steady_clock::now() - last));
      }
      else
        check_loop(disk.clone(),thread_count, std::move(users), std::move(active));

      if (!scanner::is_running())
        return;

      // if (!client)
      //   client = MONERO_UNWRAP(ctx.connect());

      // expect<rpc::client> synced = sync(disk.clone(), std::move(client));
      sync(disk.clone());
      // if (!synced)
      // {
      //   if (!synced.matches(std::errc::timed_out))
      //     MONERO_THROW(synced.error(), "Unable to sync blockchain");

      //   MWARNING("Failed to connect to daemon at " << ctx.daemon_address());
      // }
      // else
      //   client = std::move(*synced);
    } // while scanning
   }

}//lws