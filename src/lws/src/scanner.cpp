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
#include "common/hex.h"                          // monero/src
#include "crypto/crypto.h"                            // monero/src
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
           std::this_thread::sleep_for(10s);
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
           std::this_thread::sleep_for(3s);

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

      if (users.empty())
      {
        MINFO("No active accounts");
        checked_wait(account_poll_interval - (std::chrono::steady_clock::now() - last));
      }
      // else
        // check_loop(disk.clone(), ctx, thread_count, std::move(users), std::move(active));

      // if (!scanner::is_running())
      //   return;

      // if (!client)
      //   client = MONERO_UNWRAP(ctx.connect());

      // expect<rpc::client> synced = sync(disk.clone(), std::move(client));
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