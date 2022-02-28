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
#include <nlohmann/json.hpp>
// #include <oxenc/hex.h>
#include "oxenmq/oxenmq.h"
#include "oxenmq/connections.h"
#include "epee/span.h"
using namespace oxenmq;
using json = nlohmann::json;
namespace lws
{
    std::atomic<bool> scanner::running{true};


    void scanner::sync(db::storage disk)
    {
      using LMQ_ptr = std::shared_ptr<oxenmq::OxenMQ>;
    
      LMQ_ptr m_LMQ = std::make_shared<oxenmq::OxenMQ>(); 
      m_LMQ->start();

      auto c = m_LMQ->connect_remote("tcp://192.168.1.49:4567",
      [](ConnectionID conn) { std::cout << "Connected \n";},
      [](ConnectionID conn, std::string_view f) { std::cout << "connect failed: \n";} 
      );
      // std::this_thread::sleep_for(5s);
      json details;
      int a =0;
      std::vector<crypto::hash> blk_ids;
      for(;;)
      {
          m_LMQ->request(c,"rpc.get_hashes",[&details,a,&blk_ids](bool s , auto data){
          if(s==1 && data[0]=="200"){
            //  std::cout << " get_hashes is : " << data[1] << "\n";
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

        //    MONERO_CHECK(disk.sync_chain(db::block_id(details["start_height"]), details["m_block_ids"]));

         disk.sync_chain(db::block_id(details["start_height"]), epee::to_span(blk_ids));
            break;
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

}//lws