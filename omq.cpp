
#include <iostream>
#include <string_view>
#include <map>
#include <set>
#include "oxenmq/oxenmq.h"
#include "oxenmq/connections.h"
#include <chrono>
using namespace oxenmq;
int main()
{
// OxenMQ client{get_logger("C» "), LogLevel::trace};
    std::cout << "main called 's " << std::endl;
    using LMQ_ptr = std::shared_ptr<oxenmq::OxenMQ>;
    LMQ_ptr m_LMQ = std::make_unique<oxenmq::OxenMQ>();
     m_LMQ->start();
 std::cout << "before connect remote ";
    std::cout << "before connect remote ";
      auto c = m_LMQ->connect_remote("ipc:///home/blockhash/.beldex/beldexd.sock",
      [](ConnectionID conn) { std::cout << "Connected \n";},
      [](ConnectionID conn, std::string_view f) { std::cout << "connect failed: \n";}
      );
    //   Request req{}
    
      m_LMQ->request(c, "rpc.get_blocks_fast", [](bool s, std::vector<std::string> d) {
            if (s && d.size() == 2)
            std::cout << "Current height: " << d[1] << "\n";
            else
            std::cout << "Timeout fetching height!";
        }, "{\"start_height\":10}}" );
        std::this_thread::sleep_for(20s);
}