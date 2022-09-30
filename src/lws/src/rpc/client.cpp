#include "client.h"

#include <boost/thread/mutex.hpp>
#include <boost/utility/string_ref.hpp>
#include <cassert>
#include <system_error>


namespace lws
{
namespace rpc
{

  Connection connect_daemon()
  {
    Connection connection;
    connection.m_LMQ = std::make_shared<oxenmq::OxenMQ>(); 
    connection.m_LMQ->start();
    connection.c = connection.m_LMQ->connect_remote("ipc:///home/dhivakar/.beldex/beldexd.sock",
    [&connection](ConnectionID conn) { connection.daemon_connected = true;},
    [](ConnectionID conn, std::string_view f) { MERROR("connect failed:");} 
    );
    std::this_thread::sleep_for(5s);
    if(connection.daemon_connected)
    {
      MINFO("LWS-daemon connected with beldexd");
    }
    return connection;
  }
}//rpc
}//lws