#include "client.h"

#include <boost/thread/mutex.hpp>
#include <boost/utility/string_ref.hpp>
#include <cassert>
#include <system_error>


namespace lws
{
namespace rpc
{

  expect<client> client::make(std::shared_ptr<detail::context> ctx) noexcept
  {
    MONERO_PRECOND(ctx != nullptr);

    int option = daemon_zmq_linger;
    client out{std::move(ctx)};

    out.daemon.reset(zmq_socket(out.ctx->comm.get(), ZMQ_REQ));
    if (out.daemon.get() == nullptr)
      return net::zmq::get_error_code();
    MONERO_ZMQ_CHECK(zmq_connect(out.daemon.get(), out.ctx->daemon_addr.c_str()));
    MONERO_ZMQ_CHECK(zmq_setsockopt(out.daemon.get(), ZMQ_LINGER, &option, sizeof(option)));

    if (!out.ctx->sub_addr.empty())
    {
      out.daemon_sub.reset(zmq_socket(out.ctx->comm.get(), ZMQ_SUB));
      if (out.daemon_sub.get() == nullptr)
        return net::zmq::get_error_code();

      option = 1; // keep only last pub message from daemon
      MONERO_ZMQ_CHECK(zmq_connect(out.daemon_sub.get(), out.ctx->sub_addr.c_str()));
      MONERO_ZMQ_CHECK(zmq_setsockopt(out.daemon_sub.get(), ZMQ_CONFLATE, &option, sizeof(option)));
      MONERO_CHECK(do_subscribe(out.daemon_sub.get(), minimal_chain_topic));
    }

    out.signal_sub.reset(zmq_socket(out.ctx->comm.get(), ZMQ_SUB));
    if (out.signal_sub.get() == nullptr)
      return net::zmq::get_error_code();
    MONERO_ZMQ_CHECK(zmq_connect(out.signal_sub.get(), signal_endpoint));

    MONERO_CHECK(do_subscribe(out.signal_sub.get(), abort_process_signal));
    return {std::move(out)};
  }
}//rpc
}//lws