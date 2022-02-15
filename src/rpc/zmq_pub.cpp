//#include "zmq_pub.h"

#include <algorithm>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/thread/locks.hpp>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <stdexcept>
#include <string>
#include <utility>

#include "common/expect.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
// #include "cryptonote_basic/events.h"
#include "misc_log_ex.h"
#include "serialization/json_object.h"
#include "ringct/rctTypes.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "net.zmq"


namespace
{

  void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const minimal_chain& self)
  {
    namespace adapt = boost::adaptors;

    const auto to_block_id = [](const cryptonote::block& bl)
    {
      crypto::hash id;
      if (!get_block_hash(bl, id))
        MERROR("ZMQ/Pub failure: get_block_hash");
      return id;
    };

    assert(!self.blocks.empty()); // checked in zmq_pub::send_chain_main

    dest.StartObject();
    INSERT_INTO_JSON_OBJECT(dest, first_height, self.height);
    INSERT_INTO_JSON_OBJECT(dest, first_prev_id, self.blocks[0].prev_id);
    INSERT_INTO_JSON_OBJECT(dest, ids, (self.blocks | adapt::transformed(to_block_id)));
    dest.EndObject();
  }

  void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const miner_data& self)
  {
    dest.StartObject();
    INSERT_INTO_JSON_OBJECT(dest, major_version, self.major_version);
    INSERT_INTO_JSON_OBJECT(dest, height, self.height);
    INSERT_INTO_JSON_OBJECT(dest, prev_id, self.prev_id);
    INSERT_INTO_JSON_OBJECT(dest, seed_hash, self.seed_hash);
    INSERT_INTO_JSON_OBJECT(dest, difficulty, cryptonote::hex(self.diff));
    INSERT_INTO_JSON_OBJECT(dest, median_weight, self.median_weight);
    INSERT_INTO_JSON_OBJECT(dest, already_generated_coins, self.already_generated_coins);
    INSERT_INTO_JSON_OBJECT(dest, tx_backlog, self.tx_backlog);
    dest.EndObject();
  }

  void toJsonValue(rapidjson::Writer<epee::byte_stream>& dest, const minimal_txpool& self)
  {
    dest.StartObject();
    INSERT_INTO_JSON_OBJECT(dest, id, self.hash);
    INSERT_INTO_JSON_OBJECT(dest, blob_size, self.blob_size);
    INSERT_INTO_JSON_OBJECT(dest, weight, self.weight);
    INSERT_INTO_JSON_OBJECT(dest, fee, self.fee);
    dest.EndObject();
  }

}//anonymus