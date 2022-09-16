#pragma once

#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common/expect.h" // monero/src
#include "crypto/crypto.h" // monero/src
#include "db/data.h"
// #include "rpc/rates.h"
#include "util/fwd.h"
#include "wire/json/fwd.h"


namespace lws
{
namespace rpc
{
    
    //! Read/write uint64 value as JSON string.
    enum class safe_uint64 : std::uint64_t {};
    void read_bytes(wire::json_reader&, safe_uint64&);
    void write_bytes(wire::json_writer&, safe_uint64);

    //! Read an array of uint64 values as JSON strings.
    struct safe_uint64_array
    {
      std::vector<std::uint64_t> values; // so this can be passed to another function without copy
    };
    void read_bytes(wire::json_reader&, safe_uint64_array&);

    struct transaction_spend
    {
      transaction_spend() = delete;
      lws::db::output::spend_meta_ meta;
      lws::db::spend possible_spend;
    };
    void write_bytes(wire::json_writer&, const transaction_spend&);

    struct account_credentials
    {
      lws::db::account_address address;
      crypto::secret_key key;
    };
    void read_bytes(wire::json_reader&, account_credentials&);

    struct get_address_info_response
    {
      get_address_info_response() noexcept
        : locked_funds(safe_uint64(0)),
          total_received(safe_uint64(0)),
          total_sent(safe_uint64(0)),
          scanned_height(0),
          scanned_block_height(0),
          start_height(0),
          transaction_height(0),
          blockchain_height(0),
          spent_outputs()
          // rates(common_error::kInvalidArgument)
      {}

      safe_uint64 locked_funds;
      safe_uint64 total_received;
      safe_uint64 total_sent;
      std::uint64_t scanned_height;
      std::uint64_t scanned_block_height;
      std::uint64_t start_height;
      std::uint64_t transaction_height;
      std::uint64_t blockchain_height;
      std::vector<transaction_spend> spent_outputs;
      // expect<lws::rates> rates;
    };
    void write_bytes(wire::json_writer&, const get_address_info_response&);

    struct get_address_txs_response
    {
      get_address_txs_response() = delete;
      struct transaction
      {
        transaction() = delete;
        db::output info;
        std::vector<transaction_spend> spends;
        std::uint64_t spent;
      };

      safe_uint64 total_received;
      std::uint64_t scanned_height;
      std::uint64_t scanned_block_height;
      std::uint64_t start_height;
      std::uint64_t transaction_height;
      std::uint64_t blockchain_height;
      std::vector<transaction> transactions;
    };
    void write_bytes(wire::json_writer&, const get_address_txs_response&);

    struct login_request
    {
      login_request() = delete;
      account_credentials creds;
      bool create_account;
      bool generated_locally;
    };
    void read_bytes(wire::json_reader&, login_request&);

    struct login_response
    {
      login_response() = delete;
      bool new_address;
      bool generated_locally;
    };
    void write_bytes(wire::json_writer&, login_response);

}
}
