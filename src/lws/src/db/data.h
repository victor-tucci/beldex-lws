#pragma once

#include <cassert>
#include <cstdint>
#include <iosfwd>
#include <utility> 
 
#include "storage.h"
namespace lws
{
namespace db
{
 enum class account_time : std::uint32_t {};
 enum class block_id : std::uint64_t {};
 struct output_id
  {
    std::uint64_t high; //!< Amount on public chain; rct outputs are `0`
    std::uint64_t low;  //!< Offset within `amount` on the public chain
  };
 enum account_flags : std::uint8_t
  {
    default_account = 0,
    admin_account   = 1,          //!< Not currently used, for future extensions
    account_generated_locally = 2 //!< Flag sent by client on initial login request
  };

 struct view_key : crypto::ec_scalar {};
  struct account_address
  {
    crypto::public_key view_public; //!< Must be first for LMDB optimizations.
    crypto::public_key spend_public;
  };
 struct account
  {
    account_id id;          //!< Must be first for LMDB optimizations
    account_time access;    //!< Last time `get_address_info` was called.
    account_address address;
    view_key key;           //!< Doubles as authorization handle for REST API.
    block_id scan_height;   //!< Last block scanned; check-ins are always by block
    block_id start_height;  //!< Account started scanning at this block height
    account_time creation;  //!< Time account first appeared in database.
    account_flags flags;    //!< Additional account info bitmask.
    char reserved[3];
  };

   struct block_info
  {
    block_id id;      //!< Must be first for LMDB optimizations
    crypto::hash hash;
  };
  struct transaction_link
  {
    block_id height;      //!< Block height containing transaction
    crypto::hash tx_hash; //!< Hash of the transaction
  };
  struct key_image
  {
    crypto::key_image value; //!< Actual key image value
    // The above field needs to be first for LMDB optimizations
    transaction_link link;   //!< Link to `spend` and `output`.
  };
  struct request_info
  {
    account_address address;//!< Must be first for LMDB optimizations
    view_key key;
    block_id start_height;
    account_time creation;        //!< Time the request was created.
    account_flags creation_flags; //!< Generated locally?
    char reserved[3];
  };
} //db
} //lws