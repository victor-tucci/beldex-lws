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
 enum class block_id : std::uint64_t {};
 struct block_info
  {
    block_id id;      //!< Must be first for LMDB optimizations
    crypto::hash hash;
  };

} //db
} //lws