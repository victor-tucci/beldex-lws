#include "storage.h"

#include <boost/container/static_vector.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/iterator_range.hpp>
#include <cassert>
#include <chrono>
#include <limits>
#include <string>
#include <utility>

#include "common/expect.h"   //beldex/src
namespace lws
{
    namespace db
    {
     storage storage::open(const char* path, unsigned create_queue_max)
     {
     return {
      std::make_shared<storage_internal>(
        MONERO_UNWRAP(lmdb::open_environment(path, 20)), create_queue_max
        )
      };
     }

    }
}