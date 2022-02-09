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

#include "common/error.h"                             // monero/src
#include "crypto/crypto.h"                            // monero/src
#include "error.h"
#include "scanner.h"

namespace lws
{
    std::atomic<bool> scanner::running{true};

}//lws