#pragma once

#include <atomic>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>
#include "db/storage.h"
namespace lws
{
    class scanner
    {
        static std::atomic<bool> running;
        scanner() = delete;

    public:
        //! Stops all scanner instances globally.
        static void sync(db::storage disk);
        static void stop() noexcept { running = false; }
    };

} //lws