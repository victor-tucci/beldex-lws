#pragma once

#include <atomic>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <string>

namespace lws
{
    class scanner
    {
        static std::atomic<bool> running;
        scanner() = delete;

    public:
        //! Stops all scanner instances globally.
        static void stop() noexcept { running = false; }
    };

} //lws