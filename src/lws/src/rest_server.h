#pragma once

#include <boost/asio/io_service.hpp>
#include <cstddef>
#include <list>
#include <string>
#include <vector>

#include "db/storage.h"
#include "rpc/client.h"
#include "epee/span.h"

#include "epee/net/http_base.h"             // beldex/contrib/epee/include
#include "epee/net/net_parse_helpers.h"     // beldex/contrib/epee/include
#include "epee/net/net_ssl.h"               // beldex/contrib/epee/include

namespace lws
{
    class rest_server
    {
        struct internal;
        boost::asio::io_service io_service_;
        std::list<internal> ports_;
    public:
        struct configuration
        {
            epee::net_utils::ssl_authentication_t auth;
            std::vector<std::string> access_controls;
            std::size_t threads;
            bool allow_external;
        }; //configre

        rest_server(epee::span<const std::string> addresses, db::storage disk, configuration config);

        rest_server(rest_server&&) = delete;
        rest_server(rest_server const&) = delete;

        ~rest_server() noexcept;

        rest_server& operator=(rest_server&&) = delete;
        rest_server& operator=(rest_server const&) = delete;
    }; //rest_server


} //lws