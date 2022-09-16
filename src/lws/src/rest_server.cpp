#include "rest_server.h"

#include <algorithm>
#include <boost/utility/string_ref.hpp>
#include <cstring>
#include <limits>
#include <string>
#include <utility>

#include "common/error.h"         // monero/src
#include "common/expect.h"
#include "crypto/crypto.h"        // monero/src
#include "cryptonote_config.h"    // monero/src
#include "lmdb/util.h"                 // monero/src

#include "error.h"
#include "db/data.h"
#include "db/storage.h"
#include "util/http_server.h"
#include "util/gamma_picker.h"
#include "util/random_outputs.h"
#include "util/source_location.h"
#include "rpc/light_wallet.h"
#include "wire/json.h"
namespace lws
{
  namespace
  {
    namespace http = epee::net_utils::http;

    struct context : epee::net_utils::connection_context_base
    {
      context()
        : epee::net_utils::connection_context_base()
      {}
    };

    bool is_hidden(db::account_status status) noexcept
    {
      switch (status)
      {
      case db::account_status::active:
      case db::account_status::inactive:
        return false;
      default:
      case db::account_status::hidden:
        break;
      }
      return true;
    }

    bool is_locked(std::uint64_t unlock_time, db::block_id last) noexcept
    {
      if (unlock_time > CRYPTONOTE_MAX_BLOCK_NUMBER)
        return std::chrono::seconds{unlock_time} > std::chrono::system_clock::now().time_since_epoch();
      return db::block_id(unlock_time) > last;
    }

    bool key_check(const rpc::account_credentials& creds)
    {
      crypto::public_key verify{};
      if (!crypto::secret_key_to_public_key(creds.key, verify))
        return false;
      if (verify != creds.address.view_public)
        return false;
      return true;
    }
    
    std::vector<db::output::spend_meta_>::const_iterator
    find_metadata(std::vector<db::output::spend_meta_> const& metas, db::output_id id)
    {
      struct by_output_id
      {
        bool operator()(db::output::spend_meta_ const& left, db::output_id right) const noexcept
        {
          return left.id < right;
        }
        bool operator()(db::output_id left, db::output::spend_meta_ const& right) const noexcept
        {
          return left < right.id;
        }
      };
      return std::lower_bound(metas.begin(), metas.end(), id, by_output_id{});
    }


    //! \return Account info from the DB, iff key matches address AND address is NOT hidden.
    expect<std::pair<db::account, db::storage_reader>> open_account(const rpc::account_credentials& creds, db::storage disk)
    {
      if (!key_check(creds))
        return {lws::error::bad_view_key};

      auto reader = disk.start_read();
      if (!reader)
        return reader.error();

      const auto user = reader->get_account(creds.address);
      if (!user)
        return user.error();
      if (is_hidden(user->first))
        return {lws::error::account_not_found};
      return {std::make_pair(user->second, std::move(*reader))};
    }

    struct get_address_info
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_info_response;

      static expect<response> handle(const request& req, db::storage disk)
      {
        auto user = open_account(req, std::move(disk));
        if (!user)
          return user.error();

        response resp{};

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);

        std::vector<db::output::spend_meta_> metas{};
        metas.reserve(outputs->count());

        for (auto output = outputs->make_iterator(); !output.is_end(); ++output)
        {
          const db::output::spend_meta_ meta =
            output.get_value<MONERO_FIELD(db::output, spend_meta)>();

          // these outputs will usually be in correct order post ringct
          if (metas.empty() || metas.back().id < meta.id)
            metas.push_back(meta);
          else
            metas.insert(find_metadata(metas, meta.id), meta);

          resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + meta.amount);
          if (is_locked(output.get_value<MONERO_FIELD(db::output, unlock_time)>(), last->id))
            resp.locked_funds = rpc::safe_uint64(std::uint64_t(resp.locked_funds) + meta.amount);
        }

        resp.spent_outputs.reserve(spends->count());
        for (auto const& spend : spends->make_range())
        {
          const auto meta = find_metadata(metas, spend.source);
          if (meta == metas.end() || meta->id != spend.source)
          {
            throw std::logic_error{
              "Serious database error, no receive for spend"
            };
          }

          resp.spent_outputs.push_back({*meta, spend});
          resp.total_sent = rpc::safe_uint64(std::uint64_t(resp.total_sent) + meta->amount);
        }

        // resp.rates = client.get_rates();
        // if (!resp.rates && !rates_error_once.test_and_set(std::memory_order_relaxed))
        //   MWARNING("Unable to retrieve exchange rates: " << resp.rates.error().message());

        return resp;
      }
    };//get_address_info


    struct get_address_txs
    {
      using request = rpc::account_credentials;
      using response = rpc::get_address_txs_response;

      static expect<response> handle(const request& req, db::storage disk)
      {
        auto user = open_account(req, std::move(disk));
        if (!user)
          return user.error();

        auto outputs = user->second.get_outputs(user->first.id);
        if (!outputs)
          return outputs.error();

        auto spends = user->second.get_spends(user->first.id);
        if (!spends)
          return spends.error();

        const expect<db::block_info> last = user->second.get_last_block();
        if (!last)
          return last.error();

        response resp{};
        resp.scanned_height = std::uint64_t(user->first.scan_height);
        resp.scanned_block_height = resp.scanned_height;
        resp.start_height = std::uint64_t(user->first.start_height);
        resp.blockchain_height = std::uint64_t(last->id);
        resp.transaction_height = resp.blockchain_height;

        // merge input and output info into a single set of txes.

        auto output = outputs->make_iterator();
        auto spend = spends->make_iterator();

        std::vector<db::output::spend_meta_> metas{};

        resp.transactions.reserve(outputs->count());
        metas.reserve(resp.transactions.capacity());

        db::transaction_link next_output{};
        db::transaction_link next_spend{};

        if (!output.is_end())
          next_output = output.get_value<MONERO_FIELD(db::output, link)>();
        if (!spend.is_end())
          next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();

        while (!output.is_end() || !spend.is_end())
        {
          if (!resp.transactions.empty())
          {
            db::transaction_link const& last = resp.transactions.back().info.link;

            if ((!output.is_end() && next_output < last) || (!spend.is_end() && next_spend < last))
            {
              throw std::logic_error{"DB has unexpected sort order"};
            }
          }

          if (spend.is_end() || (!output.is_end() && next_output <= next_spend))
          {
            std::uint64_t amount = 0;
            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_output.tx_hash)
            {
              resp.transactions.push_back({*output});
              amount = resp.transactions.back().info.spend_meta.amount;
            }
            else
            {
              amount = output.get_value<MONERO_FIELD(db::output, spend_meta.amount)>();
              resp.transactions.back().info.spend_meta.amount += amount;
            }

            const db::output::spend_meta_ meta = output.get_value<MONERO_FIELD(db::output, spend_meta)>();
            if (metas.empty() || metas.back().id < meta.id)
              metas.push_back(meta);
            else
              metas.insert(find_metadata(metas, meta.id), meta);

            resp.total_received = rpc::safe_uint64(std::uint64_t(resp.total_received) + amount);

            ++output;
            if (!output.is_end())
              next_output = output.get_value<MONERO_FIELD(db::output, link)>();
          }
          else if (output.is_end() || (next_spend < next_output))
          {
            const db::output_id source_id = spend.get_value<MONERO_FIELD(db::spend, source)>();
            const auto meta = find_metadata(metas, source_id);
            if (meta == metas.end() || meta->id != source_id)
            {
              throw std::logic_error{
                "Serious database error, no receive for spend"
              };
            }

            if (resp.transactions.empty() || resp.transactions.back().info.link.tx_hash != next_spend.tx_hash)
            {
              resp.transactions.push_back({});
              resp.transactions.back().spends.push_back({*meta, *spend});
              resp.transactions.back().info.link.height = resp.transactions.back().spends.back().possible_spend.link.height;
              resp.transactions.back().info.link.tx_hash = resp.transactions.back().spends.back().possible_spend.link.tx_hash;
              resp.transactions.back().info.spend_meta.mixin_count =
                resp.transactions.back().spends.back().possible_spend.mixin_count;
              resp.transactions.back().info.timestamp = resp.transactions.back().spends.back().possible_spend.timestamp;
              resp.transactions.back().info.unlock_time = resp.transactions.back().spends.back().possible_spend.unlock_time;
            }
            else
              resp.transactions.back().spends.push_back({*meta, *spend});

            resp.transactions.back().spent += meta->amount;

            ++spend;
            if (!spend.is_end())
              next_spend = spend.get_value<MONERO_FIELD(db::spend, link)>();
          }
        }

        return resp;
      }
    };

    struct import_request
    {
      using request = rpc::account_credentials;
      using response = rpc::import_response;

      static expect<response> handle(request req, db::storage disk)
      {
        bool new_request = false;
        bool fulfilled = false;
        {
          auto user = open_account(req, disk.clone());
          if (!user)
            return user.error();

          if (user->first.start_height == db::block_id(0))
            fulfilled = true;
          else
          {
            const expect<db::request_info> info =
              user->second.get_request(db::request::import_scan, req.address);

            if (!info)
            {
              if (info != lmdb::error(MDB_NOTFOUND))
                return info.error();

              new_request = true;
            }
          }
        } // close reader

        if (new_request)
          MONERO_CHECK(disk.import_request(req.address, db::block_id(0)));

        const char* status = new_request ?
          "Accepted, waiting for approval" : (fulfilled ? "Approved" : "Waiting for Approval");
        return response{rpc::safe_uint64(0), status, new_request, fulfilled};
      }
    };

    struct login
    {
      using request = rpc::login_request;
      using response = rpc::login_response;

      static expect<response> handle(request req, db::storage disk)
      {
        std::cout <<"inside the login\n";
        if (!key_check(req.creds))
          return {lws::error::bad_view_key};

        {
          auto reader = disk.start_read();
          if (!reader)
            return reader.error();

          const auto account = reader->get_account(req.creds.address);
          reader->finish_read();

          if (account)
          {
            if (is_hidden(account->first))
              return {lws::error::account_not_found};

            // Do not count a request for account creation as login
            return response{false, bool(account->second.flags & db::account_generated_locally)};
          }
          else if (!req.create_account || account != lws::error::account_not_found)
            return account.error();
        }

        const auto flags = req.generated_locally ? db::account_generated_locally : db::default_account;
        MONERO_CHECK(disk.creation_request(req.creds.address, req.creds.key, flags));
        std::cout <<"creation_request called\n";
        return response{true, req.generated_locally};
      }
    };//login

    template<typename E>
    expect<epee::byte_slice> call(std::string&& root, db::storage disk)
    {
      using request = typename E::request;
      using response = typename E::response;

      expect<request> req = wire::json::from_bytes<request>(std::move(root));
      if (!req)
        return req.error();

      expect<response> resp = E::handle(std::move(*req), std::move(disk));
      if (!resp)
        return resp.error();
      return wire::json::to_bytes<response>(*resp);
    }

    struct endpoint
    {
      char const* const name;
      expect<epee::byte_slice> (*const run)(std::string&&, db::storage);
      const unsigned max_size;
    };

    constexpr const endpoint endpoints[] =
    {
      {"/get_address_info",      call<get_address_info>, 2 * 1024},
      {"/get_address_txs",       call<get_address_txs>,  2 * 1024},
      // {"/get_random_outs",       call<get_random_outs>,  2 * 1024},
      // {"/get_txt_records",       nullptr,                0       },
      // {"/get_unspent_outs",      call<get_unspent_outs>, 2 * 1024},
      {"/import_request",        call<import_request>,   2 * 1024},
      {"/login",                 call<login>,            2 * 1024}
      // {"/submit_raw_tx",         call<submit_raw_tx>,   50 * 1024}
    };

    struct by_name_
    {
      bool operator()(endpoint const& left, endpoint const& right) const noexcept
      {
        if (left.name && right.name)
          return std::strcmp(left.name, right.name) < 0;
        return false;
      }
      bool operator()(const boost::string_ref left, endpoint const& right) const noexcept
      {
        if (right.name)
          return left < right.name;
        return false;
      }
      bool operator()(endpoint const& left, const boost::string_ref right) const noexcept
      {
        if (left.name)
          return left.name < right;
        return false;
      }
    };
    constexpr const by_name_ by_name{};

  } //anonymous
    struct rest_server::internal final : public lws::http_server_impl_base<rest_server::internal, context>
    {
      db::storage disk;
    
      explicit internal(boost::asio::io_service& io_service, lws::db::storage disk)
        : lws::http_server_impl_base<rest_server::internal, context>(io_service)
        , disk(std::move(disk))
      {
        // assert(std::is_sorted(std::begin(endpoints), std::end(endpoints), by_name));
      }

      virtual bool
      handle_http_request(const http::http_request_info& query, http::http_response_info& response, context& ctx)
      override final
      {
        const auto handler = std::lower_bound(
          std::begin(endpoints), std::end(endpoints), query.m_URI, by_name
        );
        if (handler == std::end(endpoints) || handler->name != query.m_URI)
        {
          response.m_response_code = 404;
          response.m_response_comment = "Not Found";
          return true;
        }

        if (handler->run == nullptr)
        {
          response.m_response_code = 501;
          response.m_response_comment = "Not Implemented";
          return true;
        }

        if (handler->max_size < query.m_body.size())
        {
          MINFO("Client exceeded maximum body size (" << handler->max_size << " bytes)");
          response.m_response_code = 400;
          response.m_response_comment = "Bad Request";
          return true;
        }

        if (query.m_http_method != http::http_method_post)
        {
          response.m_response_code = 405;
          response.m_response_comment = "Method Not Allowed";
          return true;
        }

        // \TODO remove copy of json string here :/
        auto body = handler->run(std::string{query.m_body}, disk.clone());
        if (!body)
        {
          MINFO(body.error().message() << " from " << ctx.m_remote_address.str() << " on " << handler->name);

          if (body.error().category() == wire::error::rapidjson_category())
          {
            response.m_response_code = 400;
            response.m_response_comment = "Bad Request";
          }
          else if (body == lws::error::account_not_found || body == lws::error::duplicate_request)
          {
            response.m_response_code = 403;
            response.m_response_comment = "Forbidden";
          }
          else if (body.matches(std::errc::timed_out) || body.matches(std::errc::no_lock_available))
          {
            response.m_response_code = 503;
            response.m_response_comment = "Service Unavailable";
          }
          else
          {
            response.m_response_code = 500;
            response.m_response_comment = "Internal Server Error";
          }
          return true;
        }

        response.m_response_code = 200;
        response.m_response_comment = "OK";
        response.m_mime_tipe = "application/json";
        response.m_header_info.m_content_type = "application/json";
        response.m_body.assign(reinterpret_cast<const char*>(body->data()), body->size()); // \TODO Remove copy here too!s
        return true;
      }
    };
    rest_server::rest_server(epee::span<const std::string> addresses, db::storage disk, configuration config)
        : io_service_(), ports_()
    {
        ports_.emplace_back(io_service_, std::move(disk));

        if (addresses.empty())
            MONERO_THROW(common_error::kInvalidArgument, "REST server requires 1 or more addresses");

        const auto init_port = [](internal &port, const std::string &address, configuration config) -> bool
        {
            epee::net_utils::http::url_content url{};
            if (!epee::net_utils::parse_url(address, url))
                MONERO_THROW(lws::error::configuration, "REST Server URL/address is invalid");

            const bool https = url.schema == "https";
            if (!https && url.schema != "http")
                MONERO_THROW(lws::error::configuration, "Unsupported scheme, only http or https supported");

            if (std::numeric_limits<std::uint16_t>::max() < url.port)
                MONERO_THROW(lws::error::configuration, "Specified port for rest server is out of range");

            if (!https)
            {
                boost::system::error_code error{};
                const boost::asio::ip::address ip_host =
                    ip_host.from_string(url.host, error);
                if (error)
                    MONERO_THROW(lws::error::configuration, "Invalid IP address for REST server");
                if (!ip_host.is_loopback() && !config.allow_external)
                    MONERO_THROW(lws::error::configuration, "Binding to external interface with http - consider using https or secure tunnel (ssh, etc). Use --confirm-external-bind to override");
            }

            if (url.port == 0)
                url.port = https ? 8443 : 8080;

            epee::net_utils::ssl_options_t ssl_options = https ? epee::net_utils::ssl_support_t::e_ssl_support_enabled : epee::net_utils::ssl_support_t::e_ssl_support_disabled;
            ssl_options.verification = epee::net_utils::ssl_verification_t::none; // clients verified with view key
            ssl_options.auth = std::move(config.auth);

            if (!port.init(std::to_string(url.port), std::move(url.host), std::move(config.access_controls), std::move(ssl_options)))
                MONERO_THROW(lws::error::http_server, "REST server failed to initialize");
            return https;
        };

        bool any_ssl = false;
        for (std::size_t index = 1; index < addresses.size(); ++index)
        {
            ports_.emplace_back(io_service_, ports_.front().disk.clone());
            any_ssl |= init_port(ports_.back(), addresses[index], config);
        }

        const bool expect_ssl = !config.auth.private_key_path.empty();
        const std::size_t threads = config.threads;
        any_ssl |= init_port(ports_.front(), addresses[0], std::move(config));
        if (!any_ssl && expect_ssl)
            MONERO_THROW(lws::error::configuration, "Specified SSL key/cert without specifying https capable REST server");

        if (!ports_.front().run(threads, false))
            MONERO_THROW(lws::error::http_server, "REST server failed to run");
    }

    rest_server::~rest_server() noexcept
    {
    }
} // lws