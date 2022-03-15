#include <algorithm>
#include <boost/optional/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cassert>
#include <cstring>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "common/command_line.h" // beldex/src
#include "common/expect.h"       // beldex/src
#include "misc_log_ex.h"         // beldex/contrib/epee/include/epee
#include "span.h"                // beldex/contrib/epee/include
#include "string_tools.h"        // beldex/contrib/epee/include
#include "options.h"
#include "config.h"
#include "error.h"
#include "db/storage.h"
#include "db/string.h"
#include "db/data.h"
#include "wire/filters.h"
#include "wire/json/write.h"

namespace
{
  // Do not output "full" debug data provided by `db::data.h` header; truncate output
  template<typename T>
  struct truncated
  {
    T value;
  };

  void write_json_addresses(std::ostream& dest, epee::span<const lws::db::account_address> self)
  {
    // writes an array of monero base58 address strings
    wire::json_stream_writer stream{dest};
    wire::object(stream, wire::field("updated", wire::as_array(self, lws::db::address_string)));
    stream.finish();
  }

  struct options : lws::options
  {
    const command_line::arg_descriptor<bool> show_sensitive;
    const command_line::arg_descriptor<std::string> command;
    const command_line::arg_descriptor<std::vector<std::string>> arguments;

    options()
      : lws::options()
      , show_sensitive{"show-sensitive", "Show view keys", false}
      , command{"command", "Admin command to execute", ""}
      , arguments{"arguments", "Arguments to command"}
    {}

    void prepare(boost::program_options::options_description& description) const
    {
      lws::options::prepare(description);
      command_line::add_arg(description, show_sensitive);
      command_line::add_arg(description, command);
      command_line::add_arg(description, arguments);
    }
  };

  struct program
  {
    lws::db::storage disk;
    std::vector<std::string> arguments;
    bool show_sensitive;
  };

  crypto::secret_key get_key(std::string const& hex)
  {
    crypto::secret_key out{};
    if (!epee::string_tools::hex_to_pod(hex, out))
      MONERO_THROW(lws::error::bad_view_key, "View key has invalid hex");
    return out;
  }

  void add_account(program prog, std::ostream& out)
  {
    if (prog.arguments.size() != 2)
      throw std::runtime_error{"add_account needs exactly two arguments"};

    const lws::db::account_address address[1] = {
      lws::db::address_string(prog.arguments[0]).value()
    };
    const crypto::secret_key key{get_key(prog.arguments[1])};

    MONERO_UNWRAP(prog.disk.add_account(address[0], key));
    write_json_addresses(out, address);
  }

  void debug_database(program prog, std::ostream& out)
  {
    if (!prog.arguments.empty())
      throw std::runtime_error{"debug_database takes zero arguments"};

    auto reader = prog.disk.start_read().value();
    reader.json_debug(out, prog.show_sensitive);
  }

  struct command
  {
    char const* const name;
    void (*const handler)(program, std::ostream&);
    char const* const parameters;
  };

  static constexpr const command commands[] =
  {
    // {"accept_requests",       &accept_requests, "<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    {"add_account",           &add_account,     "<base58 address> <view key hex>"},
    {"debug_database",        &debug_database,  ""},
    // {"list_accounts",         &list_accounts,   ""},
    // {"list_requests",         &list_requests,   ""},
    // {"modify_account_status", &modify_account,  "<\"active\"|\"inactive\"|\"hidden\"> <base58 address> [base 58 address]..."},
    // {"reject_requests",       &reject_requests, "<\"create\"|\"import\"> <base58 address> [base 58 address]..."},
    // {"rescan",                &rescan,          "<height> <base58 address> [base 58 address]..."},
    // {"rollback",              &rollback,        "<height>"}
  };

  void print_help(std::ostream& out)
  {
    boost::program_options::options_description description{"Options"};
    options{}.prepare(description);

    out << "Usage: [options] [command] [arguments]" << std::endl;
    out << description << std::endl;
    out << "Commands:" << std::endl;
    for (command cmd : commands)
    {
      out << "  " << cmd.name << "\t\t" << cmd.parameters << std::endl;
    }
  }

  boost::optional<std::pair<std::string, program>> get_program(int argc, char** argv)
  {
    namespace po = boost::program_options;

    const options opts{};
    po::variables_map args{};
    {
      po::options_description description{"Options"};
      opts.prepare(description);

      po::positional_options_description positional{};
      positional.add(opts.command.name, 1);
      positional.add(opts.arguments.name, -1);

      po::store(
        po::command_line_parser(argc, argv)
        .options(description).positional(positional).run()
        , args
      );
      po::notify(args);
    }

    if (command_line::get_arg(args, command_line::arg_help))
    {
      print_help(std::cout);
      return boost::none;
    }

    opts.set_network(args); // do this first, sets global variable :/

    program prog{
      lws::db::storage::open(command_line::get_arg(args, opts.db_path).c_str(), 0)
    };

    prog.show_sensitive = command_line::get_arg(args, opts.show_sensitive);
    auto cmd = args[opts.command.name];
    if (cmd.empty())
      throw std::runtime_error{"No command given"};

    prog.arguments = command_line::get_arg(args, opts.arguments);
    return {{cmd.as<std::string>(), std::move(prog)}};
  }

  void run(boost::string_ref name, program prog, std::ostream& out)
  {
    struct by_name
    {
      bool operator()(command const& left, command const& right) const noexcept
      {
        assert(left.name && right.name);
        return std::strcmp(left.name, right.name) < 0;
      }
      bool operator()(boost::string_ref left, command const& right) const noexcept
      {
        assert(right.name);
        return left < right.name;
      }
      bool operator()(command const& left, boost::string_ref right) const noexcept
      {
        assert(left.name);
        return left.name < right;
      }
    };

    assert(std::is_sorted(std::begin(commands), std::end(commands), by_name{}));
    const auto found = std::lower_bound(
      std::begin(commands), std::end(commands), name, by_name{}
    );
    if (found == std::end(commands) || found->name != name)
      throw std::runtime_error{"No such command"};

    assert(found->handler != nullptr);
    found->handler(std::move(prog), out);

    if (out.bad())
      MONERO_THROW(std::io_errc::stream, "Writing to stdout failed");

    out << std::endl;
  }

} // anonymous

int main (int argc, char** argv)
{
  std::cout <<"check " << std::endl;
  std::cout << " argc " << argc << std::endl;
  try
  {
    mlog_configure("", false, 0, 0); // disable logging

    boost::optional<std::pair<std::string, program>> prog;

    try
    {
      prog = get_program(argc, argv);
    }
    catch (std::exception const& e)
    {
      std::cerr << e.what() << std::endl << std::endl;
      print_help(std::cerr);
      return EXIT_FAILURE;
    }

    if (prog)
      run(prog->first, std::move(prog->second), std::cout);
  }
  catch (std::exception const& e)
  {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "Unknown exception" << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}