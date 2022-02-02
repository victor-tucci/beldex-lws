#pragma once

#include <iosfwd>
#include <list>
#include <memory>
#include <utility>
#include <vector>

#include "common/expect.h"
#include "crypto/crypto.h"
#include "fwd.h"
#include "lmdb/transaction.h"
#include "lmdb/key_stream.h"
#include "lmdb/value_stream.h"
namespace crypto
{
  struct hash;
}
namespace lws 
{
 namespace db
 {
  namespace cursor
  {
    MONERO_CURSOR(accounts);
    MONERO_CURSOR(outputs);
    MONERO_CURSOR(spends);
    MONERO_CURSOR(images);
    MONERO_CURSOR(requests);

    MONERO_CURSOR(blocks);
    MONERO_CURSOR(accounts_by_address);
    MONERO_CURSOR(accounts_by_height);
  }
  
   struct storage_internal;
   class storage
    {
    std::shared_ptr<storage_internal> db;

    storage(std::shared_ptr<storage_internal> db) noexcept
      : db(std::move(db))
    {}

  public:
    /*!
      Open a light_wallet_server LDMB database.

      \param path Directory for LMDB storage
      \param create_queue_max Maximum number of create account requests allowed.

      \throw std::system_error on any LMDB error (all treated as fatal).
      \throw std::bad_alloc If `std::shared_ptr` fails to allocate.

      \return A ready light-wallet server database.
    */
    static storage open(const char* path, unsigned create_queue_max);

    storage(storage&&) = default;
    storage(storage const&) = delete;

    ~storage() noexcept;

    storage& operator=(storage&&) = default;
    storage& operator=(storage const&) = delete;

    //! \return A copy of the LMDB environment, but not reusable txn/cursors.
    storage clone() const noexcept;

  //   //! Rollback chain and accounts to `height`.
  //  // expect<void> rollback(block_id height);

  //   /*!
  //     Sync the local blockchain with a remote version. Pops user txes if reorg
  //     detected.

  //     \param height The height of the element in `hashes`
  //     \param hashes List of blockchain hashes starting at `height`.

  //     \return True if the local blockchain is correctly synced.
  //   */
  // //  expect<void> sync_chain(block_id height, epee::span<const crypto::hash> hashes);

  //   //! Bump the last access time of `address` to the current time.
  //  // expect<void> update_access_time(account_address const& address) noexcept;

  //   //! Change state of `address` to `status`. \return Updated `addresses`.
  //   expect<std::vector<account_address>>
  //     change_status(account_status status, epee::span<const account_address> addresses);


  //   //! Add an account, for immediate inclusion in the active list.
  //   expect<void> add_account(account_address const& address, crypto::secret_key const& key) noexcept;

  //   //! Reset `addresses` to `height` for scanning.
  //   expect<std::vector<account_address>>
  //     rescan(block_id height, epee::span<const account_address> addresses);

  //   //! Add an account for later approval. For use with the login endpoint.
  //   expect<void> creation_request(account_address const& address, crypto::secret_key const& key, account_flags flags) noexcept;

  //   /*!
  //     Request lock height of an existing account. No effect if the `start_height`
  //     is already older.
  //   */
  //   expect<void> import_request(account_address const& address, block_id height) noexcept;

  //   //! Accept requests by `addresses` of type `req`. \return Accepted addresses.
  //   expect<std::vector<account_address>>
  //     accept_requests(request req, epee::span<const account_address> addresses);

  //   //! Reject requests by `addresses` of type `req`. \return Rejected addresses.
  //   expect<std::vector<account_address>>
  //     reject_requests(request req, epee::span<const account_address> addresses);

  //   /*!
  //     Updates the status of user accounts, even if inactive or hidden. Duplicate
  //     receives or spends provided in `accts` are silently ignored. If a gap in
  //     `height` vs the stored account record is detected, the entire update will
  //     fail.

  //     \param height The first hash in `chain` is at this height.
  //     \param chain List of block hashes that `accts` were scanned against.
  //     \param accts Updated to `height + chain.size()` scan height.

  //     \return True iff LMDB successfully committed the update.
  //   */
  //   expect<std::size_t> update(block_id height, epee::span<const crypto::hash> chain, epee::span<const lws::account> accts);

  //   //! `txn` must have come from a previous call on the same thread.
  //   expect<storage_reader> start_read(lmdb::suspended_txn txn = nullptr) const;
  };// storage
 }//db
}//lws