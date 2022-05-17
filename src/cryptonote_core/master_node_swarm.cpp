#include "master_node_swarm.h"
#include "common/random.h"

#undef BELDEX_DEFAULT_LOG_CATEGORY
#define BELDEX_DEFAULT_LOG_CATEGORY "master_nodes"

#ifdef UNIT_TEST
  #define prod_static
#else
  #define prod_static static
#endif

namespace master_nodes
{
  uint64_t get_new_swarm_id(const swarm_mnode_map_t &swarm_to_mnodes)
  {
    if (swarm_to_mnodes.empty()) return 0;

    std::vector<swarm_id_t> all_ids;
    all_ids.reserve(swarm_to_mnodes.size());
    for (const auto& entry : swarm_to_mnodes) {
      all_ids.push_back(entry.first);
    }

    assert(std::is_sorted(all_ids.begin(), all_ids.end()));

    uint64_t max_dist = 0;
    // The new swarm that is the farthest from its right neighbour
    uint64_t best_idx = 0;

    for (auto idx = 0u; idx < all_ids.size() - 1; ++idx)
    {
      const uint64_t dist = all_ids[idx+1] - all_ids[idx];

      if (dist > max_dist)
      {
        max_dist = dist;
        best_idx = idx;
      }
    }

    // Handle the special case involving the gap between the
    // rightmost and the leftmost swarm due to wrapping.
    // Note that we are adding 1 as we treat 0 and MAX_ID as *one* apart
    const uint64_t dist = MAX_ID - all_ids.back() + all_ids.front() + 1;
    if (dist > max_dist)
    {
      max_dist = dist;
      best_idx = all_ids.size() - 1;
    }

    const uint64_t diff = max_dist / 2; /// how much to add to an existing id
    const uint64_t to_max = MAX_ID - all_ids[best_idx]; /// how much we can add not overflow

    if (diff > to_max)
    {
      return diff - to_max - 1; // again, assuming MAX_ID + 1 = 0
    }

    return all_ids[best_idx] + diff;
  }

  /// The excess is calculated as the total number of mnodes above MIN_SWARM_SIZE across all swarms
  prod_static size_t calc_excess(const swarm_mnode_map_t &swarm_to_mnodes)
  {
    const size_t excess = std::accumulate(swarm_to_mnodes.begin(),
                                          swarm_to_mnodes.end(),
                                          size_t(0),
                                          [](size_t result, const swarm_mnode_map_t::value_type &pair) {
                                            const ssize_t margin = pair.second.size() - MIN_SWARM_SIZE;
                                            return result + std::max(margin, ssize_t(0));
                                          });
    LOG_PRINT_L2("Calculated excess: " << excess);
    return excess;
  };

  /// Calculate threshold above which the excess should create a new swarm.
  /// The threshold should be such that
  /// 1. there is enough excess to create a new swarm of size NEW_SWARM_SIZE AND
  /// 2. there is enough excess to leave IDEAL_SWARM_MARGIN excess in the existing swarms
  prod_static size_t calc_threshold(const swarm_mnode_map_t &swarm_to_mnodes)
  {
    const size_t threshold = NEW_SWARM_SIZE + (swarm_to_mnodes.size() * IDEAL_SWARM_MARGIN);
    LOG_PRINT_L2("Calculated threshold: " << threshold);
    return threshold;
  };

  prod_static const excess_pool_mnode& pick_from_excess_pool(const std::vector<excess_pool_mnode>& excess_pool, std::mt19937_64 &mt)
  {
    /// Select random mnode
    const auto idx = tools::uniform_distribution_portable(mt, excess_pool.size());
    return excess_pool.at(idx);
  }

  prod_static void remove_excess_mnode_from_swarm(const excess_pool_mnode& excess_mnode, swarm_mnode_map_t &swarm_to_mnodes)
  {
    auto &swarm_mn_vec = swarm_to_mnodes.at(excess_mnode.swarm_id);
    swarm_mn_vec.erase(std::remove(swarm_mn_vec.begin(), swarm_mn_vec.end(), excess_mnode.public_key), swarm_mn_vec.end());
  }

  prod_static void get_excess_pool(size_t threshold, const swarm_mnode_map_t& swarm_to_mnodes, std::vector<excess_pool_mnode>& pool_mnodes, size_t& excess)
  {
    /// Create a pool of all the master nodes belonging
    /// to the swarms that have excess. That way we naturally
    /// make the chances of picking a swarm proportionate to the
    /// swarm size.
    pool_mnodes.clear();

    if (threshold < MIN_SWARM_SIZE)
      return;

    excess = 0;
    for (const auto &entry : swarm_to_mnodes)
    {
      if (entry.second.size() > threshold)
      {
        excess += entry.second.size() - MIN_SWARM_SIZE;
        for (const auto& mn_pk : entry.second)
        {
          pool_mnodes.push_back({mn_pk, entry.first});
        }
      }
    }
  }

  prod_static void create_new_swarm_from_excess(swarm_mnode_map_t &swarm_to_mnodes, std::mt19937_64 &mt)
  {
    const bool has_starving_swarms = std::any_of(swarm_to_mnodes.begin(),
                                                swarm_to_mnodes.end(),
                                                [](const swarm_mnode_map_t::value_type& pair) {
                                                  return pair.second.size() < MIN_SWARM_SIZE;
                                                });
    if (has_starving_swarms)
      return;

    std::vector<excess_pool_mnode> pool_mnodes;

    while (calc_excess(swarm_to_mnodes) >= calc_threshold(swarm_to_mnodes))
    {
      LOG_PRINT_L2("New swarm creation");
      std::vector<crypto::public_key> new_swarm_mnodes;
      new_swarm_mnodes.reserve(NEW_SWARM_SIZE);
      while (new_swarm_mnodes.size() < NEW_SWARM_SIZE)
      {
        size_t excess;
        get_excess_pool(MIN_SWARM_SIZE, swarm_to_mnodes, pool_mnodes, excess);
        if (pool_mnodes.size() == 0)
        {
          MERROR("Error while getting excess pool for new swarm creation");
          return;
        }
        const auto& random_excess_mnode = pick_from_excess_pool(pool_mnodes, mt);
        new_swarm_mnodes.push_back(random_excess_mnode.public_key);
        remove_excess_mnode_from_swarm(random_excess_mnode, swarm_to_mnodes);
      }
      const auto new_swarm_id = get_new_swarm_id(swarm_to_mnodes);
      if (auto [it, ins] = swarm_to_mnodes.emplace(new_swarm_id, std::move(new_swarm_mnodes));
              !ins) {
          MFATAL("New swarm ID gave a swarm id (" << new_swarm_id << ") that already exists -- this is a bug!");
          // If we actually abort() here then hitting this would potentially kill the whole network
          // if we hit this bug, so just warn very loudly and move on; if it happens we'll have to
          // track down the bug and fix it separately.
      } else {
          LOG_PRINT_L2("Created new swarm from excess: " << new_swarm_id);
      }
    }
  }

  prod_static void calc_swarm_sizes(const swarm_mnode_map_t &swarm_to_mnodes, std::vector<swarm_size> &sorted_swarm_sizes)
  {
    sorted_swarm_sizes.clear();
    sorted_swarm_sizes.reserve(swarm_to_mnodes.size());
    for (const auto &entry : swarm_to_mnodes)
    {
      sorted_swarm_sizes.push_back({entry.first, entry.second.size()});
    }
    std::sort(sorted_swarm_sizes.begin(),
              sorted_swarm_sizes.end(),
              [](const swarm_size &a, const swarm_size &b) {
                return a.size < b.size;
              });
  }

  /// Assign each mnode from mnode_pubkeys into the FILL_SWARM_LOWER_PERCENTILE or DECOMMISSIONED_REDISTRIBUTION_LOWER_PERCENTILE  percentile of swarms
  /// and run the excess/threshold logic after each assignment to ensure new swarms are generated when required.
  prod_static void assign_mnodes(const std::vector<crypto::public_key> &mnode_pubkeys, swarm_mnode_map_t &swarm_to_mnodes, std::mt19937_64 &mt, size_t percentile)
  {
    std::vector<swarm_size> sorted_swarm_sizes;
    for (const auto &mn_pk : mnode_pubkeys)
    {
      calc_swarm_sizes(swarm_to_mnodes, sorted_swarm_sizes);
      const size_t percentile_index = percentile * (sorted_swarm_sizes.size() - 1) / 100;
      const size_t percentile_value = sorted_swarm_sizes.at(percentile_index).size;
      /// Find last occurence of percentile_value
      size_t upper_index = sorted_swarm_sizes.size() - 1;
      for (size_t i = percentile_index; i < sorted_swarm_sizes.size(); ++i)
      {
        if (sorted_swarm_sizes[i].size > percentile_value)
        {
          /// Would never happen for i == 0
          upper_index = i - 1;
          break;
        }
      }
      const size_t random_idx = tools::uniform_distribution_portable(mt, upper_index + 1);
      const swarm_id_t swarm_id = sorted_swarm_sizes[random_idx].swarm_id;
      swarm_to_mnodes.at(swarm_id).push_back(mn_pk);
      /// run the excess/threshold round after each additional mnode
      create_new_swarm_from_excess(swarm_to_mnodes, mt);
    }
  }

  void calc_swarm_changes(swarm_mnode_map_t &swarm_to_mnodes, uint64_t seed)
  {

    if (swarm_to_mnodes.size() == 0)
    {
      // nothing to do
      return;
    }

    std::mt19937_64 mersenne_twister(seed);

    std::vector<crypto::public_key> unassigned_mnodes;
    const auto it = swarm_to_mnodes.find(UNASSIGNED_SWARM_ID);
    if (it != swarm_to_mnodes.end()) {
      unassigned_mnodes = it->second;
      swarm_to_mnodes.erase(it);
    }

    LOG_PRINT_L3("calc_swarm_changes. swarms: " << swarm_to_mnodes.size() << ", regs: " << unassigned_mnodes.size());

    /// 0. Ensure there is always 1 swarm
    if (swarm_to_mnodes.size() == 0)
    {
      const auto new_swarm_id = get_new_swarm_id({});
      swarm_to_mnodes.insert({new_swarm_id, {}});
      LOG_PRINT_L2("Created initial swarm " << new_swarm_id);
    }

    /// 1. Assign new registered mnodes
    assign_mnodes(unassigned_mnodes, swarm_to_mnodes, mersenne_twister, FILL_SWARM_LOWER_PERCENTILE);
    LOG_PRINT_L2("After assignment:");
    for (const auto &entry : swarm_to_mnodes)
    {
      LOG_PRINT_L2(entry.first << ": " << entry.second.size());
    }

    /// 2. *Robin Hood Round* steal mnodes from wealthy swarms and give them to the poor
    {
      std::vector<swarm_size> sorted_swarm_sizes;
      calc_swarm_sizes(swarm_to_mnodes, sorted_swarm_sizes);
      bool insufficient_excess = false;
      for (const auto& swarm : sorted_swarm_sizes)
      {
        /// we have processed all the starving swarms
        if (swarm.size >= MIN_SWARM_SIZE)
          break;

        auto& poor_swarm_mnodes = swarm_to_mnodes.at(swarm.swarm_id);
        do
        {
          const size_t percentile_index = STEALING_SWARM_UPPER_PERCENTILE * (sorted_swarm_sizes.size() - 1) / 100;
          /// -1 since we will only consider swarm sizes strictly above percentile_value
          size_t percentile_value = sorted_swarm_sizes.at(percentile_index).size - 1;
          percentile_value = std::max(MIN_SWARM_SIZE, percentile_value);
          size_t excess;
          std::vector<excess_pool_mnode> excess_pool;
          get_excess_pool(percentile_value, swarm_to_mnodes, excess_pool, excess);
          /// If we can't save the swarm, don't bother continuing
          const size_t deficit = MIN_SWARM_SIZE - poor_swarm_mnodes.size();
          insufficient_excess = (excess < deficit);
          if (insufficient_excess)
            break;
          const auto& excess_mnode = pick_from_excess_pool(excess_pool, mersenne_twister);
          remove_excess_mnode_from_swarm(excess_mnode, swarm_to_mnodes);
          /// Add public key to poor swarm
          poor_swarm_mnodes.push_back(excess_mnode.public_key);
          LOG_PRINT_L2("Stolen 1 mnode " << excess_mnode.public_key << " from " << excess_mnode.swarm_id << " and donated to " << swarm.swarm_id);
        } while (poor_swarm_mnodes.size() < MIN_SWARM_SIZE);

        /// If there is not enough excess for the current swarm,
        /// there isn't either for the next one since the swarms are sorted
        if (insufficient_excess)
          break;
      }
    }

    /// 3. New swarm creation
    create_new_swarm_from_excess(swarm_to_mnodes, mersenne_twister);

    /// 4. If there is a swarm with less than MIN_SWARM_SIZE, decommission that swarm.
    // Ensure there is always 1 swarm.

      while (swarm_to_mnodes.size() > 1)
      {
        auto it = std::find_if(swarm_to_mnodes.begin(),
                              swarm_to_mnodes.end(),
                              [](const swarm_mnode_map_t::value_type& pair) {
                                return pair.second.size() < MIN_SWARM_SIZE;
                              });
        if (it == swarm_to_mnodes.end())
          break;

        MWARNING("swarm " << it->first << " is DECOMMISSIONED");
        /// Good ol' switcheroo
        std::vector<crypto::public_key> decommissioned_mnodes;
        std::swap(decommissioned_mnodes, it->second);
        /// Remove swarm from map
        swarm_to_mnodes.erase(it);
        /// Assign mnodes to the 0 percentile, i.e. the smallest swarms
        assign_mnodes(decommissioned_mnodes, swarm_to_mnodes, mersenne_twister, DECOMMISSIONED_REDISTRIBUTION_LOWER_PERCENTILE);
      }

    /// print
    LOG_PRINT_L2("Swarm outputs:");
    for (const auto &entry : swarm_to_mnodes)
    {
      LOG_PRINT_L2(entry.first << ": " << entry.second.size());
    }
  }
}
