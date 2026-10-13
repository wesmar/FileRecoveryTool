// ============================================================================
// OverlapResolver.cpp - deleted files that claim the same clusters
// ============================================================================
// One sweep over the cluster ranges sorted by start, O(n log n): an interval
// is overwritten when an interval open at its start was written later, and
// it overwrites every open interval written earlier. Each interval is
// marked once, so the second rule costs no more than the sort.
// ============================================================================

#include "core/OverlapResolver.h"

#include <algorithm>
#include <queue>
#include <set>

namespace KVC {

size_t ResolveClusterOverlaps(std::vector<RecoveryCandidate>& candidates) {
    struct Interval {
        uint64_t start;
        uint64_t end;           // exclusive
        size_t owner;
    };
    std::vector<Interval> intervals;
    for (size_t i = 0; i < candidates.size(); ++i) {
        const auto& c = candidates[i];
        if (c.file.HasResidentData() || c.writeOrder == 0) continue;
        for (const auto& run : c.file.GetFragments().GetRuns()) {
            if (run.clusterCount) intervals.push_back({ run.startCluster, run.startCluster + run.clusterCount, i });
        }
    }
    std::sort(intervals.begin(), intervals.end(),
              [](const Interval& a, const Interval& b) { return a.start < b.start; });

    std::vector<bool> overwritten(candidates.size(), false);
    auto order = [&](size_t interval) { return candidates[intervals[interval].owner].writeOrder; };

    // open intervals: by end (to close them), by write order (to compare),
    // and those not yet found overwritten, by write order (to mark them)
    using Entry = std::pair<uint64_t, size_t>;
    std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>> byEnd;
    std::multiset<Entry> byOrder;
    std::set<Entry> unmarked;

    for (size_t k = 0; k < intervals.size(); ++k) {
        const Interval& cur = intervals[k];
        while (!byEnd.empty() && byEnd.top().first <= cur.start) {
            const size_t gone = byEnd.top().second;
            byEnd.pop();
            byOrder.erase(byOrder.find({ order(gone), gone }));
            unmarked.erase({ order(gone), gone });
        }
        const uint64_t mine = order(k);
        // a later write over this one
        if (!byOrder.empty() && std::prev(byOrder.end())->first > mine) {
            overwritten[cur.owner] = true;
        }
        // earlier writes this one covers
        while (!unmarked.empty() && unmarked.begin()->first < mine) {
            const size_t older = unmarked.begin()->second;
            if (intervals[older].owner != cur.owner) overwritten[intervals[older].owner] = true;
            unmarked.erase(unmarked.begin());
        }
        byEnd.push({ cur.end, k });
        byOrder.insert({ mine, k });
        if (!overwritten[cur.owner]) unmarked.insert({ mine, k });
    }

    size_t marked = 0;
    for (size_t i = 0; i < candidates.size(); ++i) {
        if (!overwritten[i]) continue;
        auto& c = candidates[i];
        if (c.quality == RecoveryQuality::Full) c.quality = RecoveryQuality::Partial;
        if (c.sizeFormatted.find(L"overwritten") == std::wstring::npos) {
            c.sizeFormatted += L" (overwritten by a newer file)";
        }
        ++marked;
    }
    return marked;
}

} // namespace KVC
