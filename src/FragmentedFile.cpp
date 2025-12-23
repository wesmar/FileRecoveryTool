// ============================================================================
// FragmentedFile.cpp - Fragmented File Abstraction Implementation
// ============================================================================

#include "FragmentedFile.h"
#include <algorithm>

namespace KVC {

// ============================================================================
// FragmentMap Implementation
// ============================================================================

// Add a new run at the end of the fragment list
void FragmentMap::AddRun(uint64_t startCluster, uint64_t clusterCount) {
    if (clusterCount == 0) return;
    ClusterRun run;
    run.startCluster = startCluster;
    run.clusterCount = clusterCount;
    run.fileOffset = m_totalSize;
    m_runs.push_back(run);
    m_totalSize += clusterCount * m_bytesPerCluster;
}

// Add a pre-configured run
void FragmentMap::AddRun(const ClusterRun& run) {
    if (run.clusterCount == 0) return;
    m_runs.push_back(run);
    uint64_t runEnd = run.fileOffset + run.clusterCount * m_bytesPerCluster;
    if (runEnd > m_totalSize) m_totalSize = runEnd;
}

// Build from legacy ClusterRange vector (assumes contiguous file offsets)
void FragmentMap::BuildFromRanges(const std::vector<ClusterRange>& ranges) {
    m_runs.clear();
    m_totalSize = 0;
    for (const auto& range : ranges) {
        AddRun(range.start, range.count);
    }
}

// Build from simple cluster list (coalesces consecutive clusters)
void FragmentMap::BuildFromClusterList(const std::vector<uint64_t>& clusters) {
    m_runs.clear();
    m_totalSize = 0;
    if (clusters.empty()) return;
    
    // Coalesce consecutive clusters into runs
    uint64_t runStart = clusters[0];
    uint64_t runCount = 1;
    for (size_t i = 1; i < clusters.size(); ++i) {
        if (clusters[i] == runStart + runCount) {
            runCount++;
        } else {
            AddRun(runStart, runCount);
            runStart = clusters[i];
            runCount = 1;
        }
    }
    AddRun(runStart, runCount);
}

// Merge adjacent runs for better I/O performance
void FragmentMap::Coalesce() {
    if (m_runs.size() < 2) return;
    std::vector<ClusterRun> merged;
    merged.reserve(m_runs.size());
    ClusterRun current = m_runs[0];
    for (size_t i = 1; i < m_runs.size(); ++i) {
        if (current.CanMergeWith(m_runs[i], m_bytesPerCluster)) {
            current.clusterCount += m_runs[i].clusterCount;
        } else {
            merged.push_back(current);
            current = m_runs[i];
        }
    }
    merged.push_back(current);
    m_runs = std::move(merged);
}

// Sort runs by file offset
void FragmentMap::SortByFileOffset() {
    std::sort(m_runs.begin(), m_runs.end(),
        [](const ClusterRun& a, const ClusterRun& b) {
            return a.fileOffset < b.fileOffset;
        });
}

// Validate all runs are within disk bounds
bool FragmentMap::ValidateAgainstDisk(uint64_t maxCluster) const {
    for (const auto& run : m_runs) {
        if (run.startCluster >= maxCluster || run.EndCluster() > maxCluster) {
            return false;
        }
    }
    return true;
}

// Check for overlapping runs (indicates corruption)
bool FragmentMap::HasOverlappingRuns() const {
    for (size_t i = 0; i < m_runs.size(); ++i) {
        for (size_t j = i + 1; j < m_runs.size(); ++j) {
            uint64_t endI = m_runs[i].fileOffset + m_runs[i].clusterCount * m_bytesPerCluster;
            uint64_t startJ = m_runs[j].fileOffset;
            if (m_runs[i].fileOffset < startJ + m_runs[j].clusterCount * m_bytesPerCluster && endI > startJ) {
                return true;
            }
        }
    }
    return false;
}

// Translate virtual file offset to physical disk location
PhysicalLocation FragmentMap::TranslateOffset(uint64_t fileOffset) const {
    if (m_runs.empty() || m_bytesPerCluster == 0) {
        return PhysicalLocation::Invalid();
    }
    
    // Binary search for the run containing this offset
    size_t left = 0;
    size_t right = m_runs.size();
    while (left < right) {
        size_t mid = left + (right - left) / 2;
        uint64_t runEnd = m_runs[mid].fileOffset + m_runs[mid].clusterCount * m_bytesPerCluster;
        if (fileOffset < m_runs[mid].fileOffset) {
            right = mid;
        } else if (fileOffset >= runEnd) {
            left = mid + 1;
        } else {
            PhysicalLocation loc;
            uint64_t offsetInRun = fileOffset - m_runs[mid].fileOffset;
            loc.cluster = m_runs[mid].startCluster + (offsetInRun / m_bytesPerCluster);
            loc.offsetInCluster = offsetInRun % m_bytesPerCluster;
            loc.runIndex = mid;
            loc.valid = true;
            return loc;
        }
    }
    return PhysicalLocation::Invalid();
}

// Get the run containing a specific file offset
std::optional<ClusterRun> FragmentMap::GetRunForOffset(uint64_t fileOffset) const {
    auto loc = TranslateOffset(fileOffset);
    if (loc.valid && loc.runIndex < m_runs.size()) {
        return m_runs[loc.runIndex];
    }
    return std::nullopt;
}

// Get total cluster count across all runs
uint64_t FragmentMap::TotalClusters() const {
    uint64_t total = 0;
    for (const auto& run : m_runs) {
        total += run.clusterCount;
    }
    return total;
}

// Get contiguous read size from a given offset
uint64_t FragmentMap::ContiguousBytesFrom(uint64_t fileOffset) const {
    auto loc = TranslateOffset(fileOffset);
    if (!loc.valid || loc.runIndex >= m_runs.size()) {
        return 0;
    }
    const auto& run = m_runs[loc.runIndex];
    uint64_t runEnd = run.fileOffset + run.clusterCount * m_bytesPerCluster;
    return runEnd - fileOffset;
}

// ============================================================================
// FragmentedFile Implementation
// ============================================================================

// Set resident data (copy)
void FragmentedFile::SetResidentData(const std::vector<uint8_t>& data) {
    m_residentData = data;
    m_isResident = true;
    m_fileSize = data.size();
}

// Set resident data (move)
void FragmentedFile::SetResidentData(std::vector<uint8_t>&& data) {
    m_fileSize = data.size();
    m_residentData = std::move(data);
    m_isResident = true;
}

// Translate file offset to physical location
PhysicalLocation FragmentedFile::TranslateOffset(uint64_t offset) const {
    if (m_isResident) {
        return PhysicalLocation::Invalid();
    }
    return m_fragments.TranslateOffset(offset);
}

// Get physical disk offset for a given file offset
std::optional<uint64_t> FragmentedFile::GetDiskOffset(uint64_t fileOffset, uint64_t sectorSize) const {
    auto loc = TranslateOffset(fileOffset);
    if (!loc.valid) return std::nullopt;
    uint64_t bytesPerCluster = m_fragments.BytesPerCluster();
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
    return loc.cluster * sectorsPerCluster * sectorSize + loc.offsetInCluster;
}

// Validate fragment map against disk geometry
bool FragmentedFile::Validate(uint64_t maxCluster) const {
    if (m_isResident) return true;
    return m_fragments.ValidateAgainstDisk(maxCluster);
}

} // namespace KVC
