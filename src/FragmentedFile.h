// ============================================================================
// FragmentedFile.h - Fragmented File Abstraction
// ============================================================================
// Provides data structures and utilities for handling fragmented files.
// Maps virtual file offsets to physical disk locations across multiple
// non-contiguous cluster runs.
// ============================================================================

#pragma once

#include <vector>
#include <cstdint>
#include <optional>
#include <algorithm>

namespace KVC {

// ============================================================================
// ClusterRun - Single contiguous run of clusters
// ============================================================================
// Represents a fragment of a file stored in consecutive clusters on disk.
// fileOffset is the logical offset within the file where this run starts.

struct ClusterRun {
    uint64_t startCluster;      // First cluster (LCN) on disk
    uint64_t clusterCount;      // Number of consecutive clusters
    uint64_t fileOffset;        // Byte offset within the file
    
    ClusterRun() 
        : startCluster(0)
        , clusterCount(0)
        , fileOffset(0) 
    {}
    
    ClusterRun(uint64_t start, uint64_t count, uint64_t offset = 0)
        : startCluster(start)
        , clusterCount(count)
        , fileOffset(offset)
    {}
    
    // Calculate end cluster (exclusive)
    uint64_t EndCluster() const { return startCluster + clusterCount; }
    
    // Check if this run contains a specific cluster
    bool ContainsCluster(uint64_t cluster) const {
        return cluster >= startCluster && cluster < EndCluster();
    }
    
    // Get byte size of this run
    uint64_t ByteSize(uint64_t bytesPerCluster) const {
        return clusterCount * bytesPerCluster;
    }
    
    // Check if this run is valid
    bool IsValid() const {
        return clusterCount > 0;
    }
    
    // Check if two runs are adjacent and can be merged
    bool CanMergeWith(const ClusterRun& next, uint64_t bytesPerCluster) const {
        return (startCluster + clusterCount == next.startCluster) &&
               (fileOffset + ByteSize(bytesPerCluster) == next.fileOffset);
    }
};

// ============================================================================
// PhysicalLocation - Result of virtual-to-physical translation
// ============================================================================

struct PhysicalLocation {
    uint64_t cluster;           // Physical cluster number
    uint64_t offsetInCluster;   // Byte offset within the cluster
    size_t runIndex;            // Index of the run containing this location
    bool valid;                 // Whether translation succeeded
    
    PhysicalLocation()
        : cluster(0)
        , offsetInCluster(0)
        , runIndex(0)
        , valid(false)
    {}
    
    static PhysicalLocation Invalid() { return PhysicalLocation(); }
};

// ============================================================================
// FragmentMap - Collection of cluster runs forming a complete file
// ============================================================================

class FragmentMap {
public:
    FragmentMap() 
        : m_totalSize(0)
        , m_bytesPerCluster(4096)
        , m_diskTotalClusters(0)
    {}
    
    explicit FragmentMap(uint64_t bytesPerCluster)
        : m_totalSize(0)
        , m_bytesPerCluster(bytesPerCluster)
        , m_diskTotalClusters(0)
    {}
    
    FragmentMap(uint64_t bytesPerCluster, uint64_t diskTotalClusters)
        : m_totalSize(0)
        , m_bytesPerCluster(bytesPerCluster)
        , m_diskTotalClusters(diskTotalClusters)
    {}

    // ========================================================================
    // Construction
    // ========================================================================
    
    // Add a run to the map (automatically sets fileOffset)
    void AddRun(uint64_t startCluster, uint64_t clusterCount) {
        if (clusterCount == 0) return;
        ClusterRun run;
        run.startCluster = startCluster;
        run.clusterCount = clusterCount;
        run.fileOffset = m_totalSize;
        m_runs.push_back(run);
        m_totalSize += clusterCount * m_bytesPerCluster;
    }
    
    // Add a pre-configured run
    void AddRun(const ClusterRun& run) {
        if (run.clusterCount == 0) return;
        m_runs.push_back(run);
        uint64_t runEnd = run.fileOffset + run.clusterCount * m_bytesPerCluster;
        if (runEnd > m_totalSize) m_totalSize = runEnd;
    }
    
    // Build from legacy ClusterRange vector (assumes contiguous file offsets)
    void BuildFromRanges(const std::vector<ClusterRange>& ranges) {
        m_runs.clear();
        m_totalSize = 0;
        for (const auto& range : ranges) {
            AddRun(range.start, range.count);
        }
    }
    
    // Build from simple cluster list (assumes each cluster is one run)
    void BuildFromClusterList(const std::vector<uint64_t>& clusters) {
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
    
    // ========================================================================
    // Optimization
    // ========================================================================
    
    // Merge adjacent runs for better I/O performance
    void Coalesce() {
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
    
    // Sort runs by file offset (should normally already be sorted)
    void SortByFileOffset() {
        std::sort(m_runs.begin(), m_runs.end(),
            [](const ClusterRun& a, const ClusterRun& b) {
                return a.fileOffset < b.fileOffset;
            });
    }
    
    // ========================================================================
    // Validation
    // ========================================================================
    
    // Validate all runs are within disk bounds
    bool ValidateAgainstDisk(uint64_t maxCluster) const {
        for (const auto& run : m_runs) {
            if (run.startCluster >= maxCluster || run.EndCluster() > maxCluster) {
                return false;
            }
        }
        return true;
    }
    
    // Check for overlapping runs (indicates corruption)
    bool HasOverlappingRuns() const {
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
    
    // Check if map represents a valid file
    bool IsValid() const { return !m_runs.empty() && m_bytesPerCluster > 0; }
    
    // Check if file is contiguous (single run)
    bool IsContiguous() const { return m_runs.size() <= 1; }
    
    // ========================================================================
    // Translation
    // ========================================================================
    
    // Translate virtual file offset to physical disk location
    PhysicalLocation TranslateOffset(uint64_t fileOffset) const {
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
    std::optional<ClusterRun> GetRunForOffset(uint64_t fileOffset) const {
        auto loc = TranslateOffset(fileOffset);
        if (loc.valid && loc.runIndex < m_runs.size()) {
            return m_runs[loc.runIndex];
        }
        return std::nullopt;
    }
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    const std::vector<ClusterRun>& GetRuns() const { return m_runs; }
    std::vector<ClusterRun>& GetRuns() { return m_runs; }
    
    size_t RunCount() const { return m_runs.size(); }
    size_t FragmentCount() const { return m_runs.size(); }
    
    uint64_t TotalSize() const { return m_totalSize; }
    uint64_t BytesPerCluster() const { return m_bytesPerCluster; }
    
    void SetTotalSize(uint64_t size) { m_totalSize = size; }
    void SetBytesPerCluster(uint64_t bpc) { m_bytesPerCluster = bpc; }
    void SetDiskTotalClusters(uint64_t total) { m_diskTotalClusters = total; }
    
    uint64_t TotalClusters() const {
        uint64_t total = 0;
        for (const auto& run : m_runs) {
            total += run.clusterCount;
        }
        return total;
    }
    
    // Get contiguous read size from a given offset
    uint64_t ContiguousBytesFrom(uint64_t fileOffset) const {
        auto loc = TranslateOffset(fileOffset);
        if (!loc.valid || loc.runIndex >= m_runs.size()) {
            return 0;
        }
        const auto& run = m_runs[loc.runIndex];
        uint64_t runEnd = run.fileOffset + run.clusterCount * m_bytesPerCluster;
        return runEnd - fileOffset;
    }
    
    // Clear all runs
    void Clear() {
        m_runs.clear();
        m_totalSize = 0;
    }
    
    bool Empty() const { return m_runs.empty(); }
    bool IsEmpty() const { return m_runs.empty(); }

private:
    std::vector<ClusterRun> m_runs;
    uint64_t m_totalSize;
    uint64_t m_bytesPerCluster;
    uint64_t m_diskTotalClusters;
};

// ============================================================================
// FragmentedFile - High-level fragmented file representation
// ============================================================================

class FragmentedFile {
public:
    FragmentedFile()
        : m_fileSize(0)
        , m_isResident(false)
    {}
    
    FragmentedFile(uint64_t fileSize, uint64_t bytesPerCluster)
        : m_fragments(bytesPerCluster)
        , m_fileSize(fileSize)
        , m_isResident(false)
    {}

    // ========================================================================
    // Construction
    // ========================================================================
    
    void SetFileSize(uint64_t size) { m_fileSize = size; }
    void SetFragmentMap(const FragmentMap& map) { m_fragments = map; }
    void SetFragmentMap(FragmentMap&& map) { m_fragments = std::move(map); }
    
    void SetResidentData(const std::vector<uint8_t>& data) {
        m_residentData = data;
        m_isResident = true;
        m_fileSize = data.size();
    }
    
    void SetResidentData(std::vector<uint8_t>&& data) {
        m_fileSize = data.size();
        m_residentData = std::move(data);
        m_isResident = true;
    }
    
    // ========================================================================
    // Translation
    // ========================================================================
    
    // Translate file offset to physical location
    PhysicalLocation TranslateOffset(uint64_t offset) const {
        if (m_isResident) {
            return PhysicalLocation::Invalid();
        }
        return m_fragments.TranslateOffset(offset);
    }
    
    // Get physical disk offset for a given file offset
    std::optional<uint64_t> GetDiskOffset(uint64_t fileOffset, uint64_t sectorSize) const {
        auto loc = TranslateOffset(fileOffset);
        if (!loc.valid) return std::nullopt;
        uint64_t bytesPerCluster = m_fragments.BytesPerCluster();
        uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
        return loc.cluster * sectorsPerCluster * sectorSize + loc.offsetInCluster;
    }
    
    // ========================================================================
    // Accessors
    // ========================================================================
    
    uint64_t FileSize() const { return m_fileSize; }
    uint64_t GetSize() const { return m_fileSize; }
    bool IsResident() const { return m_isResident; }
    bool HasResidentData() const { return m_isResident; }
    bool IsFragmented() const { return m_fragments.RunCount() > 1; }
    size_t FragmentCount() const { return m_fragments.RunCount(); }
    
    const FragmentMap& Fragments() const { return m_fragments; }
    const FragmentMap& GetFragments() const { return m_fragments; }
    FragmentMap& Fragments() { return m_fragments; }
    
    const std::vector<uint8_t>& ResidentData() const { return m_residentData; }
    const std::vector<uint8_t>& GetResidentData() const { return m_residentData; }
    
    bool IsRecoverable() const {
        return m_isResident || !m_fragments.Empty();
    }
    
    // ========================================================================
    // Validation
    // ========================================================================
    
    bool Validate(uint64_t maxCluster) const {
        if (m_isResident) return true;
        return m_fragments.ValidateAgainstDisk(maxCluster);
    }

private:
    FragmentMap m_fragments;
    std::vector<uint8_t> m_residentData;
    uint64_t m_fileSize;
    bool m_isResident;
};

} // namespace KVC