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

// Forward declaration
struct ClusterRange {
    uint64_t start;
    uint64_t count;
};

// ============================================================================
// ClusterRun - Single contiguous run of clusters
// ============================================================================

struct ClusterRun {
    uint64_t startCluster;
    uint64_t clusterCount;
    uint64_t fileOffset;
    
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
    
    uint64_t EndCluster() const { return startCluster + clusterCount; }
    bool ContainsCluster(uint64_t cluster) const {
        return cluster >= startCluster && cluster < EndCluster();
    }
    uint64_t ByteSize(uint64_t bytesPerCluster) const {
        return clusterCount * bytesPerCluster;
    }
    bool IsValid() const { return clusterCount > 0; }
    bool CanMergeWith(const ClusterRun& next, uint64_t bytesPerCluster) const {
        return (startCluster + clusterCount == next.startCluster) &&
               (fileOffset + ByteSize(bytesPerCluster) == next.fileOffset);
    }
};

// ============================================================================
// PhysicalLocation - Result of virtual-to-physical translation
// ============================================================================

struct PhysicalLocation {
    uint64_t cluster;
    uint64_t offsetInCluster;
    size_t runIndex;
    bool valid;
    
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

    // Construction
    void AddRun(uint64_t startCluster, uint64_t clusterCount);
    void AddRun(const ClusterRun& run);
    void BuildFromRanges(const std::vector<ClusterRange>& ranges);
    void BuildFromClusterList(const std::vector<uint64_t>& clusters);
    
    // Optimization
    void Coalesce();
    void SortByFileOffset();
    
    // Validation
    bool ValidateAgainstDisk(uint64_t maxCluster) const;
    bool HasOverlappingRuns() const;
    bool IsValid() const { return !m_runs.empty() && m_bytesPerCluster > 0; }
    bool IsContiguous() const { return m_runs.size() <= 1; }
    
    // Translation
    PhysicalLocation TranslateOffset(uint64_t fileOffset) const;
    std::optional<ClusterRun> GetRunForOffset(uint64_t fileOffset) const;
    
    // Accessors
    const std::vector<ClusterRun>& GetRuns() const { return m_runs; }
    std::vector<ClusterRun>& GetRuns() { return m_runs; }
    size_t RunCount() const { return m_runs.size(); }
    size_t FragmentCount() const { return m_runs.size(); }
    uint64_t TotalSize() const { return m_totalSize; }
    uint64_t BytesPerCluster() const { return m_bytesPerCluster; }
    void SetTotalSize(uint64_t size) { m_totalSize = size; }
    void SetBytesPerCluster(uint64_t bpc) { m_bytesPerCluster = bpc; }
    void SetDiskTotalClusters(uint64_t total) { m_diskTotalClusters = total; }
    uint64_t TotalClusters() const;
    uint64_t ContiguousBytesFrom(uint64_t fileOffset) const;
    void Clear() { m_runs.clear(); m_totalSize = 0; }
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

    // Construction
    void SetFileSize(uint64_t size) { m_fileSize = size; }
    void SetFragmentMap(const FragmentMap& map) { m_fragments = map; }
    void SetFragmentMap(FragmentMap&& map) { m_fragments = std::move(map); }
    void SetResidentData(const std::vector<uint8_t>& data);
    void SetResidentData(std::vector<uint8_t>&& data);
    
    // Translation
    PhysicalLocation TranslateOffset(uint64_t offset) const;
    std::optional<uint64_t> GetDiskOffset(uint64_t fileOffset, uint64_t sectorSize) const;
    
    // Accessors
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
    bool IsRecoverable() const { return m_isResident || !m_fragments.Empty(); }
    
    // Validation
    bool Validate(uint64_t maxCluster) const;

private:
    FragmentMap m_fragments;
    std::vector<uint8_t> m_residentData;
    uint64_t m_fileSize;
    bool m_isResident;
};

} // namespace KVC