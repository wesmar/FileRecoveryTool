// ============================================================================
// VolumeReader.h - Volume I/O Abstraction
// ============================================================================
// High-level volume I/O with unified LCN-based addressing.
// ============================================================================

#pragma once

#include "DiskHandle.h"
#include "VolumeGeometry.h"
#include "FragmentedFile.h"
#include "ForensicsExceptions.h"
#include <vector>
#include <optional>

namespace KVC {

class VolumeReader {
public:
    VolumeReader(DiskHandle& disk, const VolumeGeometry& geometry);
    ~VolumeReader();
    
    const VolumeGeometry& Geometry() const { return m_geometry; }
    DiskHandle& GetDiskHandle() { return m_disk; }
    
    // Read clusters by LCN (Logical Cluster Number)
    std::vector<uint8_t> ReadClusters(uint64_t startLCN, uint64_t count);
    std::vector<uint8_t> ReadClusterRun(const ClusterRun& run);
    
    // Memory-mapped read
    struct MappedView {
        const uint8_t* data;
        uint64_t size;
        uint64_t startLCN;
        bool valid;
        
        bool IsValid() const { return valid && data != nullptr; }
    };
    
    MappedView MapClusters(uint64_t startLCN, uint64_t count);
    void UnmapView(MappedView& view);
    bool ValidateClusterRange(uint64_t startLCN, uint64_t count);

private:
    DiskHandle& m_disk;
    VolumeGeometry m_geometry;
    DiskHandle::MappedRegion m_currentMapping;
    uint64_t m_mappedStartLCN;
    uint64_t m_mappedClusterCount;
};

} // namespace KVC