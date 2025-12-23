// ============================================================================
// VolumeGeometry.h - Volume Geometry and Addressing
// ============================================================================
// Encapsulates volume geometry and filesystem type definitions.
// Provides LCN to physical offset translation.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace KVC {

// ============================================================================
// FilesystemType - SINGLE DEFINITION (used project-wide)
// ============================================================================
enum class FilesystemType {
    NTFS,
    FAT32,
    ExFAT,
    Unknown
};

// ============================================================================
// VolumeGeometry - Physical volume layout
// ============================================================================
struct VolumeGeometry {
    uint64_t sectorSize;           // Bytes per sector (usually 512)
    uint64_t bytesPerCluster;      // Cluster size in bytes
    uint64_t totalClusters;        // Total clusters in volume
    uint64_t volumeStartOffset;    // Physical offset of volume on disk (bytes)
    FilesystemType fsType;
    
    // LCN = Logical Cluster Number (filesystem-specific addressing)
    // For NTFS: LCN 0 = first cluster of the volume (relative to volumeStartOffset)
    // For FAT32: LCN 0 = first data cluster (FAT cluster 2, relative to data region start)
    // For exFAT: LCN 0 = cluster heap start (relative to cluster heap offset)
    
    uint64_t SectorsPerCluster() const { 
        return bytesPerCluster / sectorSize; 
    }
    
    // Convert LCN â†’ physical disk offset
    uint64_t LCNToPhysicalOffset(uint64_t lcn) const {
        return volumeStartOffset + (lcn * bytesPerCluster);
    }
    
    // Convert physical disk offset â†’ LCN
    uint64_t PhysicalOffsetToLCN(uint64_t offset) const {
        if (offset < volumeStartOffset) return 0;
        return (offset - volumeStartOffset) / bytesPerCluster;
    }
    
    // Validate LCN is within bounds
    bool IsValidLCN(uint64_t lcn) const {
        return lcn < totalClusters;
    }
};

} // namespace KVC