// ============================================================================
// FilesystemDetector.h - What file system a volume holds, from its sectors
// ============================================================================
// The volume's own structures decide, not the mounted driver: a volume that
// Windows shows as RAW (a Linux partition, a damaged boot sector's neighbour)
// is recognised all the same.
// ============================================================================

#pragma once

#include "io/DiskHandle.h"
#include "core/VolumeGeometry.h"
#include <cstdint>
#include <optional>
#include <string>

namespace KVC {

// The layout of a FAT12/16/32 volume, computed as the Microsoft FAT
// specification computes it: the type follows from the cluster count alone.
struct FatLayout {
    FilesystemType type = FilesystemType::Unknown;
    uint32_t bytesPerSector = 0;
    uint32_t sectorsPerCluster = 0;
    uint32_t clusterSize = 0;
    uint32_t numberOfFats = 0;
    uint64_t fatStartSector = 0;
    uint64_t fatSectors = 0;          // one FAT
    uint64_t rootDirStartSector = 0;  // FAT12/16: the fixed root directory
    uint64_t rootDirSectors = 0;
    uint64_t dataStartSector = 0;     // cluster 2
    uint32_t clusterCount = 0;        // data clusters: 2 .. clusterCount + 1
    uint32_t rootCluster = 0;         // FAT32 only

    uint64_t ClusterOffset(uint32_t cluster) const {
        return (dataStartSector + static_cast<uint64_t>(cluster - 2) * sectorsPerCluster) * bytesPerSector;
    }
};

std::optional<FatLayout> ParseFatBootSector(const uint8_t* sector, size_t size);

struct VolumeInfo {
    FilesystemType type = FilesystemType::Unknown;
    std::wstring name;                // "NTFS", "FAT32", "ext4" ...
    uint64_t size = 0;                // bytes
};

VolumeInfo DetectFilesystem(DiskHandle& disk);

const wchar_t* FilesystemName(FilesystemType type);

} // namespace KVC
