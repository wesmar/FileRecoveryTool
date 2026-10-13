// ============================================================================
// ExFATScanner.h - exFAT deleted file scanner
// ============================================================================
// exFAT keeps a deleted file's directory entry set (InUse bit cleared) and,
// for a fragmented file, its FAT chain; only the allocation bitmap is
// cleared. So a deleted file is found whole: contiguous files (NoFatChain)
// from their first cluster and length, fragmented ones along the FAT - as
// long as the bitmap says nobody took the clusters since.
// ============================================================================

#pragma once

#include "core/DiskForensicsCore.h"
#include "io/VolumeReader.h"
#include <atomic>
#include <cstdint>
#include <deque>
#include <set>
#include <unordered_map>
#include <vector>

namespace KVC {

#pragma pack(push, 1)
struct ExFatBootSector {
    uint8_t jumpBoot[3];
    char oemName[8];
    uint8_t reserved1[53];
    uint64_t partitionOffset;
    uint64_t volumeLength;
    uint32_t fatOffset;
    uint32_t fatLength;
    uint32_t clusterHeapOffset;
    uint32_t clusterCount;
    uint32_t rootDirectoryCluster;
    uint32_t volumeSerialNumber;
    uint16_t fileSystemRevision;
    uint16_t volumeFlags;
    uint8_t bytesPerSectorShift;
    uint8_t sectorsPerClusterShift;
    uint8_t numberOfFats;
    uint8_t driveSelect;
    uint8_t percentInUse;
    uint8_t reserved2[7];
    uint8_t bootCode[390];
    uint16_t signature;
};
#pragma pack(pop)

class ExFATScanner {
public:
    ExFATScanner();
    ~ExFATScanner();

    // the clusters the allocation bitmap shows free, for carving
    FreeSpace FreeSpaceOf(DiskHandle& disk);

    bool ScanVolume(
        DiskHandle& disk,
        DiskForensicsCore::FileFoundCallback onFileFound,
        DiskForensicsCore::ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        const ScanConfiguration& config
    );

private:
    struct Stream {
        uint32_t firstCluster = 0;
        uint64_t dataLength = 0;
        uint64_t validDataLength = 0;
        bool noFatChain = false;
    };

    struct DirectoryWork {
        Stream stream;              // root: firstCluster only, FAT chain
        std::wstring path;
        bool deleted = false;
    };

    struct Volume {
        DiskHandle* disk = nullptr;
        VolumeReader* reader = nullptr;
        uint64_t sectorSize = 0;
        uint64_t clusterSize = 0;
        uint64_t heapOffsetBytes = 0;
        uint64_t fatOffsetBytes = 0;
        uint32_t clusterCount = 0;
        std::vector<uint8_t> bitmap;            // bit n: cluster n + 2 in use
        std::unordered_map<uint64_t, std::vector<uint8_t>> fatPages;
        std::deque<DirectoryWork> queue;
        std::set<uint32_t> visited;
        DiskForensicsCore::FileFoundCallback onFileFound;
        uint64_t filesFound = 0;
    };

    bool OpenVolume(DiskHandle& disk, Volume& v, VolumeGeometry& geom, uint32_t& rootCluster);
    bool IsCluster(const Volume& v, uint32_t c) const { return c >= 2 && c < v.clusterCount + 2; }
    bool InUse(const Volume& v, uint32_t c) const;
    uint32_t FatEntry(Volume& v, uint32_t cluster);

    // the clusters of a stream; for a deleted one, intact tells whether all
    // of them are still free
    std::vector<uint32_t> StreamClusters(Volume& v, const Stream& s, bool deleted, bool& intact);

    std::vector<uint8_t> ReadStream(Volume& v, const std::vector<uint32_t>& clusters, uint64_t limit);
    void ParseDirectory(Volume& v, const DirectoryWork& dir, const std::vector<uint8_t>& data);
    bool LoadBitmap(Volume& v, const std::vector<uint8_t>& rootData);
};

} // namespace KVC
