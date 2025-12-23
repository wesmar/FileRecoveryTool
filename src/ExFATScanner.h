// ============================================================================
// ExFATScanner.h - ExFAT Filesystem Scanner
// ============================================================================
// Implements logical scanning for exFAT volumes.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "VolumeReader.h"
#include "Constants.h"
#include <vector>
#include <cstdint>
#include <deque>
#include <optional>

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

struct ExFatFileEntry {
    uint8_t entryType;
    uint8_t secondaryCount;
    uint16_t setChecksum;
    uint16_t fileAttributes;
    uint16_t reserved1;
    uint32_t createTimestamp;
    uint32_t lastModifiedTimestamp;
    uint32_t lastAccessedTimestamp;
    uint8_t create10msIncrement;
    uint8_t lastModified10msIncrement;
    uint8_t createTimezone;
    uint8_t lastModifiedTimezone;
    uint8_t lastAccessedTimezone;
    uint8_t reserved2[7];
};

struct ExFatStreamEntry {
    uint8_t entryType;
    uint8_t secondaryFlags;
    uint8_t reserved1;
    uint8_t nameLength;
    uint16_t nameHash;
    uint16_t reserved2;
    uint64_t validDataLength;
    uint32_t reserved3;
    uint32_t firstCluster;
    uint64_t dataLength;
};

struct ExFatNameEntry {
    uint8_t entryType;
    uint8_t reserved;
    wchar_t fileName[15];
};
#pragma pack(pop)

class ExFATScanner {
public:
    ExFATScanner();
    ~ExFATScanner();

    bool ScanVolume(
        DiskHandle& disk,
        const std::wstring& folderFilter,
        const std::wstring& filenameFilter,
        DiskForensicsCore::FileFoundCallback onFileFound,
        DiskForensicsCore::ProgressCallback onProgress,
        bool& shouldStop,
        const ScanConfiguration& config
    );

private:
    struct ScanContext {
        uint64_t sectorSize;
        uint64_t sectorsPerCluster;
        uint64_t clusterHeapOffset;
        uint32_t rootDirCluster;
        uint32_t fatOffset;
        uint32_t fatLength;
        uint64_t volumeStartOffset;
        std::wstring folderFilter;
        std::wstring filenameFilter;
    };

    struct DirectoryWorkItem {
        uint32_t firstCluster;
        std::wstring path;
    };

    ExFatBootSector ReadBootSector(DiskHandle& disk);
    
    // FIXED: VolumeReader& instead of DiskHandle&
    void ProcessDirectory(
        VolumeReader& reader,
        const DirectoryWorkItem& dirItem,
        std::deque<DirectoryWorkItem>& subDirs,
        DiskForensicsCore::FileFoundCallback onFileFound,
        const ScanContext& context,
        bool& shouldStop
    );

    std::vector<uint8_t> ReadClusterChain(
        VolumeReader& reader,
        uint32_t startCluster,
        const ScanContext& context,
        bool& shouldStop,
        uint64_t limitBytes = 0
    );

    std::optional<uint32_t> ReadFATEntry(
        VolumeReader& reader,
        const ScanContext& context,
        uint32_t cluster
    );

    std::vector<uint32_t> FollowFATChain(
        VolumeReader& reader,
        const ScanContext& context,
        uint32_t startCluster,
        size_t maxClusters
    );

    std::wstring FormatFileSize(uint64_t bytes);
};

} // namespace KVC