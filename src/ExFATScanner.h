// ============================================================================
// ExFATScanner.h - ExFAT Filesystem Scanner
// ============================================================================
// Implements logical scanning for exFAT volumes.
// Traverses directory structure and uses FAT chain reading for accuracy.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "Constants.h"
#include "StringUtils.h"
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

struct ExFatEntryHeader {
    uint8_t entryType;
    uint8_t data[31];
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
    uint8_t entryType;           // Offset 0
    uint8_t secondaryFlags;      // Offset 1
    uint8_t reserved1;           // Offset 2
    uint8_t nameLength;          // Offset 3
    uint16_t nameHash;           // Offset 4-5
    uint16_t reserved2;          // Offset 6-7
    uint64_t validDataLength;    // Offset 8-15
    uint32_t reserved3;          // Offset 16-19 (FIXED: was uint64_t)
    uint32_t firstCluster;       // Offset 20-23
    uint64_t dataLength;         // Offset 24-31
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
        std::wstring folderFilter;
        std::wstring filenameFilter;
    };

    struct DirectoryWorkItem {
        uint32_t firstCluster;
        std::wstring path;
    };

    ExFatBootSector ReadBootSector(DiskHandle& disk);
    
    void ProcessDirectory(
        DiskHandle& disk, 
        const DirectoryWorkItem& dirItem,
        std::deque<DirectoryWorkItem>& subDirs,
        DiskForensicsCore::FileFoundCallback onFileFound,
        const ScanContext& context,
        bool& shouldStop
    );

    std::vector<uint8_t> ReadClusterChain(
        DiskHandle& disk, 
        uint32_t startCluster, 
        const ScanContext& context,
        bool& shouldStop,
        uint64_t limitBytes = 0
    );

    std::optional<uint32_t> ReadFATEntry(
        DiskHandle& disk,
        const ScanContext& context,
        uint32_t cluster
    );

    std::vector<uint32_t> FollowFATChain(
        DiskHandle& disk,
        const ScanContext& context,
        uint32_t startCluster,
        size_t maxClusters
    );

    std::wstring FormatFileSize(uint64_t bytes);
};

} // namespace KVC
