// ============================================================================
// FAT32Scanner.h - FAT32 Filesystem Scanner
// ============================================================================
// Implements logical scanning for FAT32 volumes.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "VolumeReader.h"
#include "Constants.h"
#include <vector>
#include <deque>

namespace KVC {

#pragma pack(push, 1)
struct FAT32BootSector {
    uint8_t jumpBoot[3];
    char oemName[8];
    uint16_t bytesPerSector;
    uint8_t sectorsPerCluster;
    uint16_t reservedSectors;
    uint8_t numberOfFATs;
    uint16_t rootEntryCount;
    uint16_t totalSectors16;
    uint8_t media;
    uint16_t fatSize16;
    uint16_t sectorsPerTrack;
    uint16_t numberOfHeads;
    uint32_t hiddenSectors;
    uint32_t totalSectors32;
    uint32_t fatSize32;
    uint16_t extFlags;
    uint16_t fsVersion;
    uint32_t rootCluster;
    uint16_t fsInfo;
    uint16_t backupBootSector;
    uint8_t reserved[12];
    uint8_t driveNumber;
    uint8_t reserved1;
    uint8_t bootSignature;
    uint32_t volumeID;
    char volumeLabel[11];
    char fsType[8];
    uint8_t bootCode[420];
    uint16_t signature;
};

struct FATDirEntry {
    uint8_t name[11];
    uint8_t attr;
    uint8_t lcase;
    uint8_t ctimeMs;
    uint16_t ctime;
    uint16_t cdate;
    uint16_t adate;
    uint16_t clusterHigh;
    uint16_t mtime;
    uint16_t mdate;
    uint16_t clusterLow;
    uint32_t fileSize;
};

struct FATLFNEntry {
    uint8_t sequenceNo;
    uint16_t name1[5];
    uint8_t attr;
    uint8_t type;
    uint8_t checksum;
    uint16_t name2[6];
    uint16_t firstCluster;
    uint16_t name3[2];
};
#pragma pack(pop)

class FAT32Scanner {
public:
    FAT32Scanner();
    ~FAT32Scanner();

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
        uint64_t dataStartSector;
        uint32_t rootCluster;
        uint64_t clusterSize;
        uint64_t volumeStartOffset;
        std::wstring folderFilter;
        std::wstring filenameFilter;
    };

    struct DirectoryWorkItem {
        uint32_t firstCluster;
        std::wstring path;
    };

    FAT32BootSector ReadBootSector(DiskHandle& disk);
    
    // FIXED: VolumeReader& instead of DiskHandle&
    void ProcessDirectory(
        VolumeReader& reader,
        const DirectoryWorkItem& dirItem,
        std::deque<DirectoryWorkItem>& subDirs,
        DiskForensicsCore::FileFoundCallback onFileFound,
        const ScanContext& context
    );

    std::vector<uint8_t> ReadClusterChain(
        VolumeReader& reader,
        uint32_t startCluster,
        const ScanContext& context,
        uint64_t limitBytes = 0
    );

    std::wstring ParseShortName(const uint8_t* name);
    std::wstring FormatFileSize(uint64_t bytes);
};

} // namespace KVC