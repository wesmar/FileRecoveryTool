// ============================================================================
// FAT32Scanner.h - FAT32 Filesystem Scanner
// ============================================================================
// Implements logical scanning for FAT32 volumes (common on USB drives, SD cards).
// Handles Long File Name (LFN) entries which precede standard 8.3 entries.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
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
    uint16_t rootEntryCount;     // Must be 0 for FAT32
    uint16_t totalSectors16;     // Must be 0 for FAT32
    uint8_t media;
    uint16_t fatSize16;          // Must be 0 for FAT32
    uint16_t sectorsPerTrack;
    uint16_t numberOfHeads;
    uint32_t hiddenSectors;
    uint32_t totalSectors32;
    // FAT32 specific fields
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
    uint16_t signature;          // Should be 0xAA55
};

// Standard 8.3 directory entry
struct FATDirEntry {
    uint8_t name[11];            // 8.3 format: 0xE5 = deleted, 0x00 = end
    uint8_t attr;                // 0x0F = LFN entry
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

// Long File Name entry (appears before standard entry)
struct FATLFNEntry {
    uint8_t sequenceNo;          // Sequence number (0x40 bit = last entry)
    uint16_t name1[5];           // First 5 characters (UTF-16)
    uint8_t attr;                // Must be 0x0F
    uint8_t type;                // Always 0
    uint8_t checksum;            // Checksum of short name
    uint16_t name2[6];           // Next 6 characters (UTF-16)
    uint16_t firstCluster;       // Must be 0
    uint16_t name3[2];           // Last 2 characters (UTF-16)
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
        std::wstring folderFilter;
        std::wstring filenameFilter;
    };

    struct DirectoryWorkItem {
        uint32_t firstCluster;
        std::wstring path;
    };

    FAT32BootSector ReadBootSector(DiskHandle& disk);
    
    void ProcessDirectory(
        DiskHandle& disk, 
        const DirectoryWorkItem& dirItem,
        std::deque<DirectoryWorkItem>& subDirs,
        DiskForensicsCore::FileFoundCallback onFileFound,
        const ScanContext& context
    );

    std::vector<uint8_t> ReadClusterChain(
        DiskHandle& disk, 
        uint32_t startCluster, 
        const ScanContext& context,
        uint64_t limitBytes = 0
    );

    std::wstring ParseShortName(const uint8_t* name);
    std::wstring FormatFileSize(uint64_t bytes);
};

} // namespace KVC
