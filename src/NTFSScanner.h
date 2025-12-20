// ============================================================================
// NTFSScanner.h - NTFS Filesystem Scanner
// ============================================================================
// Implements NTFS-specific scanning by parsing the Master File Table (MFT).
// Identifies deleted files by examining MFT records with FILE_NAME and DATA
// attributes. Handles both resident (small) and non-resident (large) files.
// Enhanced with robust NTFS data run parsing and validation.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "FragmentedFile.h"
#include "ForensicsExceptions.h"
#include "Constants.h"
#include "StringUtils.h"
#include <map>
#include <vector>
#include <optional>

namespace KVC {

#pragma pack(push, 1)
struct NTFSBootSector {
    uint8_t jmpBoot[3];
    char oemID[8];
    uint16_t bytesPerSector;
    uint8_t sectorsPerCluster;
    uint8_t reserved1[7];
    uint8_t mediaDescriptor;
    uint16_t reserved2;
    uint16_t sectorsPerTrack;
    uint16_t numberOfHeads;
    uint32_t hiddenSectors;
    uint32_t reserved3;
    uint32_t reserved4;
    uint64_t totalSectors;
    uint64_t mftCluster;
    uint64_t mftMirrorCluster;
    int8_t clustersPerMFTRecord;
    uint8_t reserved5[3];
    int8_t clustersPerIndexBuffer;
    uint8_t reserved6[3];
    uint64_t volumeSerialNumber;
    uint32_t checksum;
};

struct MFTFileRecord {
    char signature[4];
    uint16_t updateSequenceOffset;
    uint16_t updateSequenceSize;
    uint64_t logFileSequenceNumber;
    uint16_t sequenceNumber;
    uint16_t hardLinkCount;
    uint16_t firstAttributeOffset;
    uint16_t flags;
    uint32_t usedSize;
    uint32_t allocatedSize;
    uint64_t baseFileRecord;
    uint16_t nextAttributeID;
};

struct AttributeHeader {
    uint32_t type;
    uint32_t length;
    uint8_t nonResident;
    uint8_t nameLength;
    uint16_t nameOffset;
    uint16_t flags;
    uint16_t attributeID;
};

struct ResidentAttributeHeader {
    uint32_t type;
    uint32_t length;
    uint8_t nonResident;
    uint8_t nameLength;
    uint16_t nameOffset;
    uint16_t flags;
    uint16_t attributeID;
    uint32_t valueLength;
    uint16_t valueOffset;
    uint8_t indexedFlag;
    uint8_t padding;
};

struct NonResidentAttributeHeader {
    uint32_t type;
    uint32_t length;
    uint8_t nonResident;
    uint8_t nameLength;
    uint16_t nameOffset;
    uint16_t flags;
    uint16_t attributeID;
    uint64_t startVCN;
    uint64_t endVCN;
    uint16_t dataRunOffset;
    uint16_t compressionUnit;
    uint32_t padding;
    uint64_t allocatedSize;
    uint64_t realSize;
    uint64_t initializedSize;
};

struct FileNameAttribute {
    uint64_t parentDirectory;
    uint64_t creationTime;
    uint64_t modificationTime;
    uint64_t mftModificationTime;
    uint64_t accessTime;
    uint64_t allocatedSize;
    uint64_t realSize;
    uint32_t flags;
    uint32_t reparseValue;
    uint8_t nameLength;
    uint8_t nameType;
    wchar_t name[1];
};
#pragma pack(pop)

// ============================================================================
// NTFSDataRunParser - Robust NTFS data run decoding
// ============================================================================

class NTFSDataRunParser {
public:
    struct ParseResult {
        std::vector<ClusterRun> runs;
        uint64_t totalClusters;
        uint64_t totalBytes;
        bool valid;
        std::string errorMessage;
        
        ParseResult() : totalClusters(0), totalBytes(0), valid(false) {}
    };
    
    // Parse data runs from raw attribute data
    // Returns ClusterRun vector with proper file offsets
    static ParseResult Parse(
        const uint8_t* runData,
        size_t maxSize,
        uint64_t bytesPerCluster,
        uint64_t maxClusterNumber = 0  // 0 = no validation
    );
    
    // Validate a set of runs against disk geometry
    static bool ValidateRuns(
        const std::vector<ClusterRun>& runs,
        uint64_t maxClusterNumber,
        std::string* errorOut = nullptr
    );

private:
    // Read variable-length integer from data run encoding
    static uint64_t ReadVarInt(const uint8_t* data, uint8_t numBytes);
    
    // Read signed variable-length integer (for LCN offsets)
    static int64_t ReadSignedVarInt(const uint8_t* data, uint8_t numBytes);
};

// ============================================================================
// NTFSScanner
// ============================================================================

class NTFSScanner {
public:
    NTFSScanner();
    ~NTFSScanner();

    bool ScanVolume(
        DiskHandle& disk,
        const std::wstring& folderFilter,
        const std::wstring& filenameFilter,
        DiskForensicsCore::FileFoundCallback onFileFound,
        DiskForensicsCore::ProgressCallback onProgress,
        bool& shouldStop,
        const ScanConfiguration& config
    );

    NTFSBootSector ReadBootSector(DiskHandle& disk);
    std::vector<uint8_t> ReadMFTRecord(DiskHandle& disk, const NTFSBootSector& boot, uint64_t recordNum);
    bool ParseMFTRecord(const std::vector<uint8_t>& data, uint64_t recordNum,
        DiskForensicsCore::FileFoundCallback& callback, DiskHandle& disk, const NTFSBootSector& boot,
        const std::wstring& folderFilter, const std::wstring& filenameFilter);
    
    // NEW: Parse MFT record into FragmentedFile structure
    std::optional<FragmentedFile> ParseMFTRecordToFragmentedFile(
        const std::vector<uint8_t>& data,
        uint64_t recordNum,
        const NTFSBootSector& boot
    );

private:
    // Legacy interface for compatibility
    std::vector<ClusterRange> ParseDataRuns(const uint8_t* runData, size_t maxSize, uint64_t bytesPerCluster = 4096);
    
    // NEW: Enhanced data run parsing with validation
    NTFSDataRunParser::ParseResult ParseDataRunsEnhanced(
        const uint8_t* runData,
        size_t maxSize,
        uint64_t bytesPerCluster,
        uint64_t maxCluster
    );
    
    std::wstring ReconstructPath(DiskHandle& disk, const NTFSBootSector& boot, 
                              uint64_t mftRecord, const std::wstring& filename);
    bool ApplyFixups(std::vector<uint8_t>& recordData, uint16_t bytesPerSector);

    std::map<uint64_t, std::wstring> m_pathCache;
    uint64_t m_diskTotalClusters;  // For validation
};

} // namespace KVC
