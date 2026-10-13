// ============================================================================
// NTFSScanner.h - NTFS deleted file scanner
// ============================================================================
// Reads the MFT along $MFT's own run list (the MFT is rarely in one piece),
// and reports every file record no longer in use with its unnamed $DATA
// stream: resident bytes, or the run list gathered from the base record and
// - through $ATTRIBUTE_LIST - its extension records, holes and compression
// kept. $Bitmap tells the clusters that were taken again since.
// ============================================================================

#pragma once

#include <climits>
#include "core/DiskForensicsCore.h"
#include "core/FragmentedFile.h"
#include "support/ForensicsExceptions.h"
#include "support/Constants.h"
#include "support/StringUtils.h"
#include <atomic>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

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
#pragma pack(pop)

// One attribute of a file record, decoded
struct NtfsAttribute {
    uint32_t type = 0;
    std::wstring name;
    uint16_t flags = 0;                 // 0x0001 compressed, 0x4000 encrypted, 0x8000 sparse
    bool nonResident = false;
    std::vector<uint8_t> value;         // resident
    uint64_t startVcn = 0;              // non-resident
    uint64_t endVcn = 0;
    uint16_t compressionUnit = 0;       // log2 of clusters per unit
    uint64_t allocatedSize = 0;
    uint64_t realSize = 0;
    uint64_t initializedSize = 0;
    std::vector<ClusterRun> runs;       // fileOffset = VCN * cluster size; holes absent
    bool runsValid = true;
};

struct NtfsRecord {
    uint16_t flags = 0;                 // 0x0001 in use, 0x0002 directory
    uint16_t sequence = 0;
    uint64_t lsn = 0;                   // $LogFile sequence number of its last change
    uint64_t baseRecord = 0;            // non-zero: an extension record
    uint16_t baseSequence = 0;
    std::vector<NtfsAttribute> attributes;
};

class NTFSScanner {
public:
    NTFSScanner();
    ~NTFSScanner();

    // the boot sector, $MFT's run list and $Bitmap; ScanVolume calls it
    bool Open(DiskHandle& disk);

    bool ScanVolume(
        DiskHandle& disk,
        const std::wstring& folderFilter,
        const std::wstring& filenameFilter,
        DiskForensicsCore::FileFoundCallback onFileFound,
        DiskForensicsCore::ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        const ScanConfiguration& config
    );

    NTFSBootSector ReadBootSector(DiskHandle& disk);

    // one record, fixed up; empty when it cannot be read
    std::vector<uint8_t> ReadMFTRecord(DiskHandle& disk, const NTFSBootSector& boot, uint64_t recordNum);

    // reports the record through callback when it is a deleted file
    bool ParseMFTRecord(const std::vector<uint8_t>& data, uint64_t recordNum,
        DiskForensicsCore::FileFoundCallback& callback, DiskHandle& disk, const NTFSBootSector& boot,
        const std::wstring& folderFilter, const std::wstring& filenameFilter);

    // $Extend\$UsnJrnl, found by name
    std::optional<uint64_t> FindUsnJournal(DiskHandle& disk);

    // a named stream's runs (attribute list included) and its real size
    std::vector<ClusterRun> StreamRuns(DiskHandle& disk, uint64_t record, const std::wstring& stream, uint64_t& realSize);

    uint64_t ClusterSize() const { return m_clusterSize; }

    // the clusters $Bitmap shows free, for carving
    FreeSpace FreeSpaceOf(DiskHandle& disk);

private:
    bool DecodeRecord(const std::vector<uint8_t>& raw, NtfsRecord& out) const;
    bool ApplyFixups(std::vector<uint8_t>& record) const;
    std::vector<ClusterRun> DecodeRuns(const uint8_t* data, size_t size, uint64_t startVcn, bool& valid) const;

    // the unnamed (or named) $DATA of a record, extension records merged in
    std::optional<NtfsAttribute> GatherData(DiskHandle& disk, uint64_t recordNum, const NtfsRecord& record,
                                            const std::wstring& stream, bool& complete);

    std::wstring DirectoryPath(DiskHandle& disk, uint64_t parentRecord, uint16_t parentSequence);

    struct DirInfo {
        std::wstring name;
        uint64_t parent = 0;
        uint16_t parentSequence = 0;
        uint16_t sequence = 0;
        bool inUse = false;
        bool valid = false;
    };

    bool m_open = false;
    std::wstring m_openPath;
    NTFSBootSector m_boot{};
    uint64_t m_clusterSize = 0;
    uint64_t m_recordSize = 0;
    uint64_t m_totalClusters = 0;
    uint64_t m_recordCount = 0;
    std::vector<ClusterRun> m_mftRuns;
    std::vector<uint8_t> m_bitmap;
    std::unordered_map<uint64_t, DirInfo> m_dirCache;
};

} // namespace KVC
