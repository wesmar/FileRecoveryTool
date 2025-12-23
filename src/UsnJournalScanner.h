// ============================================================================
// UsnJournalScanner.h - NTFS USN Journal Analyzer
// ============================================================================
// Parses the NTFS Change Journal to detect file deletion events.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "DiskHandle.h"
#include "Constants.h"
#include <cstdint>
#include <map>
#include <vector>
#include <chrono>

namespace KVC {

struct UsnRecord {
    uint32_t recordLength;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint64_t fileReferenceNumber;
    uint64_t parentFileReferenceNumber;
    int64_t usn;
    std::chrono::system_clock::time_point timestamp;
    uint32_t reason;
    uint32_t sourceInfo;
    uint32_t securityId;
    uint32_t fileAttributes;
    std::wstring filename;
    
    bool IsDeletion() const;
    bool IsDirectory() const;
    uint64_t MftRecordNumber() const;
    uint64_t MftIndex() const;
    uint16_t SequenceNumber() const;
};

class UsnJournalScanner {
public:
    UsnJournalScanner();
    ~UsnJournalScanner();

    std::map<uint64_t, std::vector<UsnRecord>> ParseJournal(
        DiskHandle& disk,
        uint64_t maxRecords
    );

private:
    struct NtfsBootSector {
        uint16_t bytesPerSector;
        uint8_t sectorsPerCluster;
        uint64_t mftCluster;
        int8_t clustersPerMFTRecord;
    };

    NtfsBootSector ReadBootSector(DiskHandle& disk);
    std::vector<uint8_t> ReadMFTRecord(DiskHandle& disk, const NtfsBootSector& boot, uint64_t recordNum);
    std::vector<ClusterRange> ParseJStreamLocation(const std::vector<uint8_t>& mftData);
    std::vector<ClusterRange> ParseDataRuns(const uint8_t* attrData, size_t attrLength);
    std::vector<uint8_t> ReadClusters(DiskHandle& disk, const NtfsBootSector& boot, 
                                      const std::vector<ClusterRange>& ranges);
    std::vector<UsnRecord> ParseRecordsFromBuffer(const std::vector<uint8_t>& buffer);
};

} // namespace KVC