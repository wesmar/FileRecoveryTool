// ============================================================================
// UsnJournalScanner.h - NTFS USN Journal Analyzer
// ============================================================================
// Parses the NTFS Change Journal ($UsnJrnl) to detect file deletion events.
// Maps USN records to MFT references for recovering recently deleted files.
// ============================================================================
#pragma once

#include "DiskForensicsCore.h"
#include "Constants.h"
#include "RecoveryApplication.h"
#include <cstdint>
#include <map>
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
    
    bool IsDeletion() const { return (reason & USN_REASON_FILE_DELETE) != 0; }
    bool IsDirectory() const { return (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0; }
    uint64_t MftRecordNumber() const { return fileReferenceNumber & 0x0000FFFFFFFFFFFF; }
    uint64_t MftIndex() const { return fileReferenceNumber & 0x0000FFFFFFFFFFFF; }
    uint16_t SequenceNumber() const { return static_cast<uint16_t>(fileReferenceNumber >> 48); }
};

class UsnJournalScanner {
public:
    UsnJournalScanner();
    ~UsnJournalScanner();

    // Parse USN Journal and find deleted files
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
