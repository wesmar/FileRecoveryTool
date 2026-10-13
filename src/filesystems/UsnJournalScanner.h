// ============================================================================
// UsnJournalScanner.h - NTFS USN Journal Analyzer
// ============================================================================
// Reads the newest part of $Extend\$UsnJrnl:$J - found by name, its run list
// taken through the attribute list - and returns the change records in it.
// ============================================================================

#pragma once

#include "core/DiskForensicsCore.h"
#include "io/DiskHandle.h"
#include <chrono>
#include <cstdint>
#include <map>
#include <vector>

namespace KVC {

class NTFSScanner;

struct UsnRecord {
    uint32_t recordLength = 0;
    uint16_t majorVersion = 0;
    uint16_t minorVersion = 0;
    uint64_t fileReferenceNumber = 0;
    uint64_t parentFileReferenceNumber = 0;
    int64_t usn = 0;
    std::chrono::system_clock::time_point timestamp;
    uint32_t reason = 0;
    uint32_t sourceInfo = 0;
    uint32_t securityId = 0;
    uint32_t fileAttributes = 0;
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

    // records grouped by MFT record number, the newest maxRecords at most
    std::map<uint64_t, std::vector<UsnRecord>> ParseJournal(
        DiskHandle& disk,
        NTFSScanner& ntfs,
        uint64_t maxRecords
    );

private:
    std::vector<UsnRecord> ParseRecordsFromBuffer(const std::vector<uint8_t>& buffer);
};

} // namespace KVC
