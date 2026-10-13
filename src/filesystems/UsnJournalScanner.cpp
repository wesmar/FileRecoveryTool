// UsnJournalScanner.cpp

#include "filesystems/UsnJournalScanner.h"
#include "filesystems/NTFSScanner.h"

#include <climits>
#include <cstring>
#include <algorithm>
#include <map>
#include <vector>

namespace KVC {

UsnJournalScanner::UsnJournalScanner() = default;
UsnJournalScanner::~UsnJournalScanner() = default;

namespace {
constexpr uint64_t JOURNAL_TAIL_BYTES = 64ull * 1024 * 1024;     // the newest part read
constexpr uint64_t READ_CHUNK = 4ull * 1024 * 1024;
constexpr size_t USN_PAGE = 4096;                                  // records never cross one
}

// Parse USN Journal and group records by MFT record number.
std::map<uint64_t, std::vector<UsnRecord>> UsnJournalScanner::ParseJournal(
    DiskHandle& disk,
    NTFSScanner& ntfs,
    uint64_t maxRecords)
{
    std::map<uint64_t, std::vector<UsnRecord>> recordsByMft;
    try {
        const auto record = ntfs.FindUsnJournal(disk);
        if (!record) {
            return recordsByMft;
        }
        uint64_t realSize = 0;
        auto runs = ntfs.StreamRuns(disk, *record, L"$J", realSize);
        const uint64_t cluster = ntfs.ClusterSize();
        if (runs.empty() || cluster == 0) {
            return recordsByMft;
        }

        // $J is sparse: old records are let go at its start, new ones are
        // appended at its end - read the allocated tail, oldest first
        std::vector<uint8_t> data;
        uint64_t budget = JOURNAL_TAIL_BYTES;
        std::vector<ClusterRun> tail;
        for (auto it = runs.rbegin(); it != runs.rend() && budget > 0; ++it) {
            ClusterRun run = *it;
            const uint64_t bytes = run.clusterCount * cluster;
            if (bytes > budget) {
                const uint64_t skip = (bytes - budget) / cluster;
                run.startCluster += skip;
                run.clusterCount -= skip;
                run.fileOffset += skip * cluster;
            }
            budget -= std::min(budget, run.clusterCount * cluster);
            tail.push_back(run);
        }
        for (auto it = tail.rbegin(); it != tail.rend(); ++it) {
            for (uint64_t at = 0; at < it->clusterCount * cluster; at += READ_CHUNK) {
                const uint64_t want = std::min(READ_CHUNK, it->clusterCount * cluster - at);
                auto bytes = disk.ReadBytes(it->startCluster * cluster + at, want);
                data.insert(data.end(), bytes.begin(), bytes.end());
            }
        }

        auto records = ParseRecordsFromBuffer(data);
        const size_t first = records.size() > maxRecords ? records.size() - static_cast<size_t>(maxRecords) : 0;
        for (size_t i = first; i < records.size(); ++i) {
            recordsByMft[records[i].MftRecordNumber()].push_back(records[i]);
        }
    }
    catch (...) {
        // the journal is optional: it may be off or damaged
    }
    return recordsByMft;
}
// Parse USN records from raw buffer data.
std::vector<UsnRecord> UsnJournalScanner::ParseRecordsFromBuffer(
    const std::vector<uint8_t>& buffer)
{
    std::vector<UsnRecord> records;
    size_t offset = 0;

    while (offset + 60 < buffer.size()) {
        // Read record length (first 4 bytes).
        uint32_t recordLength = 0;
        for (int i = 0; i < 4; i++) {
            recordLength |= static_cast<uint32_t>(buffer[offset + i]) << (i * 8);
        }

        // Validate record length.
        if (recordLength < 60 || recordLength > 65536 ||
            offset + recordLength > buffer.size()) {
            offset = (offset / USN_PAGE + 1) * USN_PAGE;     // the rest of the page is empty
            continue;
        }

        // Parse USN_RECORD_V2 structure.
        UsnRecord rec;
        rec.recordLength = recordLength;

        // Major version (bytes 4-5).
        rec.majorVersion = static_cast<uint16_t>(buffer[offset + 4]) |
                          (static_cast<uint16_t>(buffer[offset + 5]) << 8);
        // Minor version (bytes 6-7).
        rec.minorVersion = static_cast<uint16_t>(buffer[offset + 6]) |
                          (static_cast<uint16_t>(buffer[offset + 7]) << 8);
        if (rec.majorVersion != 2) {                 // V3/V4 (128-bit references): not NTFS's
            offset = (offset + recordLength + 7) & ~7ULL;
            continue;
        }

        // File reference number (bytes 8-15).
        rec.fileReferenceNumber = 0;
        for (int i = 0; i < 8; i++) {
            rec.fileReferenceNumber |= static_cast<uint64_t>(buffer[offset + 8 + i]) << (i * 8);
        }

        // Parent file reference number (bytes 16-23).
        rec.parentFileReferenceNumber = 0;
        for (int i = 0; i < 8; i++) {
            rec.parentFileReferenceNumber |= static_cast<uint64_t>(buffer[offset + 16 + i]) << (i * 8);
        }

        // USN (Update Sequence Number, bytes 24-31).
        rec.usn = 0;
        for (int i = 0; i < 8; i++) {
            rec.usn |= static_cast<int64_t>(buffer[offset + 24 + i]) << (i * 8);
        }

        // Timestamp (FILETIME format, bytes 32-39).
        uint64_t filetime = 0;
        for (int i = 0; i < 8; i++) {
            filetime |= static_cast<uint64_t>(buffer[offset + 32 + i]) << (i * 8);
        }

        // Convert FILETIME to system_clock (simplified conversion).
        auto ticks = static_cast<int64_t>(filetime - 116444736000000000ULL) / 10000000;
        rec.timestamp = std::chrono::system_clock::from_time_t(ticks);

        // Reason flags (bytes 40-43).
        rec.reason = 0;
        for (int i = 0; i < 4; i++) {
            rec.reason |= static_cast<uint32_t>(buffer[offset + 40 + i]) << (i * 8);
        }

        // Source info (bytes 44-47).
        rec.sourceInfo = 0;
        for (int i = 0; i < 4; i++) {
            rec.sourceInfo |= static_cast<uint32_t>(buffer[offset + 44 + i]) << (i * 8);
        }

        // Security ID (bytes 48-51).
        rec.securityId = 0;
        for (int i = 0; i < 4; i++) {
            rec.securityId |= static_cast<uint32_t>(buffer[offset + 48 + i]) << (i * 8);
        }

        // File attributes (bytes 52-55).
        rec.fileAttributes = 0;
        for (int i = 0; i < 4; i++) {
            rec.fileAttributes |= static_cast<uint32_t>(buffer[offset + 52 + i]) << (i * 8);
        }

        // Filename length and offset (bytes 56-59).
        uint16_t filenameLength = static_cast<uint16_t>(buffer[offset + 56]) |
                                 (static_cast<uint16_t>(buffer[offset + 57]) << 8);
        uint16_t filenameOffset = static_cast<uint16_t>(buffer[offset + 58]) |
                                 (static_cast<uint16_t>(buffer[offset + 59]) << 8);

        // Read filename (UTF-16 LE).
        if (filenameOffset > 0 && filenameLength > 0 &&
            offset + filenameOffset + filenameLength <= buffer.size()) {

            size_t nameChars = filenameLength / 2;
            for (size_t i = 0; i < nameChars; i++) {
                wchar_t c = static_cast<wchar_t>(buffer[offset + filenameOffset + i * 2]) |
                           (static_cast<wchar_t>(buffer[offset + filenameOffset + i * 2 + 1]) << 8);
                rec.filename += c;
            }
        }

        records.push_back(rec);

        offset += recordLength;

        // Align to 8-byte boundary for next record.
        offset = (offset + 7) & ~7ULL;
    }

    return records;
}

// ============================================================================
// UsnRecord Helper Methods
// ============================================================================

// Check if record represents a file deletion
bool UsnRecord::IsDeletion() const {
    return (reason & USN_REASON_FILE_DELETE) != 0;
}

// Check if record represents a directory
bool UsnRecord::IsDirectory() const {
    return (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Extract MFT record number (lower 48 bits of file reference)
uint64_t UsnRecord::MftRecordNumber() const {
    return fileReferenceNumber & 0x0000FFFFFFFFFFFFULL;
}

// Alias for MftRecordNumber (same value)
uint64_t UsnRecord::MftIndex() const {
    return MftRecordNumber();
}

// Extract sequence number (upper 16 bits of file reference)
uint16_t UsnRecord::SequenceNumber() const {
    return static_cast<uint16_t>((fileReferenceNumber >> 48) & 0xFFFF);
}

} // namespace KVC