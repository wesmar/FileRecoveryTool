// ============================================================================
// RecoveryCandidate.h - Unified Data Model for File Recovery
// ============================================================================

#pragma once

#include "core/FragmentedFile.h"
#include <string>
#include <optional>
#include <chrono>

namespace KVC {

enum class RecoveryQuality {
    Full,              // Complete file data available
    Partial,           // Some clusters unreadable
    MetadataOnly,      // Only filename/size known
    Unrecoverable      // No data available
};

enum class RecoverySource {
    MFT,               // NTFS Master File Table
    USN,               // NTFS Change Journal
    Carving,           // Signature-based recovery
    FAT32,             // FAT12/16/32 directory
    ExFAT,             // exFAT directory
    Ext                // ext2/3/4 directory, inode and journal
};

// How the clusters of the file hold its bytes
enum class DataEncoding {
    Raw,               // byte for byte
    NtfsLznt1          // NTFS compression units, LZNT1
};

struct RecoveryCandidate {
    // Identity
    std::wstring name;
    std::wstring path;              // shown to the user
    std::wstring directory;         // the file's folder, relative to the volume root
    uint64_t fileSize = 0;
    std::wstring sizeFormatted;

    // Bytes past this are zero whatever the clusters hold (exFAT
    // ValidDataLength, NTFS initialized size)
    std::optional<uint64_t> validLength;
    DataEncoding encoding = DataEncoding::Raw;
    uint32_t compressionUnitClusters = 0;   // NtfsLznt1

    // which of two deleted files claiming one cluster wrote it last: larger is
    // later (NTFS record LSN, ext journal transaction, FAT creation time); 0 unknown
    uint64_t writeOrder = 0;

    // Recovery metadata
    RecoveryQuality quality = RecoveryQuality::Unrecoverable;
    RecoverySource source = RecoverySource::Carving;

    // Cluster data
    FragmentedFile file;  // Contains FragmentMap + resident data

    // Volume geometry
    uint64_t volumeStartOffset = 0;

    // Optional metadata
    std::optional<uint64_t> mftRecord;
    std::optional<std::chrono::system_clock::time_point> deletedTime;

    // Compatibility fields
    std::wstring filesystemType;
    bool hasDeletedTime = false;
    std::optional<uint64_t> fileRecord;
    uint64_t size = 0;
    bool isRecoverable = true;

    // Dedup helpers
    uint64_t UniqueId() const {
        if (mftRecord) return *mftRecord;
        if (!file.GetFragments().IsEmpty()) {
            return file.GetFragments().GetRuns()[0].startCluster;
        }
        return 0;
    }

    bool IsRecoverable() const {
        return quality == RecoveryQuality::Full ||
               quality == RecoveryQuality::Partial;
    }
};

using DeletedFileEntry = RecoveryCandidate;

} // namespace KVC