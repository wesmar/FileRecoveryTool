// ============================================================================
// RecoveryCandidate.h - Unified Data Model for File Recovery
// ============================================================================

#pragma once

#include "FragmentedFile.h"
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
    FAT32,             // FAT32 directory
    ExFAT              // exFAT directory
};

struct RecoveryCandidate {
    // Identity
    std::wstring name;
    std::wstring path;
    uint64_t fileSize;
    std::wstring sizeFormatted;

    // Recovery metadata
    RecoveryQuality quality;
    RecoverySource source;

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