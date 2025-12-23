#pragma once

#include <climits>
#include "FragmentedFile.h"
#include <string>
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
    FAT,               // FAT32/exFAT directory
};

struct RecoveryCandidate {
    std::wstring name;
    std::wstring path;
    uint64_t fileSize;
    std::wstring sizeFormatted;
    
    RecoveryQuality quality;
    RecoverySource source;
    
    FragmentedFile file;           // Cluster data + fragment map
    
    std::optional<uint64_t> mftRecord;  // For MFT/USN sources
    std::optional<std::chrono::system_clock::time_point> deletedTime;
    
    bool IsRecoverable() const {
        return quality == RecoveryQuality::Full || 
               quality == RecoveryQuality::Partial;
    }
};

} // namespace KVC