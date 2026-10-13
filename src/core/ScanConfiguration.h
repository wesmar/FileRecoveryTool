// ============================================================================
// ScanConfiguration.h - Centralized User-Tunable Scan Settings
// ============================================================================
// Runtime configuration for scan operations. Separates user-tunable settings
// from hard safety limits (see SafetyLimits.h).
// ============================================================================

#pragma once

#include <cstdint>

namespace KVC {

struct ScanConfiguration {
    // ========================================================================
    // MFT Scanning Limits
    // ========================================================================
    uint64_t ntfsMftMaxRecords = 10000000;       // Max MFT records to scan
    uint64_t ntfsMftSystemDriveLimit = 300000;   // Limit for system drives (C:)
    uint64_t ntfsMftSpareDriveLimit = 10000000;  // Limit for data drives

    // ========================================================================
    // USN Journal Limits
    // ========================================================================
    uint64_t usnJournalMaxRecords = 1000000;     // Max USN journal entries

    // ========================================================================
    // File Carving Settings
    // ========================================================================
    uint64_t carvingMaxFiles = 10000000;         // Max carved files
    uint64_t carvingClusterLimit = 0;            // 0 = scan entire volume
    uint64_t carvingBatchClusters = 65536;       // Clusters per batch (~256MB at 4KB)

    // ========================================================================
    // ExFAT/FAT32 Settings
    // ========================================================================
    uint64_t exfatDirectoryEntriesLimit = 1000000;

    // ========================================================================
    // Progress Reporting Intervals
    // ========================================================================
    uint64_t progressMftInterval = 10240;
    uint64_t progressUsnInterval = 1000;
    uint64_t progressCarvingInterval = 10000;

    // ========================================================================
    // Parallel Processing Settings
    // ========================================================================
    size_t parallelThreads = 4;

    // ========================================================================
    // Aliases for legacy compatibility
    // ========================================================================
    uint64_t usnJournalLimit() const { return usnJournalMaxRecords; }
    uint64_t fileCarvingClusterLimit() const { return carvingClusterLimit; }
    uint64_t fileCarvingMaxFiles() const { return carvingMaxFiles; }

    static ScanConfiguration Load();
    bool Save() const;
};

} // namespace KVC