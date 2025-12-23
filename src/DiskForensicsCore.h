// ============================================================================
// DiskForensicsCore.h - Core Disk Forensics Engine
// ============================================================================
// Manages low-level disk I/O and coordinates forensic scanning operations.
// Orchestrates multi-stage recovery including MFT scanning, USN analysis, and file carving.
// ============================================================================

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include "VolumeGeometry.h"    // Provides FilesystemType
#include "DiskHandle.h"
#include "ScanConfiguration.h" // Centralized scan configuration
#include "RecoveryCandidate.h" // Unified data model
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>
#include <chrono>
#include <set>
#include <unordered_set>

namespace KVC {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class NTFSScanner;
class ExFATScanner;
class FAT32Scanner;
class FileCarver;
class UsnJournalScanner;
struct RecoveryCandidate;

// ScanConfiguration is now defined in ScanConfiguration.h

// ============================================================================
// DiskForensicsCore - Main orchestrator
// ============================================================================

class DiskForensicsCore {
public:
    DiskForensicsCore();
    ~DiskForensicsCore();

    using ProgressCallback = std::function<void(const std::wstring&, float)>;
    using FileFoundCallback = std::function<void(const RecoveryCandidate&)>;

    FilesystemType DetectFilesystem(wchar_t driveLetter);
    
    bool StartScan(
        wchar_t driveLetter,
        const std::wstring& folderFilter,
        const std::wstring& filenameFilter,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        bool& shouldStop,
        bool enableMft,
        bool enableUsn,
        bool enableCarving
    );

private:
    bool StartNTFSMultiStageScan(
        DiskHandle& disk,
        const std::wstring& folderFilter,
        const std::wstring& filenameFilter,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        bool& shouldStop,
        bool enableMft,
        bool enableUsn,
        bool enableCarving
    );

    bool ProcessUsnJournal(
        DiskHandle& disk,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        bool& shouldStop
    );

    // Cross-stage deduplication
    struct DedupKey {
        uint64_t mftRecord;
        uint64_t startCluster;

        bool operator<(const DedupKey& other) const {
            if (mftRecord != other.mftRecord) return mftRecord < other.mftRecord;
            return startCluster < other.startCluster;
        }
    };

    bool ShouldSkipDuplicate(const RecoveryCandidate& candidate);

    std::unique_ptr<NTFSScanner> m_ntfsScanner;
    std::unique_ptr<ExFATScanner> m_exfatScanner;
    std::unique_ptr<FAT32Scanner> m_fat32Scanner;
    std::unique_ptr<FileCarver> m_fileCarver;
    std::unique_ptr<UsnJournalScanner> m_usnJournalScanner;
    ScanConfiguration m_config;
    std::set<uint64_t> m_processedMftRecords;
    std::set<DedupKey> m_seenCandidates;
};

std::wstring FormatFileSize(uint64_t bytes);

} // namespace KVC