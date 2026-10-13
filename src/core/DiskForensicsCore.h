// ============================================================================
// DiskForensicsCore.h - Core Disk Forensics Engine
// ============================================================================
// Opens the source volume, recognises its file system from its own sectors
// and runs the stages that apply: the file system's own records (MFT, FAT and
// exFAT directories, ext inodes and journal), the NTFS change journal, and
// carving. Filters by name and folder for every stage alike.
// ============================================================================

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>
#include "core/VolumeGeometry.h"
#include "io/DiskHandle.h"
#include "filesystems/FilesystemDetector.h"
#include "core/ScanConfiguration.h"
#include "core/RecoveryCandidate.h"
#include "carving/FileCarver.h"
#include <atomic>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>
#include <set>

namespace KVC {

class NTFSScanner;
class ExFATScanner;
class FatScanner;
class ExtScanner;
class FileCarver;
class UsnJournalScanner;

class DiskForensicsCore {
public:
    DiskForensicsCore();
    ~DiskForensicsCore();

    using ProgressCallback = std::function<void(const std::wstring&, float)>;
    using FileFoundCallback = std::function<void(const RecoveryCandidate&)>;

    // volume: "D", "D:" or a device path such as \\.\HarddiskVolume7
    VolumeInfo DetectFilesystem(const std::wstring& volume);

    bool StartScan(
        const std::wstring& volume,
        const std::wstring& folderFilter,
        const std::wstring& filenameFilter,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        bool enableMft,                 // the file system's own records
        bool enableUsn,
        bool enableCarving,
        bool rawMode = false            // whole source, no allocation metadata
    );

    const CarvingStatistics& LastCarvingStatistics() const { return m_carvingStats; }

private:
    bool StartNTFSMultiStageScan(
        DiskHandle& disk,
        FileFoundCallback onFileFound,      // MFT and change journal records
        ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        bool enableMft,
        bool enableUsn
    );

    bool ProcessUsnJournal(
        DiskHandle& disk,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        std::atomic<bool>& shouldStop
    );

    // signatures in the clusters the file system's own map shows free
    bool CarveSource(
        DiskHandle& disk,
        const FreeSpace& free,
        const std::wstring& fsName,
        const std::vector<RecoveryCandidate>& metadata,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        bool rawMode = false
    );

    // Cross-stage deduplication
    struct DedupKey {
        uint64_t mftRecord;
        uint64_t startCluster;
        uint64_t writeOrder;        // a record reused by a newer file is another file

        bool operator<(const DedupKey& other) const {
            if (mftRecord != other.mftRecord) return mftRecord < other.mftRecord;
            if (startCluster != other.startCluster) return startCluster < other.startCluster;
            return writeOrder < other.writeOrder;
        }
    };

    bool ShouldSkipDuplicate(const RecoveryCandidate& candidate);

    std::unique_ptr<NTFSScanner> m_ntfsScanner;
    std::unique_ptr<ExFATScanner> m_exfatScanner;
    std::unique_ptr<FatScanner> m_fatScanner;
    std::unique_ptr<ExtScanner> m_extScanner;
    std::unique_ptr<FileCarver> m_fileCarver;
    std::unique_ptr<UsnJournalScanner> m_usnJournalScanner;
    ScanConfiguration m_config;
    std::set<uint64_t> m_processedMftRecords;
    std::set<DedupKey> m_seenCandidates;
    uint64_t m_carvedFiles = 0;
    CarvingStatistics m_carvingStats{};
};

std::wstring FormatFileSize(uint64_t bytes);

} // namespace KVC
