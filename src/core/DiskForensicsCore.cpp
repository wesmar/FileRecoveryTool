// ============================================================================
// DiskForensicsCore.cpp - Orchestration of the scan stages
// ============================================================================

#include "core/DiskForensicsCore.h"
#include "filesystems/NTFSScanner.h"
#include "filesystems/ExFATScanner.h"
#include "filesystems/FatScanner.h"
#include "filesystems/ExtScanner.h"
#include "carving/FileCarver.h"
#include "filesystems/UsnJournalScanner.h"
#include "carving/FileSignatures.h"
#include "support/Constants.h"
#include "support/SafetyLimits.h"
#include "support/StringUtils.h"
#include "io/VolumeReader.h"
#include "core/VolumeGeometry.h"
#include "io/VolumeLocator.h"
#include "support/NameFilter.h"
#include "core/OverlapResolver.h"

#include <climits>
#include <winioctl.h>
#include <algorithm>

namespace KVC {

// ============================================================================
// ScanConfiguration Implementation
// ============================================================================

ScanConfiguration ScanConfiguration::Load() {
    return ScanConfiguration();
}

bool ScanConfiguration::Save() const {
    return true;
}

// ============================================================================
// DiskForensicsCore Implementation
// ============================================================================

DiskForensicsCore::DiskForensicsCore()
    : m_config(ScanConfiguration::Load())
{
    m_ntfsScanner = std::make_unique<NTFSScanner>();
    m_exfatScanner = std::make_unique<ExFATScanner>();
    m_fatScanner = std::make_unique<FatScanner>();
    m_extScanner = std::make_unique<ExtScanner>();
    m_fileCarver = std::make_unique<FileCarver>();
    m_usnJournalScanner = std::make_unique<UsnJournalScanner>();
}

DiskForensicsCore::~DiskForensicsCore() = default;

bool DiskForensicsCore::ShouldSkipDuplicate(const RecoveryCandidate& candidate) {
    DedupKey key;
    key.mftRecord = candidate.mftRecord.value_or(0);
    key.startCluster = candidate.file.GetFragments().IsEmpty() ? 0 :
                       candidate.file.GetFragments().GetRuns()[0].startCluster;
    key.writeOrder = candidate.writeOrder;
    // files without data (and without a record number) are told apart by name
    if (key.mftRecord == 0 && key.startCluster == 0) {
        return false;
    }
    return !m_seenCandidates.insert(key).second;
}

VolumeInfo DiskForensicsCore::DetectFilesystem(const std::wstring& volume) {
    DiskHandle disk(NormalizeVolumePath(volume));
    if (!disk.Open()) {
        return VolumeInfo{};
    }
    return KVC::DetectFilesystem(disk);
}

bool DiskForensicsCore::StartScan(
    const std::wstring& volume,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    bool enableMft,
    bool enableUsn,
    bool enableCarving,
    bool rawMode)
{
    m_carvingStats = {};
    DiskHandle disk(NormalizeVolumePath(volume));
    if (!disk.Open()) {
        onProgress(L"Failed to open the volume (administrator rights are required)", 0.0f);
        return false;
    }
    const VolumeInfo info = KVC::DetectFilesystem(disk);

    m_processedMftRecords.clear();
    m_seenCandidates.clear();
    m_carvedFiles = 0;

    // one filter for every stage; carved files have no name worth filtering
    // by folder, only by type
    auto filtered = [&, onFileFound](const RecoveryCandidate& candidate) {
        if (!MatchesNameFilter(candidate.name, filenameFilter)) return;
        if (candidate.source != RecoverySource::Carving &&
            !MatchesFolderFilter(candidate.directory.empty() ? candidate.path : candidate.directory, folderFilter)) return;
        onFileFound(candidate);
    };
    if (rawMode) {
        if (enableMft || enableUsn) {
            onProgress(L"RAW is a separate signature scan; metadata methods must be disabled", 0.0f);
            return false;
        }
        const uint64_t size = disk.GetDiskSize();
        if (size == 0) {
            onProgress(L"RAW: source length cannot be determined or the image is empty", 0.0f);
            return false;
        }
        const auto header = disk.ReadBytes(0, 8);
        const auto footer = size >= 512 ? disk.ReadBytes(size - 512, 8) : std::vector<uint8_t>{};
        if ((header.size() == 8 && std::memcmp(header.data(), "vhdxfile", 8) == 0) ||
            (footer.size() == 8 && std::memcmp(footer.data(), "conectix", 8) == 0)) {
            onProgress(L"RAW: mount the VHD/VHDX container and select its disk or volume, or use a flat image", 0.0f);
            return false;
        }
        // An addressing unit is one byte. I/O uses the actual device sectors;
        // this preserves unaligned signatures and a flat image's exact tail.
        FreeSpace whole;
        whole.valid = true;
        whole.geometry = {disk.GetSectorSize(), 1, size, 0, FilesystemType::Unknown};
        whole.runs.emplace_back(0, size);
        return CarveSource(disk, whole, L"RAW", {}, filtered, onProgress, shouldStop, true);
    }
    // the file system's records are gathered first: of two deleted files
    // claiming one cluster only the newer is whole (OverlapResolver)
    std::vector<RecoveryCandidate> collected;
    auto keep = [&](const RecoveryCandidate& candidate) { collected.push_back(candidate); };
    auto dedup = [&](const RecoveryCandidate& candidate) {
        if (!ShouldSkipDuplicate(candidate)) collected.push_back(candidate);
    };

    bool success = false;
    switch (info.type) {
    case FilesystemType::NTFS:
        success = StartNTFSMultiStageScan(disk, keep, onProgress, shouldStop, enableMft, enableUsn);
        break;

    case FilesystemType::ExFAT:
        if (!enableMft) break;
        onProgress(L"Scanning exFAT directories...", 0.0f);
        success = m_exfatScanner->ScanVolume(disk, dedup, onProgress, shouldStop, m_config);
        break;

    case FilesystemType::FAT12:
    case FilesystemType::FAT16:
    case FilesystemType::FAT32:
        if (!enableMft) break;
        onProgress(std::wstring(L"Scanning ") + info.name + L" directories...", 0.0f);
        success = m_fatScanner->ScanVolume(disk, dedup, onProgress, shouldStop, m_config);
        break;

    case FilesystemType::Ext:
        // ext2/3 indirect blocks interrupt a physical byte stream. Even
        // carving-only can use journal maps to read the actual data blocks.
        if (!enableMft && !enableCarving) break;
        onProgress(L"Scanning " + info.name + L" directories, inodes and journal...", 0.0f);
        success = m_extScanner->ScanVolume(disk, dedup, onProgress, shouldStop, m_config);
        break;

    default:
        onProgress(L"Unsupported or unreadable file system", 0.0f);
        break;
    }

    const size_t overwritten = ResolveClusterOverlaps(collected);
    if (overwritten) {
        wchar_t msg[160];
        swprintf_s(msg, L"%zu deleted files lost clusters to newer files", overwritten);
        onProgress(msg, 1.0f);
    }
    for (const auto& candidate : collected) {
        if (enableMft || enableUsn) filtered(candidate);
    }

    // carving: the free space of every file system, as its own map says
    if (enableCarving && !shouldStop && info.type != FilesystemType::Unknown) {
        FreeSpace free;
        switch (info.type) {
        case FilesystemType::NTFS:  free = m_ntfsScanner->FreeSpaceOf(disk); break;
        case FilesystemType::ExFAT: free = m_exfatScanner->FreeSpaceOf(disk); break;
        case FilesystemType::Ext:   free = m_extScanner->FreeSpaceOf(disk); break;
        default:                    free = m_fatScanner->FreeSpaceOf(disk); break;
        }
        if (free.valid) {
            success = CarveSource(disk, free, info.name, collected, filtered, onProgress, shouldStop) || success;
        } else {
            onProgress(L"Carving: the allocation map cannot be read, carving skipped", 1.0f);
        }
    }
    onProgress(L"Scan complete!", 1.0f);
    return success;
}

bool DiskForensicsCore::StartNTFSMultiStageScan(
    DiskHandle& disk,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    bool enableMft,
    bool enableUsn)
{
    bool anySuccess = false;

    if (enableMft) {
        onProgress(L"Stage 1: Scanning MFT for deleted files...", 0.0f);
        auto mftCallback = [&](const RecoveryCandidate& candidate) {
            if (candidate.mftRecord) {
                m_processedMftRecords.insert(*candidate.mftRecord);
            }
            if (!ShouldSkipDuplicate(candidate)) {
                onFileFound(candidate);
            }
        };
        anySuccess = m_ntfsScanner->ScanVolume(disk, L"", L"", mftCallback, onProgress, shouldStop, m_config) || anySuccess;
        if (shouldStop) {
            onProgress(L"Scan stopped by user", 1.0f);
            return anySuccess;
        }
    }

    if (enableUsn) {
        onProgress(L"Stage 2: Analyzing USN Journal...", enableMft ? 0.33f : 0.0f);
        auto usnCallback = [&](const RecoveryCandidate& candidate) {
            if (!ShouldSkipDuplicate(candidate)) {
                onFileFound(candidate);
            }
        };
        anySuccess = ProcessUsnJournal(disk, usnCallback, onProgress, shouldStop) || anySuccess;
        if (shouldStop) {
            onProgress(L"Scan stopped by user", 1.0f);
            return anySuccess;
        }
    }

    return anySuccess;
}

bool DiskForensicsCore::CarveSource(
    DiskHandle& disk,
    const FreeSpace& free,
    const std::wstring& fsName,
    const std::vector<RecoveryCandidate>& metadata,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    bool rawMode)
{
    onProgress(rawMode ? L"RAW: scanning all source bytes; file deletion state is unknown" : L"Carving files from free space...", 0.0f);
    VolumeReader reader(disk, free.geometry);

    CarvingOptions options;
    options.maxFiles = m_config.carvingMaxFiles;
    options.clusterLimit = m_config.carvingClusterLimit;
    if (rawMode) options.batchClusters = 64ull * 1024 * 1024;
    options.dedupMode = DedupMode::FastDedup;
    options.signatures = FileSignatures::GetAllSignatures();
    options.freeRuns = free.runs;
    options.freeRunsGiven = true;
    if (free.geometry.fsType == FilesystemType::Ext) {
        for (const auto& candidate : metadata) {
            const auto& map = candidate.file.GetFragments();
            if (candidate.source != RecoverySource::Ext || candidate.quality != RecoveryQuality::Full ||
                map.Empty() || map.GetRuns().front().fileOffset != 0 ||
                map.BytesPerCluster() != free.geometry.bytesPerCluster) continue;
            options.fragmentHints.try_emplace(map.GetRuns().front().startCluster, map);
        }
    }

    auto carved = [&](const CarvedFile& file) {
        RecoveryCandidate candidate;
        candidate.name = std::to_wstring(++m_carvedFiles) + L"." +
                         std::wstring(file.signature.extension,
                                      file.signature.extension + strlen(file.signature.extension));
        candidate.path = rawMode ? L"<raw signature scan; deletion state unknown>" : L"<carved from free space>";
        candidate.directory = L"carved";
        candidate.fileSize = candidate.size = file.fileSize;
        candidate.sizeFormatted = StringUtils::FormatFileSize(file.fileSize);
        candidate.source = RecoverySource::Carving;
        candidate.quality = (file.spillsIntoUsed || file.incompleteRevision) ? RecoveryQuality::Partial : RecoveryQuality::Full;
        if (file.incompleteRevision) candidate.sizeFormatted += L" (earlier PDF revision; later update incomplete)";
        if (file.spillsIntoUsed) candidate.sizeFormatted += L" (runs into used clusters)";
        candidate.filesystemType = fsName;
        candidate.volumeStartOffset = free.geometry.volumeStartOffset;
        candidate.file = FragmentedFile(file.fileSize, free.geometry.bytesPerCluster);
        candidate.file.SetFragmentMap(file.fragments);
        onFileFound(candidate);
    };

    try {
        const auto result = m_fileCarver->CarveVolume(reader, options, carved, onProgress, shouldStop);
        m_carvingStats = result.stats;
        if (!result.complete && !shouldStop) onProgress(L"Signature scan incomplete: source reads failed", 0.99f);
        return result.complete;
    } catch (const std::exception& e) {
        wchar_t msg[256];
        swprintf_s(msg, L"Carving error: %hs", e.what());
        onProgress(msg, 0.99f);
        return false;
    }
}
bool DiskForensicsCore::ProcessUsnJournal(
    DiskHandle& disk,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    std::atomic<bool>& shouldStop)
{
    try {
        auto boot = m_ntfsScanner->ReadBootSector(disk);
        if (std::memcmp(boot.oemID, "NTFS    ", 8) != 0) {
            onProgress(L"USN Journal: Not a valid NTFS drive", 0.66f);
            return false;
        }

        auto recordsByMft = m_usnJournalScanner->ParseJournal(disk, *m_ntfsScanner, m_config.usnJournalMaxRecords);

        uint64_t totalRecords = 0;
        for (const auto& pair : recordsByMft) {
            totalRecords += pair.second.size();
        }
        if (totalRecords == 0) {
            onProgress(L"USN Journal: No deletion records found", 0.66f);
            return true;
        }

        uint64_t processed = 0;
        uint64_t filesRecovered = 0;
        uint64_t filesOverwritten = 0;
        DiskForensicsCore::FileFoundCallback forward = onFileFound;

        for (const auto& pair : recordsByMft) {
            if (shouldStop) return false;
            for (const auto& record : pair.second) {
                if (shouldStop) return false;
                ++processed;
                if (!record.IsDeletion() || record.IsDirectory()) {
                    continue;
                }
                const uint64_t mftIndex = record.MftIndex();
                if (m_processedMftRecords.count(mftIndex)) {
                    continue;
                }

                // the record still describes the deleted file when its
                // sequence number is the one the journal saw
                bool mftMatch = false;
                auto mftData = m_ntfsScanner->ReadMFTRecord(disk, boot, mftIndex);
                if (mftData.size() >= sizeof(MFTFileRecord)) {
                    const MFTFileRecord* mftRec = reinterpret_cast<const MFTFileRecord*>(mftData.data());
                    if (std::memcmp(mftRec->signature, "FILE", 4) == 0 &&
                        mftRec->sequenceNumber == record.SequenceNumber() &&
                        m_ntfsScanner->ParseMFTRecord(mftData, mftIndex, forward, disk, boot, L"", L"")) {
                        mftMatch = true;
                        ++filesRecovered;
                    }
                }
                if (!mftMatch) {
                    DeletedFileEntry usnFile;
                    usnFile.filesystemType = L"NTFS";
                    usnFile.source = RecoverySource::USN;
                    usnFile.hasDeletedTime = true;
                    usnFile.deletedTime = record.timestamp;
                    usnFile.name = record.filename;
                    usnFile.path = L"<USN: MFT Overwritten>";
                    usnFile.fileRecord = mftIndex;
                    usnFile.size = 0;
                    usnFile.sizeFormatted = L"Metadata Only";
                    usnFile.quality = RecoveryQuality::MetadataOnly;
                    usnFile.isRecoverable = false;
                    onFileFound(usnFile);
                    ++filesOverwritten;
                }
                m_processedMftRecords.insert(mftIndex);

                if ((processed % Constants::Progress::USN_JOURNAL_INTERVAL) == 0) {
                    wchar_t statusMsg[256];
                    swprintf_s(statusMsg, L"USN Journal: %llu / %llu records (%llu recovered, %llu overwritten)",
                               processed, totalRecords, filesRecovered, filesOverwritten);
                    onProgress(statusMsg, 0.33f + 0.33f * (static_cast<float>(processed) / totalRecords));
                }
            }
        }

        wchar_t completeMsg[256];
        swprintf_s(completeMsg, L"USN Journal complete: %llu recovered, %llu metadata only",
                   filesRecovered, filesOverwritten);
        onProgress(completeMsg, 0.66f);
        return true;
    } catch (const std::exception&) {
        onProgress(L"USN Journal not available", 0.66f);
        return false;
    }
}

std::wstring FormatFileSize(uint64_t bytes) {
    return StringUtils::FormatFileSize(bytes);
}

} // namespace KVC
