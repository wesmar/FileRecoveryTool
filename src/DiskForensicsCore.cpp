// ============================================================================
// DiskForensicsCore.cpp - Orchestration Layer with VolumeReader Integration
// ============================================================================

#include "DiskForensicsCore.h"
#include "NTFSScanner.h"
#include "ExFATScanner.h"
#include "FAT32Scanner.h"
#include "FileCarver.h"
#include "UsnJournalScanner.h"
#include "FileSignatures.h"
#include "Constants.h"
#include "SafetyLimits.h"
#include "StringUtils.h"
#include "VolumeReader.h"
#include "VolumeGeometry.h"

#include <climits>
#include <winioctl.h>
#include <sstream>
#include <set>
#include <algorithm>

namespace KVC {

// ============================================================================
// DiskHandle Implementation
// ============================================================================

DiskHandle::DiskHandle(wchar_t driveLetter)
    : m_driveLetter(driveLetter)
    , m_handle(INVALID_HANDLE_VALUE)
    , m_mappingHandle(nullptr)
    , m_mappedView(nullptr)
    , m_currentMappedOffset(0)
    , m_currentMappedSize(0)
{
}

DiskHandle::~DiskHandle() {
    Close();
}

bool DiskHandle::Open() {
    std::wstring path = L"\\\\.\\";
    path += m_driveLetter;
    path += L":";
    m_handle = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    return m_handle != INVALID_HANDLE_VALUE;
}

void DiskHandle::Close() {
    auto closeHandle = [](HANDLE& h) {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    };
    
    if (m_mappedView != nullptr) {
        UnmapViewOfFile(m_mappedView);
        m_mappedView = nullptr;
    }
    
    m_currentMappedOffset = 0;
    m_currentMappedSize = 0;
    
    closeHandle(m_mappingHandle);
    closeHandle(m_handle);
}

std::vector<uint8_t> DiskHandle::ReadSectors(uint64_t startSector, uint64_t numSectors, uint64_t sectorSize) {
    if (m_handle == INVALID_HANDLE_VALUE || numSectors == 0) {
        return {};
    }
    
    if (numSectors > (UINT64_MAX / sectorSize)) {
        return {};
    }

    uint64_t totalBytes = numSectors * sectorSize;
    
    LARGE_INTEGER offset;
    offset.QuadPart = static_cast<LONGLONG>(startSector * sectorSize);

    if (SetFilePointerEx(m_handle, offset, nullptr, FILE_BEGIN) == 0) {
        return {};
    }

    std::vector<uint8_t> buffer;
    try {
        buffer.resize(static_cast<size_t>(totalBytes));
    } catch (const std::bad_alloc&) {
        return {};
    }
    
    uint64_t bytesRemaining = totalBytes;
    uint64_t bufferOffset = 0;
    
    while (bytesRemaining > 0) {
        uint64_t chunkSize = std::min(bytesRemaining, Constants::MAX_READ_CHUNK);
        
        if (chunkSize > static_cast<uint64_t>(MAXDWORD)) {
            chunkSize = MAXDWORD;
        }
        
        DWORD bytesRead = 0;
        BOOL success = ReadFile(
            m_handle,
            buffer.data() + bufferOffset,
            static_cast<DWORD>(chunkSize),
            &bytesRead,
            nullptr
        );
        
        if (!success || bytesRead == 0) {
            buffer.resize(static_cast<size_t>(bufferOffset));
            return buffer;
        }
        
        bufferOffset += bytesRead;
        bytesRemaining -= bytesRead;
        
        if (bytesRead < chunkSize) {
            buffer.resize(static_cast<size_t>(bufferOffset));
            return buffer;
        }
    }
    
    return buffer;
}

uint64_t DiskHandle::GetSectorSize() const {
    if (m_handle == INVALID_HANDLE_VALUE) {
        return Limits::DEFAULT_SECTOR_SIZE;
    }

    DISK_GEOMETRY geometry = {};
    DWORD bytesReturned = 0;

    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0,
                       &geometry, sizeof(geometry), &bytesReturned, nullptr)) {
        return geometry.BytesPerSector;
    }

    return Limits::DEFAULT_SECTOR_SIZE;
}

uint64_t DiskHandle::GetDiskSize() const {
    if (m_handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD bytesReturned = 0;

    GET_LENGTH_INFORMATION lengthInfo = {};
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                       &lengthInfo, sizeof(lengthInfo), &bytesReturned, nullptr)) {
        return static_cast<uint64_t>(lengthInfo.Length.QuadPart);
    }

    DISK_GEOMETRY geometry = {};
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0,
                       &geometry, sizeof(geometry), &bytesReturned, nullptr)) {
        return static_cast<uint64_t>(geometry.Cylinders.QuadPart) *
               geometry.TracksPerCylinder *
               geometry.SectorsPerTrack *
               geometry.BytesPerSector;
    }

    return 0;
}

DiskHandle::MappedRegion DiskHandle::MapDiskRegion(uint64_t offset, uint64_t size) {
    MappedRegion region;
    
    if (m_handle == INVALID_HANDLE_VALUE) {
        return region;
    }
    
    if (m_mappedView != nullptr && 
        offset >= m_currentMappedOffset &&
        offset + size <= m_currentMappedOffset + m_currentMappedSize) {
        
        uint64_t offsetInMapping = offset - m_currentMappedOffset;
        region.data = static_cast<const uint8_t*>(m_mappedView) + offsetInMapping;
        region.size = size;
        region.diskOffset = offset;
        return region;
    }
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uint64_t granularity = sysInfo.dwAllocationGranularity;
    
    uint64_t alignedOffset = (offset / granularity) * granularity;
    uint64_t extraBytes = offset - alignedOffset;
    uint64_t adjustedSize = size + extraBytes;
    
    if (adjustedSize > Limits::MAX_MAPPING_SIZE) {
        adjustedSize = Limits::MAX_MAPPING_SIZE;
    }
    
    // FIX: Create mapping for entire disk (pass 0,0)
    HANDLE hMapping = CreateFileMappingW(
        m_handle,
        nullptr,
        PAGE_READONLY,
        0,  // High part of max size (0 = entire file)
        0,  // Low part of max size (0 = entire file)
        nullptr
    );
    
    if (hMapping == nullptr) {
        return region;
    }
    
    LARGE_INTEGER fileOffset;
    fileOffset.QuadPart = alignedOffset;
    
    void* pView = MapViewOfFile(
        hMapping,
        FILE_MAP_READ,
        fileOffset.HighPart,
        fileOffset.LowPart,
        static_cast<SIZE_T>(adjustedSize)
    );
    
    if (pView == nullptr) {
        CloseHandle(hMapping);
        return region;
    }
    
    if (m_mappingHandle != nullptr) {
        CloseHandle(m_mappingHandle);
    }
    if (m_mappedView != nullptr) {
        UnmapViewOfFile(m_mappedView);
    }
    
    m_mappingHandle = hMapping;
    m_mappedView = pView;
    
    m_currentMappedOffset = alignedOffset;
    m_currentMappedSize = adjustedSize;
    
    region.data = static_cast<const uint8_t*>(pView) + extraBytes;
    region.size = adjustedSize - extraBytes;
    region.diskOffset = offset;
    
    return region;
}

void DiskHandle::UnmapRegion(MappedRegion& region) {
    region.data = nullptr;
    region.size = 0;
    region.diskOffset = 0;
}

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
    m_fat32Scanner = std::make_unique<FAT32Scanner>();
    m_fileCarver = std::make_unique<FileCarver>();
    m_usnJournalScanner = std::make_unique<UsnJournalScanner>();
}

DiskForensicsCore::~DiskForensicsCore() = default;

bool DiskForensicsCore::ShouldSkipDuplicate(const RecoveryCandidate& candidate) {
    DedupKey key;
    key.mftRecord = candidate.mftRecord.value_or(0);
    key.startCluster = candidate.file.GetFragments().IsEmpty() ? 0 :
                       candidate.file.GetFragments().GetRuns()[0].startCluster;

    if (m_seenCandidates.find(key) != m_seenCandidates.end()) {
        return true;  // Duplicate
    }

    m_seenCandidates.insert(key);
    return false;
}

FilesystemType DiskForensicsCore::DetectFilesystem(wchar_t driveLetter) {
    std::wstring rootPath;
    rootPath += driveLetter;
    rootPath += L":\\";
    wchar_t fsName[MAX_PATH + 1] = {};

    if (GetVolumeInformationW(rootPath.c_str(), nullptr, 0, nullptr, nullptr, nullptr,
                             fsName, MAX_PATH)) {
        std::wstring fs(fsName);
        if (fs == L"NTFS") return FilesystemType::NTFS;
        if (fs == L"exFAT") return FilesystemType::ExFAT;
        if (fs == L"FAT32") return FilesystemType::FAT32;
    }

    return FilesystemType::Unknown;
}

bool DiskForensicsCore::StartScan(
    wchar_t driveLetter,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    bool& shouldStop,
    bool enableMft,
    bool enableUsn,
    bool enableCarving)
{
    FilesystemType fsType = DetectFilesystem(driveLetter);
    
    DiskHandle disk(driveLetter);
    if (!disk.Open()) {
        onProgress(L"Failed to open disk drive", 0.0f);
        return false;
    }

    bool success = false;

    switch (fsType) {
    case FilesystemType::NTFS:
        success = StartNTFSMultiStageScan(disk, folderFilter, filenameFilter, 
                                         onFileFound, onProgress, shouldStop,
                                         enableMft, enableUsn, enableCarving);
        break;

    case FilesystemType::ExFAT:
        onProgress(L"Scanning exFAT filesystem...", 0.0f);
        m_seenCandidates.clear();
        {
            auto dedupCallback = [&](const RecoveryCandidate& candidate) {
                if (!ShouldSkipDuplicate(candidate)) {
                    onFileFound(candidate);
                }
            };
            success = m_exfatScanner->ScanVolume(disk, folderFilter, filenameFilter,
                                                dedupCallback, onProgress, shouldStop, m_config);
        }
        break;

    case FilesystemType::FAT32:
        onProgress(L"Scanning FAT32 filesystem...", 0.0f);
        m_seenCandidates.clear();
        {
            auto dedupCallback = [&](const RecoveryCandidate& candidate) {
                if (!ShouldSkipDuplicate(candidate)) {
                    onFileFound(candidate);
                }
            };
            success = m_fat32Scanner->ScanVolume(disk, folderFilter, filenameFilter,
                                                dedupCallback, onProgress, shouldStop, m_config);
        }
        break;

    default:
        onProgress(L"Unsupported filesystem type", 0.0f);
        break;
    }

    return success;
}

bool DiskForensicsCore::StartNTFSMultiStageScan(
    DiskHandle& disk,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    bool& shouldStop,
    bool enableMft,
    bool enableUsn,
    bool enableCarving)
{
    bool anySuccess = false;

    m_processedMftRecords.clear();
    m_seenCandidates.clear();

    // Build volume geometry for NTFS
    auto boot = m_ntfsScanner->ReadBootSector(disk);
    
    VolumeGeometry geom;
    geom.sectorSize = boot.bytesPerSector;
    geom.bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    geom.totalClusters = disk.GetDiskSize() / geom.bytesPerCluster;
    geom.volumeStartOffset = 0;  // Raw volume handle starts at partition offset 0
    geom.fsType = FilesystemType::NTFS;

    // ========================================================================
    // Stage 1: MFT (Master File Table) Scan - Ultra Fast
    // ========================================================================
    
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

        bool stage1Success = m_ntfsScanner->ScanVolume(disk, folderFilter, filenameFilter,
                                                      mftCallback, onProgress, shouldStop, m_config);
        anySuccess = anySuccess || stage1Success;

        if (shouldStop) {
            onProgress(L"Scan stopped by user", 1.0f);
            return anySuccess;
        }
    }
    
    // ========================================================================
    // Stage 2: USN Journal Analysis - Medium Speed
    // ========================================================================
    
    if (enableUsn) {
        float baseProgress = enableMft ? 0.33f : 0.0f;
        onProgress(L"Stage 2: Analyzing USN Journal...", baseProgress);

        auto usnCallback = [&](const RecoveryCandidate& candidate) {
            if (!ShouldSkipDuplicate(candidate)) {
                onFileFound(candidate);
            }
        };

        bool stage2Success = ProcessUsnJournal(disk, usnCallback, onProgress, shouldStop);
        anySuccess = anySuccess || stage2Success;

        if (shouldStop) {
            onProgress(L"Scan stopped by user", 1.0f);
            return anySuccess;
        }
    }
    
    // ========================================================================
    // Stage 3: File Carving - Slow but Thorough
    // ========================================================================
    
    if (enableCarving) {
        float baseProgress = 0.0f;
        if (enableMft && enableUsn) baseProgress = 0.66f;
        else if (enableMft || enableUsn) baseProgress = 0.5f;
        
        onProgress(L"Stage 3: Carving files from free space...", baseProgress);
        
        // Create VolumeReader for carving
        VolumeReader reader(disk, geom);
        
        // Configure carving options
        CarvingOptions carvingOpts;
        carvingOpts.maxFiles = m_config.carvingMaxFiles;
        carvingOpts.clusterLimit = m_config.carvingClusterLimit;
        carvingOpts.dedupMode = DedupMode::FastDedup;
        carvingOpts.signatures = FileSignatures::GetAllSignatures();
        carvingOpts.startLCN = 0;
        
        // File counter for naming
        static uint64_t carvedFileCounter = 0;
        
        auto carvingCallback = [&](const CarvedFile& carved) {
            // Convert CarvedFile → RecoveryCandidate
            RecoveryCandidate candidate;

            candidate.name = std::to_wstring(++carvedFileCounter) + L"." +
                         std::wstring(carved.signature.extension,
                                    carved.signature.extension + strlen(carved.signature.extension));
            candidate.path = L"<carved from free space>";
            candidate.fileSize = carved.fileSize;
            candidate.sizeFormatted = StringUtils::FormatFileSize(carved.fileSize);
            candidate.source = RecoverySource::Carving;
            candidate.quality = RecoveryQuality::Full;
            candidate.file = FragmentedFile(0, geom.bytesPerCluster);
            candidate.file.SetFragmentMap(carved.fragments);

            if (!ShouldSkipDuplicate(candidate)) {
                onFileFound(candidate);
            }
        };
        
        auto carvingProgress = [&](const std::wstring& msg, float progress) {
            float adjustedProgress = baseProgress + (progress * (1.0f - baseProgress));
            onProgress(msg, adjustedProgress);
        };
        
        try {
            std::atomic<bool> stopAtomic(shouldStop);
            auto result = m_fileCarver->CarveVolume(
                reader, 
                carvingOpts, 
                carvingCallback, 
                carvingProgress, 
                stopAtomic
            );
            
            anySuccess = anySuccess || !result.files.empty();
            
        } catch (const std::exception& e) {
            wchar_t msg[256];
            swprintf_s(msg, L"Carving error: %hs", e.what());
            onProgress(msg, 0.99f);
        }
    }
    
    onProgress(L"Scan complete!", 1.0f);
    return anySuccess;
}

bool DiskForensicsCore::ProcessUsnJournal(
    DiskHandle& disk,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    bool& shouldStop)
{
    try {
        auto boot = m_ntfsScanner->ReadBootSector(disk);
        
        if (std::memcmp(boot.oemID, "NTFS    ", 8) != 0) {
            onProgress(L"USN Journal: Not a valid NTFS drive", 0.66f);
            return false;
        }

        auto recordsByMft = m_usnJournalScanner->ParseJournal(disk, m_config.usnJournalMaxRecords);
        
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
        
        for (const auto& pair : recordsByMft) {
            if (shouldStop) return false;
            
            for (const auto& record : pair.second) {
                if (shouldStop) return false;
                
                if (record.IsDeletion() && !record.IsDirectory()) {
                    
                    uint64_t mftIndex = record.MftIndex();
                    
                    if (m_processedMftRecords.find(mftIndex) != m_processedMftRecords.end()) {
                        processed++;
                        continue;
                    }
                    
                    DeletedFileEntry usnFile;
                    usnFile.filesystemType = L"NTFS";
                    usnFile.hasDeletedTime = true;
                    usnFile.deletedTime = record.timestamp;
                    usnFile.name = record.filename;
                    
                    uint16_t usnSequenceNumber = record.SequenceNumber();
                    
                    auto mftData = m_ntfsScanner->ReadMFTRecord(disk, boot, mftIndex);
                    
                    bool mftMatch = false;
                    
                    if (mftData.size() >= sizeof(MFTFileRecord)) {
                        const MFTFileRecord* mftRec = reinterpret_cast<const MFTFileRecord*>(mftData.data());
                        
                        if (std::memcmp(mftRec->signature, "FILE", 4) == 0) {
                            if (mftRec->sequenceNumber == usnSequenceNumber) {
                                bool parseSuccess = m_ntfsScanner->ParseMFTRecord(
                                    mftData, 
                                    mftIndex, 
                                    onFileFound, 
                                    disk,
                                    boot, 
                                    L"", 
                                    L""
                                );
                                
                                if (parseSuccess) {
                                    mftMatch = true;
                                    filesRecovered++;
                                    m_processedMftRecords.insert(mftIndex);
                                }
                            }
                        }
                    }
                    
                    if (!mftMatch) {
                        usnFile.path = L"<USN: MFT Overwritten>";
                        usnFile.fileRecord = mftIndex;
                        usnFile.size = 0;
                        usnFile.sizeFormatted = L"Metadata Only";
                        usnFile.isRecoverable = false;
                        
                        onFileFound(usnFile);
                        filesOverwritten++;
                        m_processedMftRecords.insert(mftIndex);
                    }
                }
                
                processed++;
                
                if ((processed % Constants::Progress::USN_JOURNAL_INTERVAL) == 0) {
                    float progress = 0.33f + (0.33f * (static_cast<float>(processed) / totalRecords));
                    wchar_t statusMsg[256];
                    swprintf_s(statusMsg, L"USN Journal: %llu / %llu records (%llu recovered, %llu overwritten)", 
                              processed, totalRecords, filesRecovered, filesOverwritten);
                    onProgress(statusMsg, progress);
                }
            }
        }
        
        wchar_t completeMsg[256];
        swprintf_s(completeMsg, L"USN Journal complete: %llu recovered, %llu metadata only", 
                   filesRecovered, filesOverwritten);
        onProgress(completeMsg, 0.66f);
        
        return true;
    }
    catch (const std::exception& e) {
        (void)e;
        onProgress(L"USN Journal not available", 0.66f);
        return false;
    }
}

std::wstring FormatFileSize(uint64_t bytes) {
    return StringUtils::FormatFileSize(bytes);
}

} // namespace KVC