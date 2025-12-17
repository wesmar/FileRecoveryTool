// DiskForensicsCore.cpp
#include "DiskForensicsCore.h"
#include "NTFSScanner.h"
#include "ExFATScanner.h"
#include "FAT32Scanner.h"
#include "FileCarver.h"
#include "UsnJournalScanner.h"
#include "FileSignatures.h"
#include <winioctl.h>
#include <sstream>
#include <set>
#include <algorithm>

namespace KVC {

// Construct disk handle for a specific drive letter.
DiskHandle::DiskHandle(wchar_t driveLetter)
    : m_driveLetter(driveLetter)
    , m_handle(INVALID_HANDLE_VALUE)
    , m_mappingHandle(nullptr)
    , m_mappedView(nullptr)
{
}

// Ensure all resources are released on destruction.
DiskHandle::~DiskHandle() {
    Close();                                    // Clean up handles and mappings
}

// Open direct disk access handle for raw sector I/O.
bool DiskHandle::Open() {
    std::wstring path = L"\\\\.\\";
    path += m_driveLetter;
    path += L":";
    m_handle = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,     // Allow concurrent access
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    return m_handle != INVALID_HANDLE_VALUE;    // Return success status
}

// Close disk handle and unmap any memory-mapped regions.
void DiskHandle::Close() {
    // RAII for handles
    auto closeHandle = [](HANDLE& h) {
        if (h != INVALID_HANDLE_VALUE && h != nullptr) {
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
        }
    };
    
    // Unmap any active memory-mapped view
    if (m_mappedView != nullptr) {
        UnmapViewOfFile(m_mappedView);
        m_mappedView = nullptr;
    }
    
    // Use RAII through local objects
    closeHandle(m_mappingHandle);
    closeHandle(m_handle);
}

// Read sequential sectors from disk into memory buffer.
std::vector<uint8_t> DiskHandle::ReadSectors(uint64_t startSector, uint64_t numSectors, uint64_t sectorSize) {
    if (m_handle == INVALID_HANDLE_VALUE || numSectors == 0) {
        return {};                              // Invalid handle or zero sectors
    }

    LARGE_INTEGER offset;
    offset.QuadPart = static_cast<LONGLONG>(startSector * sectorSize);

    if (SetFilePointerEx(m_handle, offset, nullptr, FILE_BEGIN) == 0) {
        return {};                              // Seek failed
    }

    size_t bufferSize = static_cast<size_t>(numSectors * sectorSize);
    std::vector<uint8_t> buffer(bufferSize);
    DWORD bytesRead = 0;

    if (ReadFile(m_handle, buffer.data(), static_cast<DWORD>(bufferSize), &bytesRead, nullptr)) {
        buffer.resize(bytesRead);               // Trim to actual bytes read
        return buffer;
    }

    return {};                                  // Read failed
}

// Query physical sector size from disk geometry.
uint64_t DiskHandle::GetSectorSize() const {
    if (m_handle == INVALID_HANDLE_VALUE) {
        return 512;                             // Default sector size
    }

    DISK_GEOMETRY geometry = {};
    DWORD bytesReturned = 0;

    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0,
                       &geometry, sizeof(geometry), &bytesReturned, nullptr)) {
        return geometry.BytesPerSector;
    }

    return 512;                                 // Fallback to standard size
}

// Query total disk capacity in bytes.
uint64_t DiskHandle::GetDiskSize() const {
    if (m_handle == INVALID_HANDLE_VALUE) {
        return 0;                               // Invalid handle
    }

    DWORD bytesReturned = 0;

    // Try modern method first
    GET_LENGTH_INFORMATION lengthInfo = {};
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                       &lengthInfo, sizeof(lengthInfo), &bytesReturned, nullptr)) {
        return static_cast<uint64_t>(lengthInfo.Length.QuadPart);
    }

    // Fallback to geometry-based calculation
    DISK_GEOMETRY geometry = {};
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0,
                       &geometry, sizeof(geometry), &bytesReturned, nullptr)) {
        return static_cast<uint64_t>(geometry.Cylinders.QuadPart) *
               geometry.TracksPerCylinder *
               geometry.SectorsPerTrack *
               geometry.BytesPerSector;
    }

    return 0;                                   // Both methods failed
}

// Map disk region into process memory for zero-copy access.
DiskHandle::MappedRegion DiskHandle::MapDiskRegion(uint64_t offset, uint64_t size) {
    MappedRegion region;
    
    if (m_handle == INVALID_HANDLE_VALUE) {
        return region;                          // Invalid handle
    }
    
    // Align offset to allocation granularity (typically 64KB on Windows)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    uint64_t granularity = sysInfo.dwAllocationGranularity;
    
    uint64_t alignedOffset = (offset / granularity) * granularity;
    uint64_t extraBytes = offset - alignedOffset;
    uint64_t adjustedSize = size + extraBytes;
    
    // Limit mapping size to reasonable chunk (e.g., 256MB)
    const uint64_t MAX_MAPPING_SIZE = 256ULL * 1024 * 1024;
    if (adjustedSize > MAX_MAPPING_SIZE) {
        adjustedSize = MAX_MAPPING_SIZE;
    }
    
    // Create file mapping object for the disk
    LARGE_INTEGER mappingSize;
    mappingSize.QuadPart = alignedOffset + adjustedSize;
    
    HANDLE hMapping = CreateFileMappingW(
        m_handle,
        nullptr,
        PAGE_READONLY,                          // Read-only access
        mappingSize.HighPart,
        mappingSize.LowPart,
        nullptr
    );
    
    if (hMapping == nullptr) {
        return region;                          // Mapping creation failed
    }
    
    // Map view of file into address space
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
        return region;                          // View mapping failed
    }
    
    // Store mapping handle for cleanup
    if (m_mappingHandle != nullptr) {
        CloseHandle(m_mappingHandle);
    }
    if (m_mappedView != nullptr) {
        UnmapViewOfFile(m_mappedView);
    }
    
    m_mappingHandle = hMapping;
    m_mappedView = pView;
    
    // Set up region info
    region.data = static_cast<const uint8_t*>(pView) + extraBytes;
    region.size = adjustedSize - extraBytes;
    region.diskOffset = offset;
    
    return region;
}

// Invalidate mapped region structure (actual cleanup in Close()).
void DiskHandle::UnmapRegion(MappedRegion& region) {
    // Actual unmapping happens in Close() or when creating new mapping
    // This just invalidates the region struct
    region.data = nullptr;
    region.size = 0;
    region.diskOffset = 0;
}

// Load scan configuration from persistent storage.
ScanConfiguration ScanConfiguration::Load() {
    return ScanConfiguration();                 // Use default values
}

// Save scan configuration to persistent storage.
bool ScanConfiguration::Save() const {
    return true;                                // Stub implementation
}

// Initialize forensics core with all scanner modules.
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

// Detect filesystem type by querying volume information.
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

    return FilesystemType::Unknown;             // Unrecognized filesystem
}

// Main entry point for initiating a scan operation.
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
    // Detect filesystem type to use appropriate scanner
    FilesystemType fsType = DetectFilesystem(driveLetter);
    
    // Open disk for raw sector access
    DiskHandle disk(driveLetter);
    if (!disk.Open()) {
        onProgress(L"Failed to open disk drive", 0.0f);
        return false;
    }

    bool success = false;

    switch (fsType) {
    case FilesystemType::NTFS:
        // NTFS supports multi-stage scanning: MFT, USN Journal, and File Carving
        success = StartNTFSMultiStageScan(disk, folderFilter, filenameFilter, 
                                         onFileFound, onProgress, shouldStop,
                                         enableMft, enableUsn, enableCarving);
        break;

    case FilesystemType::ExFAT:
        onProgress(L"Scanning exFAT filesystem...", 0.0f);
        success = m_exfatScanner->ScanVolume(disk, folderFilter, filenameFilter,
                                            onFileFound, onProgress, shouldStop, m_config);
        break;

    case FilesystemType::FAT32:
        onProgress(L"Scanning FAT32 filesystem...", 0.0f);
        success = m_fat32Scanner->ScanVolume(disk, folderFilter, filenameFilter,
                                            onFileFound, onProgress, shouldStop, m_config);
        break;

    default:
        onProgress(L"Unsupported filesystem type", 0.0f);
        break;
    }

    return success;
}

// Execute multi-stage NTFS scan with MFT, USN, and carving phases.
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
    
    // Clear deduplication set at start
    m_processedMftRecords.clear();

    // ========================================================================
    // Stage 1: MFT (Master File Table) Scan - Ultra Fast
    // ========================================================================
    // Scans the MFT for deleted file entries. This is the fastest method
    // and finds files that were recently deleted and still have intact MFT entries.
    
    if (enableMft) {
        onProgress(L"Stage 1: Scanning MFT for deleted files...", 0.0f);
        
        // Wrapper callback to track processed MFT records
        auto mftCallback = [&](const DeletedFileEntry& file) {
            m_processedMftRecords.insert(file.fileRecord);
            onFileFound(file);
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
    // Analyzes the NTFS Change Journal to find deletion events.
    // This can find files that no longer have MFT entries but were recently deleted.
    
    if (enableUsn) {
        float baseProgress = enableMft ? 0.33f : 0.0f;
        onProgress(L"Stage 2: Analyzing USN Journal...", baseProgress);
        bool stage2Success = ProcessUsnJournal(disk, onFileFound, onProgress, shouldStop);
        anySuccess = anySuccess || stage2Success;
        
        if (shouldStop) {
            onProgress(L"Scan stopped by user", 1.0f);
            return anySuccess;
        }
    }
    
    // ========================================================================
    // Stage 3: File Carving - Slow but Thorough
    // ========================================================================
    // Scans raw disk sectors for file signatures. This is the slowest method
    // but can recover files even when filesystem metadata is completely gone.
    // Uses memory-mapped I/O for optimal performance on 64-bit systems.
    
    if (enableCarving) {
        float baseProgress = 0.0f;
        if (enableMft && enableUsn) baseProgress = 0.66f;
        else if (enableMft || enableUsn) baseProgress = 0.5f;
        
        onProgress(L"Stage 3: Carving files from free space (memory-mapped)...", baseProgress);
        
        // Use optimized memory-mapped version for better performance
        bool stage3Success = ProcessFileCarvingMemoryMapped(disk, onFileFound, onProgress, shouldStop);
        anySuccess = anySuccess || stage3Success;
    }
    
    onProgress(L"Scan complete!", 1.0f);
    return anySuccess;
}

// Process USN Journal to find deleted files with MFT correlation.
bool DiskForensicsCore::ProcessUsnJournal(
    DiskHandle& disk,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    bool& shouldStop)
{
    try {
        // Read NTFS boot sector to get geometry
        auto boot = m_ntfsScanner->ReadBootSector(disk);
        
        if (std::memcmp(boot.oemID, "NTFS    ", 8) != 0) {
            onProgress(L"USN Journal: Not a valid NTFS drive", 0.66f);
            return false;
        }

        // Parse USN Journal records
        auto recordsByMft = m_usnJournalScanner->ParseJournal(disk, m_config.usnJournalLimit);
        
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
                
                // Only process file deletions (not directories)
                if (record.IsDeletion() && !record.IsDirectory()) {
                    
                    // Read current MFT record at this index
                    uint64_t mftIndex = record.MftIndex();
                    
                    // Skip if already processed in Stage 1 (MFT scan)
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
                        
                        // Check FILE signature
                        if (std::memcmp(mftRec->signature, "FILE", 4) == 0) {
                            // CRITICAL: Compare sequence numbers
                            // If equal, MFT record still describes the same file (tombstone state)
                            if (mftRec->sequenceNumber == usnSequenceNumber) {
                                // Match! Parse MFT record to get cluster data
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
                        // MFT record was overwritten by another file (different sequence number)
                        // or is unreadable. Report metadata only.
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
                
                // Update progress every 1000 records
                if ((processed % 1000) == 0) {
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

// Legacy cluster-by-cluster file carving implementation.
bool DiskForensicsCore::ProcessFileCarving(
    DiskHandle& disk,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    bool& shouldStop)
{
    try {
        uint64_t sectorSize = disk.GetSectorSize();
        uint64_t diskSize = disk.GetDiskSize();
        uint64_t totalSectors = diskSize / sectorSize;
        
        auto bootData = disk.ReadSectors(0, 1, sectorSize);
        if (bootData.size() < 512) {
            onProgress(L"Cannot read boot sector for carving", 0.99f);
            return false;
        }
        
        uint8_t sectorsPerCluster = bootData[13];
        if (sectorsPerCluster == 0) sectorsPerCluster = 8;
        
        uint64_t bytesPerCluster = sectorsPerCluster * sectorSize;
        uint64_t totalClusters = totalSectors / sectorsPerCluster;
        
        // Scan the entire disk unless a limit is explicitly set
        uint64_t maxClusters = totalClusters;
        if (m_config.fileCarvingClusterLimit > 0 && m_config.fileCarvingClusterLimit < totalClusters) {
            maxClusters = m_config.fileCarvingClusterLimit;
        }
        
        uint64_t clusterHeapOffset = 0;
        
        auto signatures = FileSignatures::GetAllSignatures();
        uint64_t filesFound = 0;
        
        wchar_t startMsg[256];
        swprintf_s(startMsg, L"File carving: Scanning %llu clusters (%.2f GB)...", 
                  maxClusters, (maxClusters * bytesPerCluster) / 1000000000.0);
        onProgress(startMsg, 0.66f);
        
        // Scan cluster by cluster - this method is slower but more thorough
        for (uint64_t cluster = 2; cluster < maxClusters && filesFound < m_config.fileCarvingMaxFiles; cluster++) {
            
            // Check stop flag every 1000 clusters for responsiveness
            if ((cluster % 1000) == 0 && shouldStop) {
                wchar_t stopMsg[256];
                swprintf_s(stopMsg, L"File carving stopped at cluster %llu: %llu files found", 
                          cluster, filesFound);
                onProgress(stopMsg, 1.0f);
                return filesFound > 0;
            }
            
            // Scan this cluster for file signatures
            auto signature = m_fileCarver->ScanClusterForSignature(
                disk, cluster, sectorsPerCluster, clusterHeapOffset, 
                sectorSize, signatures
            );
            
            if (signature.has_value()) {
                auto fileSize = m_fileCarver->ParseFileSize(
                    disk, cluster, sectorsPerCluster, clusterHeapOffset,
                    sectorSize, signature.value()
                );
                
                if (fileSize.has_value() && fileSize.value() > 0) {
                    DeletedFileEntry carvedFile;
                    carvedFile.name = std::to_wstring(filesFound + 1) + L"." + 
                                     std::wstring(signature->extension, 
                                                signature->extension + strlen(signature->extension));
                    carvedFile.path = L"<carved from free space>";
                    carvedFile.size = fileSize.value();
                    carvedFile.sizeFormatted = FormatFileSize(fileSize.value());
                    carvedFile.filesystemType = L"NTFS";
                    carvedFile.hasDeletedTime = false;
                    carvedFile.isRecoverable = true;
                    carvedFile.clusterSize = bytesPerCluster;
                    carvedFile.clusters = {cluster};
                    
                    // Calculate clusters needed for entire file
                    uint64_t clustersNeeded = (fileSize.value() + bytesPerCluster - 1) / bytesPerCluster;
                    if (clustersNeeded > 1) {
                        for (uint64_t i = 1; i < clustersNeeded; i++) {
                            carvedFile.clusters.push_back(cluster + i);
                        }
                    }
                    
                    onFileFound(carvedFile);
                    filesFound++;
                    
                    // Skip clusters occupied by this file
                    uint64_t clustersToSkip = (fileSize.value() + bytesPerCluster - 1) / bytesPerCluster;
                    cluster += std::max<uint64_t>(1, clustersToSkip - 1);
                }
            }
            
            // Update progress every 10,000 clusters (~40MB)
            if ((cluster % 10000) == 0) {
                float progress = 0.66f + (0.34f * (static_cast<float>(cluster) / maxClusters));
                float percentDone = (static_cast<float>(cluster) / maxClusters) * 100.0f;
                float gbProcessed = (cluster * bytesPerCluster) / 1000000000.0f;
                float gbTotal = (maxClusters * bytesPerCluster) / 1000000000.0f;
                
                wchar_t statusMsg[256];
                swprintf_s(statusMsg, L"File carving: %.1f%% (%.2f / %.2f GB) - %llu files found", 
                          percentDone, gbProcessed, gbTotal, filesFound);
                onProgress(statusMsg, progress);
                
                if (filesFound >= m_config.fileCarvingMaxFiles) {
                    wchar_t limitMsg[256];
                    swprintf_s(limitMsg, L"File carving limit reached: %llu files", filesFound);
                    onProgress(limitMsg, progress);
                    break;
                }
            }
        }
        
        wchar_t completeMsg[256];
        float percentScanned = (static_cast<float>(maxClusters) / totalClusters) * 100.0f;
        swprintf_s(completeMsg, L"File carving complete: %llu files found (%.1f%% of disk scanned)", 
                   filesFound, percentScanned);
        onProgress(completeMsg, 1.0f);
        
        return filesFound > 0;
    }
    catch (const std::exception& e) {
        (void)e;
        onProgress(L"File carving failed", 0.99f);
        return false;
    }
}

// Optimized file carving using memory-mapped I/O for batch processing.
bool DiskForensicsCore::ProcessFileCarvingMemoryMapped(
    DiskHandle& disk,
    FileFoundCallback onFileFound,
    ProgressCallback onProgress,
    bool& shouldStop)
{
    try {
        uint64_t sectorSize = disk.GetSectorSize();
        uint64_t diskSize = disk.GetDiskSize();
        uint64_t totalSectors = diskSize / sectorSize;
        
        auto bootData = disk.ReadSectors(0, 1, sectorSize);
        if (bootData.size() < 512) {
            onProgress(L"Cannot read boot sector for carving", 0.99f);
            return false;
        }
        
        uint8_t sectorsPerCluster = bootData[13];
        if (sectorsPerCluster == 0) sectorsPerCluster = 8; // Default 4KB clusters
        
        uint64_t bytesPerCluster = sectorsPerCluster * sectorSize;
        uint64_t totalClusters = totalSectors / sectorsPerCluster;
        
        // Apply limit only if set, otherwise scan the entire disk
        uint64_t maxClusters = totalClusters;
        if (m_config.fileCarvingClusterLimit > 0 && m_config.fileCarvingClusterLimit < totalClusters) {
            maxClusters = m_config.fileCarvingClusterLimit;
            wchar_t limitMsg[256];
            swprintf_s(limitMsg, L"File carving limited to %llu clusters (%.2f GB)", 
                      maxClusters, (maxClusters * bytesPerCluster) / 1000000000.0);
            onProgress(limitMsg, 0.66f);
        } else {
            wchar_t fullMsg[256];
            swprintf_s(fullMsg, L"File carving scanning FULL DISK: %llu clusters (%.2f GB)", 
                      totalClusters, (totalClusters * bytesPerCluster) / 1000000000.0);
            onProgress(fullMsg, 0.66f);
        }
        
        uint64_t clusterHeapOffset = 0;
        
        auto signatures = FileSignatures::GetAllSignatures();
        uint64_t filesFound = 0;
        
        // Process disk in large batches using memory-mapped I/O
        // Batch size depends on available memory - 256MB is safe on most systems
        const uint64_t CLUSTERS_PER_BATCH = 65536; // 256MB at 4KB clusters
        
        uint64_t clustersProcessed = 0;
        
        for (uint64_t batchStart = 2; batchStart < maxClusters && filesFound < m_config.fileCarvingMaxFiles; ) {
            if (shouldStop) {
                wchar_t stopMsg[256];
                swprintf_s(stopMsg, L"File carving stopped: %llu files found", filesFound);
                onProgress(stopMsg, 1.0f);
                return filesFound > 0;
            }
            
            uint64_t clustersInBatch = std::min(CLUSTERS_PER_BATCH, maxClusters - batchStart);
            
            // Scan batch using memory-mapped I/O
            auto carvedFiles = m_fileCarver->ScanRegionMemoryMapped(
                disk,
                batchStart,
                clustersInBatch,
                sectorsPerCluster,
                clusterHeapOffset,
                sectorSize,
                signatures,
                m_config.fileCarvingMaxFiles - filesFound
            );
            
            // Report found files
            for (const auto& carved : carvedFiles) {
                DeletedFileEntry entry;
                entry.name = std::to_wstring(filesFound + 1) + L"." + 
                            std::wstring(carved.signature.extension, 
                                       carved.signature.extension + strlen(carved.signature.extension));
                entry.path = L"<carved from free space>";
                entry.size = carved.fileSize;
                entry.sizeFormatted = FormatFileSize(carved.fileSize);
                entry.filesystemType = L"NTFS";
                entry.hasDeletedTime = false;
                entry.isRecoverable = true;
                entry.clusterSize = bytesPerCluster;
                
                // Build cluster list
                uint64_t clustersNeeded = (carved.fileSize + bytesPerCluster - 1) / bytesPerCluster;
                for (uint64_t i = 0; i < clustersNeeded; i++) {
                    entry.clusters.push_back(carved.startCluster + i);
                }
                
                onFileFound(entry);
                filesFound++;
            }
            
            clustersProcessed += clustersInBatch;
            
            // Update progress more frequently for better user experience
            uint64_t progressInterval = std::max<uint64_t>(1000, maxClusters / 100);
			if ((batchStart % progressInterval) == 0 || batchStart + clustersInBatch >= maxClusters) {

                float progress = 0.66f + (0.34f * (static_cast<float>(batchStart) / maxClusters));
                wchar_t statusMsg[256];
                
                // Show percentage and estimated time
                float percentDone = (static_cast<float>(batchStart) / maxClusters) * 100.0f;
                float gbProcessed = (batchStart * bytesPerCluster) / 1000000000.0f;
                float gbTotal = (maxClusters * bytesPerCluster) / 1000000000.0f;
                
                swprintf_s(statusMsg, L"File carving: %.1f%% (%.2f / %.2f GB) - %llu files found", 
                          percentDone, gbProcessed, gbTotal, filesFound);
                onProgress(statusMsg, progress);
            }
            
            // Move to next batch
            batchStart += clustersInBatch;
            
            if (filesFound >= m_config.fileCarvingMaxFiles) {
                wchar_t limitMsg[256];
                swprintf_s(limitMsg, L"File carving limit reached: %llu files (scanned %.1f%% of disk)", 
                          filesFound, (static_cast<float>(batchStart) / maxClusters) * 100.0f);
                onProgress(limitMsg, 1.0f);
                break;
            }
        }
        
        wchar_t completeMsg[256];
        float percentScanned = (static_cast<float>(clustersProcessed) / totalClusters) * 100.0f;
        swprintf_s(completeMsg, L"File carving complete: %llu files found (%.1f%% of disk scanned)", 
                   filesFound, percentScanned);
        onProgress(completeMsg, 1.0f);
        
        return filesFound > 0;
    }
    catch (const std::exception& e) {
        (void)e;
        onProgress(L"File carving failed", 0.99f);
        return false;
    }
}

std::wstring FormatFileSize(uint64_t bytes) {
    wchar_t buffer[64];
    if (bytes >= 1000000000) {
        swprintf_s(buffer, L"%.2f GB", bytes / 1000000000.0);
    } else if (bytes >= 1000000) {
        swprintf_s(buffer, L"%.2f MB", bytes / 1000000.0);
    } else if (bytes >= 1000) {
        swprintf_s(buffer, L"%.2f KB", bytes / 1000.0);
    } else {
        swprintf_s(buffer, L"%llu bytes", bytes);
    }
    return buffer;
}

} // namespace KVC