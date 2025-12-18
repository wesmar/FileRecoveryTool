// ============================================================================
// DiskForensicsCore.h - Core Disk Forensics Engine
// ============================================================================
// Manages low-level disk I/O and coordinates forensic scanning operations.
// Orchestrates multi-stage recovery including MFT scanning, USN analysis, and file carving.
// ============================================================================
#pragma once

#define NOMINMAX
#include <Windows.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>
#include <chrono>
#include <set>

namespace KVC {

struct ClusterRange {
    uint64_t start;
    uint64_t count;
};

struct DeletedFileEntry {
    std::wstring name;
    std::wstring path;
    uint64_t size;
    std::wstring sizeFormatted;
    uint64_t fileRecord;
    std::vector<uint64_t> clusters;
    std::vector<ClusterRange> clusterRanges;
    std::vector<uint8_t> residentData;
    uint64_t clusterSize;
    bool isRecoverable;
    std::wstring filesystemType;
    std::chrono::system_clock::time_point deletedTime;
    bool hasDeletedTime;
};

enum class FilesystemType {
    NTFS,
    ExFAT,
    FAT32,
    Unknown
};

struct ScanConfiguration {
    uint64_t ntfsMftSystemDriveLimit = 300000;
    uint64_t ntfsMftSpareDriveLimit = 10000000;
    uint64_t usnJournalLimit = 1000000;
    uint64_t fileCarvingClusterLimit = 0;
    uint64_t fileCarvingMaxFiles = 10000000;
    uint64_t exfatDirectoryEntriesLimit = 1000000;
    size_t parallelThreads = 4;

    static ScanConfiguration Load();
    bool Save() const;
};

class DiskHandle {
public:
    explicit DiskHandle(wchar_t driveLetter);
    ~DiskHandle();

    bool Open();
    void Close();
    bool IsOpen() const { return m_handle != INVALID_HANDLE_VALUE; }

    std::vector<uint8_t> ReadSectors(uint64_t startSector, uint64_t numSectors, uint64_t sectorSize);
    uint64_t GetSectorSize() const;
    uint64_t GetDiskSize() const;

    struct MappedRegion {
        const uint8_t* data;
        uint64_t size;
        uint64_t diskOffset;
        
        MappedRegion() : data(nullptr), size(0), diskOffset(0) {}
        bool IsValid() const { return data != nullptr; }
    };
    
    MappedRegion MapDiskRegion(uint64_t offset, uint64_t size);
    void UnmapRegion(MappedRegion& region);

private:
    wchar_t m_driveLetter;
    HANDLE m_handle;
    HANDLE m_mappingHandle;
    void* m_mappedView;
};

class NTFSScanner;
class ExFATScanner;
class FAT32Scanner;
class FileCarver;
class UsnJournalScanner;
struct CarvingDiagnostics;

class DiskForensicsCore {
public:
    DiskForensicsCore();
    ~DiskForensicsCore();

    using ProgressCallback = std::function<void(const std::wstring&, float)>;
    using FileFoundCallback = std::function<void(const DeletedFileEntry&)>;

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

    bool ProcessFileCarving(
        DiskHandle& disk,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        bool& shouldStop
    );
    
    bool ProcessFileCarvingMemoryMapped(
        DiskHandle& disk,
        FileFoundCallback onFileFound,
        ProgressCallback onProgress,
        bool& shouldStop
    );

    std::unique_ptr<NTFSScanner> m_ntfsScanner;
    std::unique_ptr<ExFATScanner> m_exfatScanner;
    std::unique_ptr<FAT32Scanner> m_fat32Scanner;
    std::unique_ptr<FileCarver> m_fileCarver;
    std::unique_ptr<UsnJournalScanner> m_usnJournalScanner;
    ScanConfiguration m_config;
    std::set<uint64_t> m_processedMftRecords;
};

std::wstring FormatFileSize(uint64_t bytes);

} // namespace KVC
