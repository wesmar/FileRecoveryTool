// ============================================================================
// FragmentedRecoveryEngine.h - Fragment-Aware File Recovery
// ============================================================================
// Enhanced recovery engine that properly handles fragmented files.
// Uses FragmentMap for accurate data extraction across non-contiguous clusters.
// Provides parallel cluster validation for heavily fragmented files.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "FragmentedFile.h"
#include "ForensicsExceptions.h"
#include <vector>
#include <string>
#include <functional>
#include <future>
#include <atomic>

namespace KVC {

class FragmentedRecoveryEngine {
public:
    FragmentedRecoveryEngine();
    ~FragmentedRecoveryEngine();

    using ProgressCallback = std::function<void(const std::wstring&, float)>;
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    struct RecoveryConfig {
        bool useMemoryMapping;          // Use MapDiskRegion for reads
        bool validateClusters;          // Verify cluster readability before recovery
        bool parallelValidation;        // Use parallel threads for validation
        size_t maxParallelThreads;      // Max threads for parallel operations
        size_t readBufferSize;          // Size of read buffer (default 64KB)
        uint64_t maxFileSize;           // Max file size to recover (0 = unlimited)
        
        RecoveryConfig()
            : useMemoryMapping(true)
            , validateClusters(true)
            , parallelValidation(true)
            , maxParallelThreads(4)
            , readBufferSize(65536)
            , maxFileSize(0)
        {}
    };
    
    void SetConfig(const RecoveryConfig& config) { m_config = config; }
    const RecoveryConfig& GetConfig() const { return m_config; }
    
    // ========================================================================
    // Validation
    // ========================================================================
    
    // Validate destination is not on source drive
    bool ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath);
    
    // Validate all clusters in a FragmentMap are readable
    struct ValidationResult {
        bool allClustersValid;
        uint64_t validClusters;
        uint64_t invalidClusters;
        std::vector<uint64_t> failedClusters;
        std::string errorMessage;
    };
    
    ValidationResult ValidateFragmentMap(
        DiskHandle& disk,
        const FragmentMap& fragments,
        uint64_t sectorSize
    );
    
    // Parallel validation for large fragmented files
    ValidationResult ValidateFragmentMapParallel(
        DiskHandle& disk,
        const FragmentMap& fragments,
        uint64_t sectorSize,
        ProgressCallback onProgress = nullptr
    );
    
    // ========================================================================
    // Recovery Operations
    // ========================================================================
    
    // Recover a single file using FragmentMap
    bool RecoverFragmentedFile(
        DiskHandle& disk,
        const FragmentedFile& file,
        const std::wstring& outputPath,
        ProgressCallback onProgress
    );
    
    // Recover file from DeletedFileEntry (auto-builds FragmentMap)
    bool RecoverFile(
        const DeletedFileEntry& file,
        wchar_t sourceDrive,
        const std::wstring& destinationPath,
        ProgressCallback onProgress
    );
    
    // Batch recovery of multiple files
    struct BatchResult {
        int successCount;
        int failedCount;
        std::vector<std::wstring> failedFiles;
        std::vector<std::wstring> successFiles;
    };
    
    BatchResult RecoverMultipleFiles(
        const std::vector<DeletedFileEntry>& files,
        wchar_t sourceDrive,
        const std::wstring& destinationFolder,
        ProgressCallback onProgress,
        std::atomic<bool>* shouldStop = nullptr
    );
    
    // ========================================================================
    // Memory-Mapped Recovery
    // ========================================================================
    
    // Recover using memory-mapped I/O for each fragment
    bool RecoverWithMapping(
        DiskHandle& disk,
        const FragmentMap& fragments,
        uint64_t fileSize,
        const std::wstring& outputPath,
        ProgressCallback onProgress
    );

private:
    // Build FragmentMap from DeletedFileEntry
    FragmentMap BuildFragmentMap(const DeletedFileEntry& file);
    
    // Write data from disk to output file, following fragment map
    bool WriteFragmentedData(
        DiskHandle& disk,
        const FragmentMap& fragments,
        uint64_t fileSize,
        std::ofstream& outFile,
        uint64_t sectorSize,
        ProgressCallback& onProgress
    );
    
    // Write data using memory-mapped reads
    bool WriteFragmentedDataMapped(
        DiskHandle& disk,
        const FragmentMap& fragments,
        uint64_t fileSize,
        std::ofstream& outFile,
        uint64_t sectorSize,
        ProgressCallback& onProgress
    );
    
    // Read a single cluster run from disk
    std::vector<uint8_t> ReadClusterRun(
        DiskHandle& disk,
        const ClusterRun& run,
        uint64_t sectorSize,
        uint64_t bytesPerCluster
    );
    
    // Validate a single cluster is readable
    bool ValidateCluster(
        DiskHandle& disk,
        uint64_t cluster,
        uint64_t sectorSize,
        uint64_t bytesPerCluster
    );
    
    RecoveryConfig m_config;
};

} // namespace KVC
