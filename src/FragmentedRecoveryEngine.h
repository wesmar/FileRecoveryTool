// ============================================================================
// FragmentedRecoveryEngine.h - Fragment-Aware File Recovery
// ============================================================================
// Enhanced recovery engine that properly handles fragmented files.
// Uses VolumeReader for consistent LCN-based cluster access.
// Uses FragmentMap for accurate data extraction across non-contiguous clusters.
// Provides parallel cluster validation for heavily fragmented files.
// ============================================================================

#pragma once

#include <climits>
#include "DiskForensicsCore.h"
#include "FragmentedFile.h"
#include "VolumeReader.h"
#include "VolumeGeometry.h"
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
    // Throws: DestinationInvalidError if invalid
    void ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath);

    // Validate all clusters in a FragmentMap are readable
    struct ValidationResult {
        bool allClustersValid;
        uint64_t validClusters;
        uint64_t invalidClusters;
        std::vector<uint64_t> failedClusters;
        std::string errorMessage;
    };

    ValidationResult ValidateFragmentMap(
        VolumeReader& reader,
        const FragmentMap& fragments
    );

    // Parallel validation for large fragmented files
    ValidationResult ValidateFragmentMapParallel(
        VolumeReader& reader,
        const FragmentMap& fragments,
        ProgressCallback onProgress = nullptr
    );

    // ========================================================================
    // Recovery Operations
    // ========================================================================

    // Recover a single file using FragmentMap
    // Throws: RecoveryError, DiskReadError
    void RecoverFragmentedFile(
        VolumeReader& reader,
        const FragmentedFile& file,
        const std::wstring& outputPath,
        ProgressCallback onProgress
    );

    // Recover file from RecoveryCandidate (auto-builds FragmentMap)
    // Throws: DestinationInvalidError, RecoveryError, DiskReadError
    void RecoverFile(
        const RecoveryCandidate& file,
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
        const std::vector<RecoveryCandidate>& files,
        wchar_t sourceDrive,
        const std::wstring& destinationFolder,
        ProgressCallback onProgress,
        std::atomic<bool>* shouldStop = nullptr
    );

    // ========================================================================
    // Memory-Mapped Recovery
    // ========================================================================

    // Recover using memory-mapped I/O for each fragment
    // Throws: RecoveryError
    void RecoverWithMapping(
        VolumeReader& reader,
        const FragmentMap& fragments,
        uint64_t fileSize,
        const std::wstring& outputPath,
        ProgressCallback onProgress
    );

private:
    // Build VolumeGeometry from RecoveryCandidate
    VolumeGeometry BuildGeometry(DiskHandle& disk, const RecoveryCandidate& file);

    // Build FragmentMap from RecoveryCandidate
    FragmentMap BuildFragmentMap(const RecoveryCandidate& file);

    // Write data from disk to output file, following fragment map
    // Throws: RecoveryError, DiskReadError
    void WriteFragmentedData(
        VolumeReader& reader,
        const FragmentMap& fragments,
        uint64_t fileSize,
        std::ofstream& outFile,
        const ProgressCallback& onProgress
    );

    // Write data using memory-mapped reads
    // Throws: RecoveryError
    void WriteFragmentedDataMapped(
        VolumeReader& reader,
        const FragmentMap& fragments,
        uint64_t fileSize,
        std::ofstream& outFile,
        const ProgressCallback& onProgress
    );

    // Validate a single cluster is readable using VolumeReader
    bool ValidateCluster(VolumeReader& reader, uint64_t cluster);

    RecoveryConfig m_config;
};

} // namespace KVC
