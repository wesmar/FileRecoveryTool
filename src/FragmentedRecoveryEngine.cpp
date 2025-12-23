// ============================================================================
// FragmentedRecoveryEngine.cpp - Fragment-Aware File Recovery
// ============================================================================
// Implementation of fragmentation-aware file recovery engine.
// Uses VolumeReader for consistent LCN-based cluster access.
// Reads data across non-contiguous clusters and reconstructs complete files.
// ============================================================================

#include "FragmentedRecoveryEngine.h"
#include "SafetyLimits.h"
#include "StringUtils.h"

#include <climits>
#include <fstream>
#include <filesystem>
#include <cwctype>
#include <algorithm>
#include <thread>
#include <mutex>

namespace KVC {

FragmentedRecoveryEngine::FragmentedRecoveryEngine() = default;
FragmentedRecoveryEngine::~FragmentedRecoveryEngine() = default;

// ============================================================================
// Destination Validation
// ============================================================================

void FragmentedRecoveryEngine::ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath) {
    if (destPath.length() < 2) {
        throw DestinationInvalidError("Destination path too short");
    }

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(destPath.c_str(), MAX_PATH, fullPath, nullptr)) {
        throw DestinationInvalidError("Cannot resolve destination path");
    }

    // UNC paths are always allowed
    if (fullPath[0] == L'\\' && fullPath[1] == L'\\') {
        return;
    }

    if (fullPath[1] != L':') {
        throw DestinationInvalidError("Invalid path format");
    }

    wchar_t destDrive = static_cast<wchar_t>(towupper(fullPath[0]));
    wchar_t srcDrive = static_cast<wchar_t>(towupper(sourceDrive));

    if (destDrive == srcDrive) {
        throw DestinationInvalidError("Cannot recover to source drive");
    }
}

// ============================================================================
// Geometry Builder
// ============================================================================

VolumeGeometry FragmentedRecoveryEngine::BuildGeometry(DiskHandle& disk, const RecoveryCandidate& file) {
    VolumeGeometry geom;

    geom.sectorSize = disk.GetSectorSize();
    geom.bytesPerCluster = file.file.GetFragments().BytesPerCluster();
    geom.volumeStartOffset = file.volumeStartOffset;

    uint64_t availableSpace = disk.GetDiskSize();
    if (availableSpace > geom.volumeStartOffset) {
        availableSpace -= geom.volumeStartOffset;
    }
    geom.totalClusters = availableSpace / geom.bytesPerCluster;

    // Determine filesystem type from source
    if (file.source == RecoverySource::MFT || file.source == RecoverySource::USN) {
        geom.fsType = FilesystemType::NTFS;
    } else if (file.source == RecoverySource::ExFAT) {
        geom.fsType = FilesystemType::ExFAT;
    } else if (file.source == RecoverySource::FAT32) {
        geom.fsType = FilesystemType::FAT32;
    } else {
        geom.fsType = FilesystemType::Unknown;
    }

    return geom;
}

// ============================================================================
// Fragment Map Validation
// ============================================================================

FragmentedRecoveryEngine::ValidationResult FragmentedRecoveryEngine::ValidateFragmentMap(
    VolumeReader& reader,
    const FragmentMap& fragments)
{
    ValidationResult result;
    result.allClustersValid = true;
    result.validClusters = 0;
    result.invalidClusters = 0;

    if (fragments.BytesPerCluster() == 0) {
        result.allClustersValid = false;
        result.errorMessage = "Invalid bytes per cluster (0)";
        return result;
    }

    const auto& runs = fragments.GetRuns();

    for (const auto& run : runs) {
        for (uint64_t i = 0; i < run.clusterCount; ++i) {
            uint64_t cluster = run.startCluster + i;

            if (ValidateCluster(reader, cluster)) {
                result.validClusters++;
            } else {
                result.invalidClusters++;
                result.failedClusters.push_back(cluster);
                result.allClustersValid = false;
            }
        }
    }

    if (!result.allClustersValid) {
        result.errorMessage = "Some clusters are unreadable";
    }

    return result;
}

FragmentedRecoveryEngine::ValidationResult FragmentedRecoveryEngine::ValidateFragmentMapParallel(
    VolumeReader& reader,
    const FragmentMap& fragments,
    ProgressCallback onProgress)
{
    ValidationResult result;
    result.allClustersValid = true;
    result.validClusters = 0;
    result.invalidClusters = 0;

    if (fragments.BytesPerCluster() == 0) {
        result.allClustersValid = false;
        result.errorMessage = "Invalid bytes per cluster (0)";
        return result;
    }

    // Build flat list of clusters
    std::vector<uint64_t> allClusters;
    const auto& runs = fragments.GetRuns();

    for (const auto& run : runs) {
        for (uint64_t i = 0; i < run.clusterCount; ++i) {
            allClusters.push_back(run.startCluster + i);
        }
    }

    if (allClusters.empty()) {
        return result;
    }

    // Parallel validation
    size_t numThreads = std::min(m_config.maxParallelThreads, allClusters.size());
    size_t clustersPerThread = (allClusters.size() + numThreads - 1) / numThreads;

    std::mutex resultMutex;
    std::atomic<uint64_t> processedClusters(0);
    std::vector<std::future<std::vector<uint64_t>>> futures;

    for (size_t t = 0; t < numThreads; ++t) {
        size_t start = t * clustersPerThread;
        size_t end = std::min(start + clustersPerThread, allClusters.size());

        if (start >= allClusters.size()) break;

        futures.push_back(std::async(std::launch::async, [&, start, end]() {
            std::vector<uint64_t> localFailed;

            for (size_t i = start; i < end; ++i) {
                uint64_t cluster = allClusters[i];

                bool valid;
                {
                    std::lock_guard<std::mutex> lock(resultMutex);
                    valid = ValidateCluster(reader, cluster);
                }

                if (!valid) {
                    localFailed.push_back(cluster);
                }

                processedClusters++;

                if (onProgress && (processedClusters % 100 == 0)) {
                    float progress = static_cast<float>(processedClusters) / allClusters.size();
                    wchar_t msg[256];
                    swprintf_s(msg, L"Validating clusters: %llu / %zu",
                              processedClusters.load(), allClusters.size());
                    onProgress(msg, progress);
                }
            }

            return localFailed;
        }));
    }

    for (auto& future : futures) {
        auto failed = future.get();
        if (!failed.empty()) {
            result.failedClusters.insert(result.failedClusters.end(),
                                        failed.begin(), failed.end());
            result.allClustersValid = false;
        }
    }

    result.invalidClusters = result.failedClusters.size();
    result.validClusters = allClusters.size() - result.invalidClusters;

    if (!result.allClustersValid) {
        result.errorMessage = "Some clusters are unreadable";
    }

    return result;
}

bool FragmentedRecoveryEngine::ValidateCluster(VolumeReader& reader, uint64_t cluster) {
    try {
        auto data = reader.ReadClusters(cluster, 1);
        return !data.empty();
    } catch (const ClusterOutOfBoundsError&) {
        return false;
    } catch (const DiskReadError&) {
        return false;
    }
}

// ============================================================================
// Fragment Map Building
// ============================================================================

FragmentMap FragmentedRecoveryEngine::BuildFragmentMap(const RecoveryCandidate& file) {
    // Return the FragmentMap directly from the FragmentedFile
    return file.file.GetFragments();
}

// ============================================================================
// Recovery Operations
// ============================================================================

void FragmentedRecoveryEngine::RecoverFragmentedFile(
    VolumeReader& reader,
    const FragmentedFile& file,
    const std::wstring& outputPath,
    ProgressCallback onProgress)
{
    // Handle resident data
    if (file.HasResidentData()) {
        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            throw RecoveryError("Failed to create output file");
        }

        const auto& resData = file.GetResidentData();
        outFile.write(reinterpret_cast<const char*>(resData.data()), resData.size());
        outFile.close();

        if (!outFile.good()) {
            throw RecoveryError("Failed to write resident data");
        }
        return;
    }

    const FragmentMap& fragments = file.GetFragments();

    if (fragments.IsEmpty()) {
        throw RecoveryError("No cluster data available for recovery");
    }

    // Optionally validate clusters
    if (m_config.validateClusters) {
        ValidationResult validation;

        if (m_config.parallelValidation && fragments.FragmentCount() > 10) {
            validation = ValidateFragmentMapParallel(reader, fragments, onProgress);
        } else {
            validation = ValidateFragmentMap(reader, fragments);
        }

        if (!validation.allClustersValid && onProgress) {
            wchar_t msg[512];
            swprintf_s(msg, L"Warning: %llu clusters unreadable, recovery may be incomplete",
                      validation.invalidClusters);
            onProgress(msg, -1.0f);
        }
    }

    // Recover using appropriate method
    if (m_config.useMemoryMapping) {
        RecoverWithMapping(reader, fragments, file.GetSize(), outputPath, onProgress);
    } else {
        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            throw RecoveryError("Failed to create output file");
        }

        WriteFragmentedData(reader, fragments, file.GetSize(), outFile, onProgress);
        outFile.close();
    }
}

void FragmentedRecoveryEngine::RecoverFile(
    const RecoveryCandidate& file,
    wchar_t sourceDrive,
    const std::wstring& destinationPath,
    ProgressCallback onProgress)
{
    ValidateDestination(sourceDrive, destinationPath);

    // Handle resident data
    if (file.file.HasResidentData()) {
        const auto& residentData = file.file.GetResidentData();
        std::ofstream outFile(destinationPath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            throw RecoveryError("Failed to create output file");
        }

        outFile.write(reinterpret_cast<const char*>(residentData.data()),
                     residentData.size());
        outFile.close();

        if (!outFile.good()) {
            throw RecoveryError("Failed to write resident data");
        }
        return;
    }

    FragmentMap fragments = BuildFragmentMap(file);

    if (fragments.IsEmpty()) {
        throw RecoveryError("No cluster data available");
    }

    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        throw DiskReadError(0, 0, GetLastError());
    }

    VolumeGeometry geom = BuildGeometry(disk, file);
    VolumeReader reader(disk, geom);

    std::ofstream outFile(destinationPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        throw RecoveryError("Failed to create output file");
    }

    if (m_config.useMemoryMapping) {
        outFile.close();
        RecoverWithMapping(reader, fragments, file.fileSize, destinationPath, onProgress);
    } else {
        WriteFragmentedData(reader, fragments, file.fileSize, outFile, onProgress);
        outFile.close();
    }

    if (onProgress) {
        wchar_t msg[256];
        swprintf_s(msg, L"Recovered: %s (%s)", file.name.c_str(), file.sizeFormatted.c_str());
        onProgress(msg, -1.0f);
    }
}

FragmentedRecoveryEngine::BatchResult FragmentedRecoveryEngine::RecoverMultipleFiles(
    const std::vector<RecoveryCandidate>& files,
    wchar_t sourceDrive,
    const std::wstring& destinationFolder,
    ProgressCallback onProgress,
    std::atomic<bool>* shouldStop)
{
    BatchResult result;
    result.successCount = 0;
    result.failedCount = 0;

    if (files.empty()) {
        if (onProgress) {
            onProgress(L"No files to recover", 0.0f);
        }
        return result;
    }

    ValidateDestination(sourceDrive, destinationFolder);

    try {
        std::filesystem::create_directories(destinationFolder);
    } catch (const std::exception&) {
        throw RecoveryError("Failed to create destination folder");
    }

    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        throw DiskReadError(0, 0, GetLastError());
    }

    int totalFiles = static_cast<int>(files.size());

    for (int i = 0; i < totalFiles; ++i) {
        if (shouldStop && *shouldStop) {
            if (onProgress) {
                onProgress(L"Recovery cancelled by user", -1.0f);
            }
            break;
        }

        const auto& file = files[i];
        std::wstring destPath = destinationFolder + L"\\" + file.name;

        // Handle duplicate filenames
        int suffix = 1;
        while (std::filesystem::exists(destPath)) {
            size_t dotPos = file.name.rfind(L'.');
            std::wstring baseName, ext;
            if (dotPos != std::wstring::npos) {
                baseName = file.name.substr(0, dotPos);
                ext = file.name.substr(dotPos);
            } else {
                baseName = file.name;
                ext = L"";
            }
            destPath = destinationFolder + L"\\" + baseName + L"_" + std::to_wstring(suffix) + ext;
            suffix++;
        }

        float progress = static_cast<float>(i) / totalFiles;

        if (onProgress) {
            wchar_t progressMsg[512];
            swprintf_s(progressMsg, L"Recovering %s (%d/%d)", file.name.c_str(), i + 1, totalFiles);
            onProgress(progressMsg, progress);
        }

        try {
            // Handle resident data
            if (file.file.HasResidentData()) {
                const auto& residentData = file.file.GetResidentData();
                std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
                if (outFile.is_open()) {
                    outFile.write(reinterpret_cast<const char*>(residentData.data()),
                                 residentData.size());
                    outFile.close();
                    if (outFile.good()) {
                        result.successCount++;
                        result.successFiles.push_back(file.name);
                        continue;
                    }
                }
                throw RecoveryError("Failed to write resident data");
            }

            FragmentMap fragments = BuildFragmentMap(file);

            if (fragments.IsEmpty()) {
                throw RecoveryError("No cluster data");
            }

            VolumeGeometry geom = BuildGeometry(disk, file);
            VolumeReader reader(disk, geom);

            if (m_config.useMemoryMapping) {
                RecoverWithMapping(reader, fragments, file.fileSize, destPath, nullptr);
            } else {
                std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
                if (!outFile.is_open()) {
                    throw RecoveryError("Failed to create output file");
                }
                ProgressCallback nullCallback = nullptr;
                WriteFragmentedData(reader, fragments, file.fileSize, outFile, nullCallback);
                outFile.close();
            }

            result.successCount++;
            result.successFiles.push_back(file.name);

        } catch (const ForensicsException&) {
            result.failedCount++;
            result.failedFiles.push_back(file.name);
        }
    }

    if (onProgress) {
        wchar_t completeMsg[256];
        swprintf_s(completeMsg, L"Recovery complete: %d/%d files recovered",
                  result.successCount, totalFiles);
        onProgress(completeMsg, 1.0f);
    }

    return result;
}

// ============================================================================
// Memory-Mapped Recovery
// ============================================================================

void FragmentedRecoveryEngine::RecoverWithMapping(
    VolumeReader& reader,
    const FragmentMap& fragments,
    uint64_t fileSize,
    const std::wstring& outputPath,
    ProgressCallback onProgress)
{
    std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        throw RecoveryError("Failed to create output file");
    }

    const auto& runs = fragments.GetRuns();
    uint64_t bytesWritten = 0;
    uint64_t totalBytes = fileSize > 0 ? fileSize : fragments.TotalSize();

    for (size_t runIndex = 0; runIndex < runs.size() && bytesWritten < totalBytes; ++runIndex) {
        const auto& run = runs[runIndex];

        uint64_t runBytes = run.clusterCount * fragments.BytesPerCluster();
        uint64_t bytesToProcess = std::min(runBytes, totalBytes - bytesWritten);

        // Try memory-mapped access
        auto view = reader.MapClusters(run.startCluster, run.clusterCount);

        if (view.valid && view.data) {
            size_t toWrite = static_cast<size_t>(std::min(bytesToProcess, view.size));
            outFile.write(reinterpret_cast<const char*>(view.data), toWrite);
            reader.UnmapView(view);
            bytesWritten += toWrite;
        } else {
            // Fallback to regular reads
            try {
                auto data = reader.ReadClusters(run.startCluster, run.clusterCount);

                size_t toWrite = static_cast<size_t>(std::min(
                    bytesToProcess,
                    static_cast<uint64_t>(data.size())
                ));

                outFile.write(reinterpret_cast<const char*>(data.data()), toWrite);
                bytesWritten += toWrite;

            } catch (const DiskReadError&) {
                // Write zeros for unreadable clusters
                std::vector<char> zeros(static_cast<size_t>(bytesToProcess), 0);
                outFile.write(zeros.data(), static_cast<std::streamsize>(bytesToProcess));
                bytesWritten += bytesToProcess;
            }
        }

        if (onProgress && totalBytes > 0) {
            float progress = static_cast<float>(bytesWritten) / static_cast<float>(totalBytes);
            wchar_t msg[256];
            swprintf_s(msg, L"Writing: %.1f%% (%s / %s)",
                      progress * 100.0f,
                      StringUtils::FormatFileSize(bytesWritten).c_str(),
                      StringUtils::FormatFileSize(totalBytes).c_str());
            onProgress(msg, progress);
        }
    }

    outFile.close();

    if (bytesWritten == 0) {
        throw RecoveryError("No data was written");
    }
}

// ============================================================================
// Data Writing with VolumeReader
// ============================================================================

void FragmentedRecoveryEngine::WriteFragmentedData(
    VolumeReader& reader,
    const FragmentMap& fragments,
    uint64_t fileSize,
    std::ofstream& outFile,
    const ProgressCallback& onProgress)
{
    const auto& runs = fragments.GetRuns();
    uint64_t bytesWritten = 0;
    uint64_t totalBytes = fileSize > 0 ? fileSize : fragments.TotalSize();
    uint64_t bytesPerCluster = fragments.BytesPerCluster();

    for (const auto& run : runs) {
        if (bytesWritten >= totalBytes) break;

        try {
            auto data = reader.ReadClusters(run.startCluster, run.clusterCount);

            uint64_t runBytes = run.clusterCount * bytesPerCluster;
            size_t toWrite = static_cast<size_t>(std::min(
                std::min(runBytes, static_cast<uint64_t>(data.size())),
                totalBytes - bytesWritten
            ));

            outFile.write(reinterpret_cast<const char*>(data.data()), toWrite);

            if (!outFile.good()) {
                throw RecoveryError("Write error during recovery");
            }

            bytesWritten += toWrite;

        } catch (const ClusterOutOfBoundsError&) {
            // Write zeros
            uint64_t runBytes = run.clusterCount * bytesPerCluster;
            size_t toWrite = static_cast<size_t>(std::min(runBytes, totalBytes - bytesWritten));
            std::vector<char> zeros(toWrite, 0);
            outFile.write(zeros.data(), toWrite);
            bytesWritten += toWrite;

        } catch (const DiskReadError&) {
            // Write zeros
            uint64_t runBytes = run.clusterCount * bytesPerCluster;
            size_t toWrite = static_cast<size_t>(std::min(runBytes, totalBytes - bytesWritten));
            std::vector<char> zeros(toWrite, 0);
            outFile.write(zeros.data(), toWrite);
            bytesWritten += toWrite;
        }

        if (onProgress && totalBytes > 0) {
            float progress = static_cast<float>(bytesWritten) / static_cast<float>(totalBytes);
            wchar_t msg[256];
            swprintf_s(msg, L"Writing: %.1f%%", progress * 100.0f);
            onProgress(msg, progress);
        }
    }

    if (bytesWritten == 0) {
        throw RecoveryError("No data was written");
    }
}

void FragmentedRecoveryEngine::WriteFragmentedDataMapped(
    VolumeReader& reader,
    const FragmentMap& fragments,
    uint64_t fileSize,
    std::ofstream& outFile,
    const ProgressCallback& onProgress)
{
    const auto& runs = fragments.GetRuns();
    uint64_t bytesWritten = 0;
    uint64_t totalBytes = fileSize > 0 ? fileSize : fragments.TotalSize();
    uint64_t bytesPerCluster = fragments.BytesPerCluster();

    for (const auto& run : runs) {
        if (bytesWritten >= totalBytes) break;

        uint64_t runSize = std::min(run.clusterCount * bytesPerCluster, totalBytes - bytesWritten);

        auto view = reader.MapClusters(run.startCluster, run.clusterCount);

        if (view.valid && view.data) {
            size_t toWrite = static_cast<size_t>(std::min(runSize, view.size));
            outFile.write(reinterpret_cast<const char*>(view.data), toWrite);
            reader.UnmapView(view);
            bytesWritten += toWrite;
        } else {
            // Fallback
            try {
                auto data = reader.ReadClusters(run.startCluster, run.clusterCount);
                size_t toWrite = static_cast<size_t>(std::min(
                    static_cast<uint64_t>(data.size()),
                    totalBytes - bytesWritten
                ));
                outFile.write(reinterpret_cast<const char*>(data.data()), toWrite);
                bytesWritten += toWrite;

            } catch (const ForensicsException&) {
                std::vector<char> zeros(static_cast<size_t>(runSize), 0);
                outFile.write(zeros.data(), static_cast<std::streamsize>(runSize));
                bytesWritten += runSize;
            }
        }

        if (onProgress && totalBytes > 0) {
            float progress = static_cast<float>(bytesWritten) / static_cast<float>(totalBytes);
            onProgress(L"Writing data...", progress);
        }
    }

    if (bytesWritten == 0) {
        throw RecoveryError("No data was written");
    }
}

} // namespace KVC
