// ============================================================================
// FragmentedRecoveryEngine.cpp - Fragment-Aware File Recovery
// ============================================================================
// Implementation of fragmentation-aware file recovery engine.
// Reads data across non-contiguous clusters and reconstructs complete files.
// ============================================================================

#include "FragmentedRecoveryEngine.h"
#include "StringUtils.h"
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

bool FragmentedRecoveryEngine::ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath) {
    if (destPath.length() < 2) {
        return false;
    }

    // Get full path to handle relative paths and normalize
    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(destPath.c_str(), MAX_PATH, fullPath, nullptr)) {
        return false;
    }

    // UNC paths (\\server\share) are always allowed (network location)
    if (fullPath[0] == L'\\' && fullPath[1] == L'\\') {
        return true;
    }

    // Check for drive letter path
    if (fullPath[1] != L':') {
        return false;
    }

    wchar_t destDrive = static_cast<wchar_t>(towupper(fullPath[0]));
    wchar_t srcDrive = static_cast<wchar_t>(towupper(sourceDrive));

    return destDrive != srcDrive;
}

// ============================================================================
// Fragment Map Validation
// ============================================================================

FragmentedRecoveryEngine::ValidationResult FragmentedRecoveryEngine::ValidateFragmentMap(
    DiskHandle& disk,
    const FragmentMap& fragments,
    uint64_t sectorSize)
{
    ValidationResult result;
    result.allClustersValid = true;
    result.validClusters = 0;
    result.invalidClusters = 0;
    
    uint64_t bytesPerCluster = fragments.BytesPerCluster();
    if (bytesPerCluster == 0) {
        result.allClustersValid = false;
        result.errorMessage = "Invalid bytes per cluster (0)";
        return result;
    }
    
    const auto& runs = fragments.GetRuns();
    
    for (const auto& run : runs) {
        // Validate each cluster in the run
        for (uint64_t i = 0; i < run.clusterCount; ++i) {
            uint64_t cluster = run.startCluster + i;
            
            if (ValidateCluster(disk, cluster, sectorSize, bytesPerCluster)) {
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
    DiskHandle& disk,
    const FragmentMap& fragments,
    uint64_t sectorSize,
    ProgressCallback onProgress)
{
    ValidationResult result;
    result.allClustersValid = true;
    result.validClusters = 0;
    result.invalidClusters = 0;
    
    uint64_t bytesPerCluster = fragments.BytesPerCluster();
    if (bytesPerCluster == 0) {
        result.allClustersValid = false;
        result.errorMessage = "Invalid bytes per cluster (0)";
        return result;
    }
    
    // Build flat list of all clusters to validate
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
    
    // Parallel validation using thread pool
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
                
                // Each thread needs its own disk handle for parallel reads
                // For now, we'll serialize disk access with a mutex
                bool valid;
                {
                    // Note: In a real implementation, you'd want separate disk handles
                    // For now, we serialize access to the single disk handle
                    std::lock_guard<std::mutex> lock(resultMutex);
                    valid = ValidateCluster(disk, cluster, sectorSize, bytesPerCluster);
                }
                
                if (!valid) {
                    localFailed.push_back(cluster);
                }
                
                processedClusters++;
                
                // Report progress periodically
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
    
    // Collect results
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

bool FragmentedRecoveryEngine::ValidateCluster(
    DiskHandle& disk,
    uint64_t cluster,
    uint64_t sectorSize,
    uint64_t bytesPerCluster)
{
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
    uint64_t sector = cluster * sectorsPerCluster;
    
    // Try to read the cluster
    auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
    
    return !data.empty() && data.size() == bytesPerCluster;
}

// ============================================================================
// Fragment Map Building
// ============================================================================

FragmentMap FragmentedRecoveryEngine::BuildFragmentMap(const DeletedFileEntry& file) {
    FragmentMap map(file.clusterSize);
    
    // Priority 1: Use cluster ranges (from NTFS data runs)
    if (!file.clusterRanges.empty()) {
        map.BuildFromRanges(file.clusterRanges);
        return map;
    }
    
    // Priority 2: Use cluster list (from carved files or FAT)
    if (!file.clusters.empty()) {
        map.BuildFromClusterList(file.clusters);
        return map;
    }
    
    // No cluster information available
    return map;
}

// ============================================================================
// Recovery Operations
// ============================================================================

bool FragmentedRecoveryEngine::RecoverFragmentedFile(
    DiskHandle& disk,
    const FragmentedFile& file,
    const std::wstring& outputPath,
    ProgressCallback onProgress)
{
    // Handle resident data (small files stored in MFT)
    if (file.HasResidentData()) {
        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            if (onProgress) {
                wchar_t msg[512];
                swprintf_s(msg, L"Failed to create output file: %s", outputPath.c_str());
                onProgress(msg, -1.0f);
            }
            return false;
        }
        
        const auto& resData = file.GetResidentData();
        outFile.write(reinterpret_cast<const char*>(resData.data()), resData.size());
        outFile.close();
        return outFile.good();
    }
    
    // Non-resident data - use fragment map
    const FragmentMap& fragments = file.GetFragments();
    
    if (fragments.IsEmpty()) {
        if (onProgress) {
            onProgress(L"No cluster data available for recovery", -1.0f);
        }
        return false;
    }
    
    uint64_t sectorSize = disk.GetSectorSize();
    
    // Optionally validate clusters first
    if (m_config.validateClusters) {
        ValidationResult validation;
        
        if (m_config.parallelValidation && fragments.FragmentCount() > 10) {
            validation = ValidateFragmentMapParallel(disk, fragments, sectorSize, onProgress);
        } else {
            validation = ValidateFragmentMap(disk, fragments, sectorSize);
        }
        
        if (!validation.allClustersValid) {
            if (onProgress) {
                wchar_t msg[512];
                swprintf_s(msg, L"Warning: %llu clusters unreadable, recovery may be incomplete",
                          validation.invalidClusters);
                onProgress(msg, -1.0f);
            }
            // Continue anyway - partial recovery is better than none
        }
    }
    
    // Use memory-mapped or traditional recovery
    if (m_config.useMemoryMapping) {
        return RecoverWithMapping(disk, fragments, file.GetSize(), outputPath, onProgress);
    }
    
    // Traditional sector-by-sector recovery
    std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        if (onProgress) {
            wchar_t msg[512];
            swprintf_s(msg, L"Failed to create output file: %s", outputPath.c_str());
            onProgress(msg, -1.0f);
        }
        return false;
    }
    
    bool success = WriteFragmentedData(disk, fragments, file.GetSize(), outFile, sectorSize, onProgress);
    outFile.close();
    
    return success;
}

bool FragmentedRecoveryEngine::RecoverFile(
    const DeletedFileEntry& file,
    wchar_t sourceDrive,
    const std::wstring& destinationPath,
    ProgressCallback onProgress)
{
    if (!ValidateDestination(sourceDrive, destinationPath)) {
        if (onProgress) {
            onProgress(L"Invalid destination - cannot recover to source drive", 0.0f);
        }
        return false;
    }
    
    // Check for resident data first
    if (!file.residentData.empty()) {
        std::ofstream outFile(destinationPath, std::ios::binary | std::ios::trunc);
        if (!outFile.is_open()) {
            if (onProgress) {
                wchar_t msg[512];
                swprintf_s(msg, L"Failed to create output file: %s", destinationPath.c_str());
                onProgress(msg, -1.0f);
            }
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(file.residentData.data()), 
                     file.residentData.size());
        outFile.close();
        return outFile.good();
    }
    
    // Build fragment map from file entry
    FragmentMap fragments = BuildFragmentMap(file);
    
    if (fragments.IsEmpty()) {
        if (onProgress) {
            wchar_t msg[512];
            swprintf_s(msg, L"Cannot recover %s: no cluster data available", file.name.c_str());
            onProgress(msg, -1.0f);
        }
        return false;
    }
    
    // Open disk
    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        if (onProgress) {
            onProgress(L"Failed to open source drive", 0.0f);
        }
        return false;
    }
    
    uint64_t sectorSize = disk.GetSectorSize();
    
    // Create output file
    std::ofstream outFile(destinationPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        if (onProgress) {
            wchar_t msg[512];
            swprintf_s(msg, L"Failed to create output file: %s", destinationPath.c_str());
            onProgress(msg, -1.0f);
        }
        return false;
    }
    
    bool success;
    if (m_config.useMemoryMapping) {
        outFile.close();
        success = RecoverWithMapping(disk, fragments, file.size, destinationPath, onProgress);
    } else {
        success = WriteFragmentedData(disk, fragments, file.size, outFile, sectorSize, onProgress);
        outFile.close();
    }
    
    if (success && onProgress) {
        wchar_t msg[256];
        swprintf_s(msg, L"Recovered: %s (%s)", file.name.c_str(), file.sizeFormatted.c_str());
        onProgress(msg, -1.0f);
    }
    
    return success;
}

FragmentedRecoveryEngine::BatchResult FragmentedRecoveryEngine::RecoverMultipleFiles(
    const std::vector<DeletedFileEntry>& files,
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
    
    if (!ValidateDestination(sourceDrive, destinationFolder)) {
        if (onProgress) {
            onProgress(L"Invalid destination - cannot recover to source drive", 0.0f);
        }
        result.failedCount = static_cast<int>(files.size());
        return result;
    }
    
    // Ensure destination folder exists
    try {
        std::filesystem::create_directories(destinationFolder);
    } catch (const std::exception&) {
        if (onProgress) {
            onProgress(L"Failed to create destination folder", 0.0f);
        }
        result.failedCount = static_cast<int>(files.size());
        return result;
    }
    
    // Open disk once for all files
    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        if (onProgress) {
            onProgress(L"Failed to open source drive", 0.0f);
        }
        result.failedCount = static_cast<int>(files.size());
        return result;
    }
    
    int totalFiles = static_cast<int>(files.size());
    
    for (int i = 0; i < totalFiles; ++i) {
        // Check for cancellation
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
        
        // Build fragment map
        FragmentMap fragments = BuildFragmentMap(file);
        
        bool success = false;
        
        // Handle resident data
        if (!file.residentData.empty()) {
            std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
            if (outFile.is_open()) {
                outFile.write(reinterpret_cast<const char*>(file.residentData.data()), 
                             file.residentData.size());
                outFile.close();
                success = outFile.good();
            }
        }
        // Handle non-resident data
        else if (!fragments.IsEmpty()) {
            uint64_t sectorSize = disk.GetSectorSize();
            
            if (m_config.useMemoryMapping) {
                success = RecoverWithMapping(disk, fragments, file.size, destPath, nullptr);
            } else {
                std::ofstream outFile(destPath, std::ios::binary | std::ios::trunc);
                if (outFile.is_open()) {
                    ProgressCallback nullCallback = nullptr;
                    success = WriteFragmentedData(disk, fragments, file.size, outFile, sectorSize, nullCallback);
                    outFile.close();
                }
            }
        }
        
        if (success) {
            result.successCount++;
            result.successFiles.push_back(file.name);
        } else {
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

bool FragmentedRecoveryEngine::RecoverWithMapping(
    DiskHandle& disk,
    const FragmentMap& fragments,
    uint64_t fileSize,
    const std::wstring& outputPath,
    ProgressCallback onProgress)
{
    std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        if (onProgress) {
            wchar_t msg[512];
            swprintf_s(msg, L"Failed to create output file: %s", outputPath.c_str());
            onProgress(msg, -1.0f);
        }
        return false;
    }
    
    uint64_t sectorSize = disk.GetSectorSize();
    uint64_t bytesPerCluster = fragments.BytesPerCluster();
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
    
    const auto& runs = fragments.GetRuns();
    uint64_t bytesWritten = 0;
    uint64_t totalBytes = fileSize > 0 ? fileSize : fragments.TotalSize();
    
    for (size_t runIndex = 0; runIndex < runs.size() && bytesWritten < totalBytes; ++runIndex) {
        const auto& run = runs[runIndex];
        
        uint64_t runOffset = run.startCluster * sectorsPerCluster * sectorSize;
        uint64_t runSize = run.clusterCount * bytesPerCluster;
        
        uint64_t bytesToProcess = (std::min)(runSize, totalBytes - bytesWritten);
        
        auto region = disk.MapDiskRegion(runOffset, bytesToProcess);
        
        if (region.IsValid()) {
            size_t toWrite = static_cast<size_t>((std::min)(bytesToProcess, region.size));
            outFile.write(reinterpret_cast<const char*>(region.data), toWrite);
            disk.UnmapRegion(region);
            bytesWritten += toWrite;
        } else {
            uint64_t runBytesWritten = 0;
            
            for (uint64_t c = 0; c < run.clusterCount && bytesWritten < totalBytes; ++c) {
                uint64_t cluster = run.startCluster + c;
                uint64_t sector = cluster * sectorsPerCluster;
                
                auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
                
                size_t toWrite = static_cast<size_t>((std::min)(
                    static_cast<uint64_t>(data.size()),
                    totalBytes - bytesWritten
                ));
                
                if (data.empty()) {
                    std::vector<char> zeros(toWrite, 0);
                    outFile.write(zeros.data(), toWrite);
                } else {
                    outFile.write(reinterpret_cast<const char*>(data.data()), toWrite);
                }
                
                bytesWritten += toWrite;
                runBytesWritten += toWrite;
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
    
    return bytesWritten > 0 && outFile.good();
}

// ============================================================================
// Data Writing
// ============================================================================

bool FragmentedRecoveryEngine::WriteFragmentedData(
    DiskHandle& disk,
    const FragmentMap& fragments,
    uint64_t fileSize,
    std::ofstream& outFile,
    uint64_t sectorSize,
    ProgressCallback& onProgress)
{
    uint64_t bytesPerCluster = fragments.BytesPerCluster();
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
    
    const auto& runs = fragments.GetRuns();
    uint64_t bytesWritten = 0;
    uint64_t totalBytes = fileSize > 0 ? fileSize : fragments.TotalSize();
    
    for (const auto& run : runs) {
        if (bytesWritten >= totalBytes) break;
        
        for (uint64_t c = 0; c < run.clusterCount && bytesWritten < totalBytes; ++c) {
            uint64_t cluster = run.startCluster + c;
            uint64_t sector = cluster * sectorsPerCluster;
            
            auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
            
            size_t toWrite = static_cast<size_t>((std::min)(
                static_cast<uint64_t>(data.empty() ? bytesPerCluster : data.size()),
                totalBytes - bytesWritten
            ));
            
            if (data.empty()) {
                std::vector<char> zeros(toWrite, 0);
                outFile.write(zeros.data(), toWrite);
            } else {
                outFile.write(reinterpret_cast<const char*>(data.data()), toWrite);
            }
            
            if (!outFile.good()) {
                if (onProgress) {
                    wchar_t msg[256];
                    swprintf_s(msg, L"Write error at cluster %llu", cluster);
                    onProgress(msg, -1.0f);
                }
                return false;
            }
            
            bytesWritten += toWrite;
        }
        
        if (onProgress && totalBytes > 0) {
            float progress = static_cast<float>(bytesWritten) / static_cast<float>(totalBytes);
            wchar_t msg[256];
            swprintf_s(msg, L"Writing: %.1f%%", progress * 100.0f);
            onProgress(msg, progress);
        }
    }
    
    return bytesWritten > 0;
}

bool FragmentedRecoveryEngine::WriteFragmentedDataMapped(
    DiskHandle& disk,
    const FragmentMap& fragments,
    uint64_t fileSize,
    std::ofstream& outFile,
    uint64_t sectorSize,
    ProgressCallback& onProgress)
{
    uint64_t bytesPerCluster = fragments.BytesPerCluster();
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
    
    const auto& runs = fragments.GetRuns();
    uint64_t bytesWritten = 0;
    uint64_t totalBytes = fileSize > 0 ? fileSize : fragments.TotalSize();
    
    for (const auto& run : runs) {
        if (bytesWritten >= totalBytes) break;
        
        uint64_t runOffset = run.startCluster * sectorsPerCluster * sectorSize;
        uint64_t runSize = (std::min)(run.clusterCount * bytesPerCluster, totalBytes - bytesWritten);
        
        auto region = disk.MapDiskRegion(runOffset, runSize);
        
        if (region.IsValid()) {
            size_t toWrite = static_cast<size_t>((std::min)(runSize, region.size));
            outFile.write(reinterpret_cast<const char*>(region.data), toWrite);
            disk.UnmapRegion(region);
            bytesWritten += toWrite;
        } else {
            for (uint64_t c = 0; c < run.clusterCount && bytesWritten < totalBytes; ++c) {
                uint64_t cluster = run.startCluster + c;
                uint64_t sector = cluster * sectorsPerCluster;
                
                auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
                
                size_t toWrite = static_cast<size_t>((std::min)(
                    static_cast<uint64_t>(data.size()),
                    totalBytes - bytesWritten
                ));
                
                if (data.empty()) {
                    std::vector<char> zeros(toWrite, 0);
                    outFile.write(zeros.data(), toWrite);
                } else {
                    outFile.write(reinterpret_cast<const char*>(data.data()), toWrite);
                }
                
                bytesWritten += toWrite;
            }
        }
        
        if (onProgress && totalBytes > 0) {
            float progress = static_cast<float>(bytesWritten) / static_cast<float>(totalBytes);
            onProgress(L"Writing data...", progress);
        }
    }
    
    return bytesWritten > 0;
}

std::vector<uint8_t> FragmentedRecoveryEngine::ReadClusterRun(
    DiskHandle& disk,
    const ClusterRun& run,
    uint64_t sectorSize,
    uint64_t bytesPerCluster)
{
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;
    uint64_t totalSectors = run.clusterCount * sectorsPerCluster;
    uint64_t startSector = run.startCluster * sectorsPerCluster;
    
    // Read all sectors in the run
    return disk.ReadSectors(startSector, totalSectors, sectorSize);
}

} // namespace KVC
