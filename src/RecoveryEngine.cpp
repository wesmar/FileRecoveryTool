// RecoveryEngine.cpp
#define NOMINMAX
#include "RecoveryEngine.h"
#include <fstream>
#include <filesystem>
#include <cwctype>
#include <algorithm>

namespace KVC {

RecoveryEngine::RecoveryEngine() = default;
RecoveryEngine::~RecoveryEngine() = default;

bool RecoveryEngine::ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath) {
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

bool RecoveryEngine::RecoverFile(
    const DeletedFileEntry& file,
    wchar_t sourceDrive,
    const std::wstring& destinationPath,
    ProgressCallback onProgress)
{
    if (!ValidateDestination(sourceDrive, destinationPath)) {
        onProgress(L"Invalid destination - cannot recover to source drive", 0.0f);
        return false;
    }

    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        onProgress(L"Failed to open source drive", 0.0f);
        return false;
    }

    return WriteRecoveredData(disk, file, destinationPath, onProgress);
}

bool RecoveryEngine::RecoverMultipleFiles(
    const std::vector<DeletedFileEntry>& files,
    wchar_t sourceDrive,
    const std::wstring& destinationFolder,
    ProgressCallback onProgress)
{
    if (files.empty()) {
        onProgress(L"No files to recover", 0.0f);
        return false;
    }

    // Validate that destination is not on the same drive as source
    // This prevents overwriting potentially recoverable data
    if (!ValidateDestination(sourceDrive, destinationFolder)) {
        onProgress(L"Invalid destination - cannot recover to source drive", 0.0f);
        return false;
    }

    // Open the source drive for raw sector reading
    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        onProgress(L"Failed to open source drive", 0.0f);
        return false;
    }

    // Process each file in the recovery list
    int successCount = 0;
    int totalFiles = static_cast<int>(files.size());

    for (int i = 0; i < totalFiles; ++i) {
        const auto& file = files[i];
        std::wstring destPath = destinationFolder + L"\\" + file.name;
        
        // Calculate progress percentage
        float progress = static_cast<float>(i) / totalFiles;

        wchar_t progressMsg[512];
        swprintf_s(progressMsg, L"Recovering %s (%d/%d)", file.name.c_str(), i + 1, totalFiles);
        onProgress(progressMsg, progress);

        if (WriteRecoveredData(disk, file, destPath, onProgress)) {
            ++successCount;
        }
    }

    wchar_t completeMsg[256];
    swprintf_s(completeMsg, L"Recovery complete: %d/%d files recovered", successCount, totalFiles);
    onProgress(completeMsg, 1.0f); // Set 100% completion

    return successCount > 0;
}

bool RecoveryEngine::WriteRecoveredData(
    DiskHandle& disk,
    const DeletedFileEntry& file,
    const std::wstring& outputPath,
    ProgressCallback& onProgress)
{
    // ========================================================================
    // Phase 1: Validate file has recoverable data
    // ========================================================================
    
    if (file.size == 0 && file.residentData.empty()) {
        onProgress(L"File has no data to recover", -1.0f); // -1.0f to keep previous progress
        return false;
    }

    // Check if we have actual data locations for non-resident files
    // This prevents creating empty files when cluster locations are lost
    if (file.residentData.empty() && file.clusterRanges.empty() && file.clusters.empty()) {
        wchar_t msg[512];
        swprintf_s(msg, L"Cannot recover %s: cluster locations lost (metadata exists but data location unknown)", 
                   file.name.c_str());
        onProgress(msg, -1.0f);
        return false;
    }

    // ========================================================================
    // Phase 2: Create output file
    // ========================================================================
    
    std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        wchar_t msg[512];
        swprintf_s(msg, L"Failed to create output file: %s", outputPath.c_str());
        onProgress(msg, -1.0f);
        return false;
    }

    // ========================================================================
    // Phase 3: Handle resident data (small files stored directly in MFT)
    // ========================================================================
    
    if (!file.residentData.empty()) {
        outFile.write(reinterpret_cast<const char*>(file.residentData.data()), 
                     file.residentData.size());
        outFile.flush();
        outFile.close();
        return outFile.good();
    }

    // ========================================================================
    // Phase 4: Validate cluster and sector geometry
    // ========================================================================
    
    if (file.clusterSize == 0) {
        outFile.close();
        onProgress(L"Invalid cluster size", -1.0f);
        return false;
    }

    uint64_t sectorSize = disk.GetSectorSize();
    if (sectorSize == 0) {
        outFile.close();
        onProgress(L"Invalid sector size", -1.0f);
        return false;
    }

    uint64_t sectorsPerCluster = file.clusterSize / sectorSize;
    if (sectorsPerCluster == 0) {
        outFile.close();
        onProgress(L"Invalid sectors per cluster", -1.0f);
        return false;
    }

    // ========================================================================
    // Phase 5: Recover data from disk clusters
    // ========================================================================
    
    uint64_t bytesWritten = 0;
    bool recoverySuccessful = false;

    // Method A: Use cluster ranges (preferred for non-resident files)
    if (!file.clusterRanges.empty()) {
        for (const auto& range : file.clusterRanges) {
            if (bytesWritten >= file.size) break;
            // Process each cluster in the range
            for (uint64_t i = 0; i < range.count && bytesWritten < file.size; ++i) {
                uint64_t cluster = range.start + i;
                uint64_t sector = cluster * sectorsPerCluster;

                // Read raw sectors from disk
                auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
                size_t bytesToWrite = std::min(
                    static_cast<size_t>(file.size - bytesWritten),
                    data.empty() ? static_cast<size_t>(file.clusterSize) : data.size()
                );
                // Write data or zeros if sector is unreadable
                if (data.empty()) {
                    std::vector<char> zeroBuffer(bytesToWrite, 0);
                    outFile.write(zeroBuffer.data(), bytesToWrite);
                } else {
                    outFile.write(reinterpret_cast<const char*>(data.data()), bytesToWrite);
                }

                if (!outFile.good()) {
                    wchar_t msg[256];
                    swprintf_s(msg, L"Write error at cluster %llu", cluster);
                    onProgress(msg, -1.0f);
                    outFile.close();
                    return false;
                }

                bytesWritten += bytesToWrite;
                recoverySuccessful = true;
            }
        }
    }
    // Method B: Use individual cluster list (for carved files)
    else if (!file.clusters.empty()) {
        for (uint64_t cluster : file.clusters) {
            if (bytesWritten >= file.size) break;
            uint64_t sector = cluster * sectorsPerCluster;
            auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
            size_t bytesToWrite = std::min(
                static_cast<size_t>(file.size - bytesWritten),
                static_cast<size_t>(file.clusterSize)
            );
            if (data.empty()) {
                std::vector<char> zeroBuffer(bytesToWrite, 0);
                outFile.write(zeroBuffer.data(), bytesToWrite);
            } else {
                size_t validBytes = std::min(bytesToWrite, data.size());
                outFile.write(reinterpret_cast<const char*>(data.data()), validBytes);
            }

            if (!outFile.good()) {
                wchar_t msg[256];
                swprintf_s(msg, L"Write error at cluster %llu", cluster);
                onProgress(msg, -1.0f);
                outFile.close();
                return false;
            }

            bytesWritten += bytesToWrite;
            recoverySuccessful = true;
        }
    }

    // ========================================================================
    // Phase 6: Finalize and verify
    // ========================================================================
    
    outFile.flush();
    outFile.close();

    if (!recoverySuccessful || bytesWritten == 0) {
        wchar_t msg[256];
        swprintf_s(msg, L"Failed to write data for %s", file.name.c_str());
        onProgress(msg, -1.0f);
        return false;
    }

    wchar_t progressMsg[256];
    swprintf_s(progressMsg, L"Recovered %llu bytes for %s", bytesWritten, file.name.c_str());
    onProgress(progressMsg, -1.0f);

    return true;
}
} // namespace KVC
