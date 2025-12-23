// ============================================================================
// RecoveryEngine.cpp - File Recovery Engine Implementation
// ============================================================================
// Uses VolumeReader for consistent LCN-based cluster access.
// Exception-based error handling per Phase 4 of architecture refactor.
// ============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "RecoveryEngine.h"
#include "RecoveryCandidate.h"
#include "SafetyLimits.h"

#include <Windows.h>
#include <climits>
#include <fstream>
#include <filesystem>
#include <cwctype>
#include <algorithm>
#include <vector>
#include <string>

namespace KVC {

RecoveryEngine::RecoveryEngine() = default;
RecoveryEngine::~RecoveryEngine() = default;

// ============================================================================
// Destination Validation
// ============================================================================

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
        return true; // Valid network path
    }

    // Check for drive letter path
    if (fullPath[1] != L':') {
        return false;
    }

    wchar_t destDrive = static_cast<wchar_t>(towupper(fullPath[0]));
    wchar_t srcDrive = static_cast<wchar_t>(towupper(sourceDrive));

    if (destDrive == srcDrive) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Geometry Builder
// ============================================================================

VolumeGeometry RecoveryEngine::BuildGeometry(DiskHandle& disk, const RecoveryCandidate& file) {
    VolumeGeometry geom;

    geom.sectorSize = disk.GetSectorSize();
    geom.bytesPerCluster = file.file.GetFragments().BytesPerCluster();
    geom.totalClusters = disk.GetDiskSize() / geom.bytesPerCluster;
    geom.volumeStartOffset = file.volumeStartOffset;

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
// Single File Recovery
// ============================================================================

void RecoveryEngine::RecoverFile(
    const RecoveryCandidate& file,
    wchar_t sourceDrive,
    const std::wstring& destinationPath,
    const ProgressCallback& onProgress)
{
    // Validate destination
    if (!ValidateDestination(sourceDrive, destinationPath)) {
        throw DestinationInvalidError("Invalid destination path");
    }

    // Open source drive
    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        throw DiskReadError(0, 0, GetLastError());
    }

    // Build geometry and create VolumeReader
    VolumeGeometry geom = BuildGeometry(disk, file);
    VolumeReader reader(disk, geom);

    // Recover the file
    WriteRecoveredData(reader, file, destinationPath, onProgress);
}

// ============================================================================
// Multiple File Recovery
// ============================================================================

int RecoveryEngine::RecoverMultipleFiles(
    const std::vector<RecoveryCandidate>& files,
    wchar_t sourceDrive,
    const std::wstring& destinationFolder,
    const ProgressCallback& onProgress)
{
    if (files.empty()) {
        if (onProgress) {
            onProgress(L"No files to recover", 0.0f);
        }
        return 0;
    }

    // Validate destination (throws on invalid)
    if (!ValidateDestination(sourceDrive, destinationFolder)) {
        throw DestinationInvalidError("Invalid destination folder");
    }

    // Open source drive
    DiskHandle disk(sourceDrive);
    if (!disk.Open()) {
        throw DiskReadError(0, 0, GetLastError());
    }

    int successCount = 0;
    int totalFiles = static_cast<int>(files.size());

    for (int i = 0; i < totalFiles; ++i) {
        const auto& file = files[i];
        std::wstring destPath = destinationFolder + L"\\" + file.name;

        // Progress
        float progress = static_cast<float>(i) / totalFiles;
        if (onProgress) {
            wchar_t progressMsg[512];
            swprintf_s(progressMsg, L"Recovering %s (%d/%d)",
                      file.name.c_str(), i + 1, totalFiles);
            onProgress(progressMsg, progress);
        }

        try {
            // Build geometry for this file
            VolumeGeometry geom = BuildGeometry(disk, file);
            VolumeReader reader(disk, geom);

            WriteRecoveredData(reader, file, destPath, onProgress);
            ++successCount;
        } catch (const ForensicsException& e) {
            // Log error but continue with other files
            if (onProgress) {
                wchar_t errMsg[512];
                swprintf_s(errMsg, L"Failed to recover %s: %hs",
                          file.name.c_str(), e.what());
                onProgress(errMsg, -1.0f);
            }
        }
    }

    if (onProgress) {
        wchar_t completeMsg[256];
        swprintf_s(completeMsg, L"Recovery complete: %d/%d files recovered",
                  successCount, totalFiles);
        onProgress(completeMsg, 1.0f);
    }

    return successCount;
}

// ============================================================================
// Data Writing with VolumeReader
// ============================================================================

void RecoveryEngine::WriteRecoveredData(
    VolumeReader& reader,
    const RecoveryCandidate& file,
    const std::wstring& outputPath,
    const ProgressCallback& onProgress)
{
    // ========================================================================
    // Phase 1: Validate file has recoverable data
    // ========================================================================

    if (file.fileSize == 0 && !file.file.HasResidentData()) {
        throw InsufficientDataError(1, 0);
    }

    // Check for data locations
    if (!file.file.HasResidentData() && file.file.GetFragments().IsEmpty()) {
        throw RecoveryError("Cluster locations lost - metadata exists but data location unknown");
    }

    // ========================================================================
    // Phase 2: Create output file
    // ========================================================================

    std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
        throw RecoveryError("Failed to create output file");
    }

    // ========================================================================
    // Phase 3: Handle resident data (small files stored directly in MFT)
    // ========================================================================

    if (file.file.HasResidentData()) {
        const auto& residentData = file.file.GetResidentData();
        outFile.write(reinterpret_cast<const char*>(residentData.data()),
                     residentData.size());
        outFile.flush();
        outFile.close();

        if (!outFile.good()) {
            throw RecoveryError("Failed to write resident data");
        }
        return;
    }

    // ========================================================================
    // Phase 4: Validate geometry
    // ========================================================================

    const VolumeGeometry& geom = reader.Geometry();

    if (geom.bytesPerCluster == 0) {
        outFile.close();
        throw InvalidGeometryError("Invalid cluster size (0)");
    }

    // ========================================================================
    // Phase 5: Recover data from disk clusters using VolumeReader
    // ========================================================================

    uint64_t bytesWritten = 0;

    // Use FragmentMap to recover data
    const auto& runs = file.file.GetFragments().GetRuns();
    for (const auto& run : runs) {
        if (bytesWritten >= file.fileSize) break;

        // Read clusters using VolumeReader (LCN-based)
        try {
            auto data = reader.ReadClusters(run.startCluster, run.clusterCount);

            // Calculate how much to write
            uint64_t bytesInRun = run.clusterCount * geom.bytesPerCluster;
            uint64_t bytesToWrite = std::min(bytesInRun, file.fileSize - bytesWritten);

            if (data.size() < bytesToWrite) {
                bytesToWrite = data.size();
            }

            outFile.write(reinterpret_cast<const char*>(data.data()),
                         static_cast<std::streamsize>(bytesToWrite));

            if (!outFile.good()) {
                outFile.close();
                throw RecoveryError("Write error during recovery");
            }

            bytesWritten += bytesToWrite;

        } catch (const ClusterOutOfBoundsError&) {
            // Write zeros for out-of-bounds clusters
            uint64_t bytesInRun = run.clusterCount * geom.bytesPerCluster;
            uint64_t bytesToWrite = std::min(bytesInRun, file.fileSize - bytesWritten);
            std::vector<char> zeroBuffer(static_cast<size_t>(bytesToWrite), 0);
            outFile.write(zeroBuffer.data(), static_cast<std::streamsize>(bytesToWrite));
            bytesWritten += bytesToWrite;
        } catch (const DiskReadError&) {
            // Write zeros for unreadable clusters
            uint64_t bytesInRun = run.clusterCount * geom.bytesPerCluster;
            uint64_t bytesToWrite = std::min(bytesInRun, file.fileSize - bytesWritten);
            std::vector<char> zeroBuffer(static_cast<size_t>(bytesToWrite), 0);
            outFile.write(zeroBuffer.data(), static_cast<std::streamsize>(bytesToWrite));
            bytesWritten += bytesToWrite;
        }
    }

    // ========================================================================
    // Phase 6: Finalize and verify
    // ========================================================================

    outFile.flush();
    outFile.close();

    if (bytesWritten == 0) {
        throw RecoveryError("No data was written during recovery");
    }

    if (onProgress) {
        wchar_t progressMsg[256];
        swprintf_s(progressMsg, L"Recovered %llu bytes for %s",
                  bytesWritten, file.name.c_str());
        onProgress(progressMsg, -1.0f);
    }
}

} // namespace KVC