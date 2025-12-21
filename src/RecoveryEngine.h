// ============================================================================
// RecoveryEngine.h - File Recovery Engine
// ============================================================================
// Handles the actual recovery of deleted files by reading raw disk sectors
// and writing recovered data to destination files.
// Validates recovery targets to prevent data corruption on the source drive.
// ============================================================================

#pragma once

#include "DiskForensicsCore.h"
#include "StringUtils.h"
#include <vector>
#include <string>
#include <functional>

namespace KVC {

class RecoveryEngine {
public:
    RecoveryEngine();
    ~RecoveryEngine();

    using ProgressCallback = std::function<void(const std::wstring&, float)>;

    bool RecoverFile(
        const DeletedFileEntry& file,
        wchar_t sourceDrive,
        const std::wstring& destinationPath,
        ProgressCallback onProgress
    );

    bool RecoverMultipleFiles(
        const std::vector<DeletedFileEntry>& files,
        wchar_t sourceDrive,
        const std::wstring& destinationFolder,
        ProgressCallback onProgress
    );

    bool ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath);

private:

    bool WriteRecoveredData(
        DiskHandle& disk,
        const DeletedFileEntry& file,
        const std::wstring& outputPath,
        ProgressCallback& onProgress
    );
};

} // namespace KVC