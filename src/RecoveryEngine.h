// ============================================================================
// RecoveryEngine.h - File Recovery Engine
// ============================================================================
// Handles the actual recovery of deleted files using VolumeReader for
// consistent LCN-based cluster access. Uses exception-based error handling.
// Validates recovery targets to prevent data corruption on the source drive.
// ============================================================================

#pragma once

#include <climits>
#include "DiskForensicsCore.h"
#include "VolumeReader.h"
#include "VolumeGeometry.h"
#include "ForensicsExceptions.h"
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

    // Recover a single file
    // Throws: DestinationInvalidError, RecoveryError, DiskReadError
    void RecoverFile(
        const RecoveryCandidate& file,
        wchar_t sourceDrive,
        const std::wstring& destinationPath,
        const ProgressCallback& onProgress
    );

    // Recover multiple files to a folder
    // Throws: DestinationInvalidError, RecoveryError
    // Returns count of successfully recovered files
    int RecoverMultipleFiles(
        const std::vector<RecoveryCandidate>& files,
        wchar_t sourceDrive,
        const std::wstring& destinationFolder,
        const ProgressCallback& onProgress
    );

	// Validate destination is not on source drive
	// Returns false if invalid, true if valid
	bool ValidateDestination(wchar_t sourceDrive, const std::wstring& destPath);

private:
    // Build VolumeGeometry from RecoveryCandidate
    VolumeGeometry BuildGeometry(DiskHandle& disk, const RecoveryCandidate& file);

    // Write recovered data using VolumeReader
    // Throws: RecoveryError, DiskReadError
    void WriteRecoveredData(
        VolumeReader& reader,
        const RecoveryCandidate& file,
        const std::wstring& outputPath,
        const ProgressCallback& onProgress
    );
};

} // namespace KVC