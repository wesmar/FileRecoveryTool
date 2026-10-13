// ============================================================================
// RecoveryEngine.h - File Recovery Engine
// ============================================================================
// Writes the bytes of recovery candidates out of the source volume: streamed
// in bounded chunks, holes and data past the valid length as zeros, each file
// in its source folder below the destination, never over another file.
// Refuses a destination on the source volume.
// ============================================================================

#pragma once

#include <climits>
#include "core/DiskForensicsCore.h"
#include "io/VolumeReader.h"
#include "core/VolumeGeometry.h"
#include "support/ForensicsExceptions.h"
#include "support/StringUtils.h"
#include <vector>
#include <string>
#include <functional>

namespace KVC {

class RecoveryEngine {
public:
    RecoveryEngine();
    ~RecoveryEngine();

    using ProgressCallback = std::function<void(const std::wstring&, float)>;

    struct Outcome {
        int recovered = 0;          // written in full
        int damaged = 0;            // written, some ranges unreadable (zeros)
        int failed = 0;
        int skipped = 0;            // nothing recoverable (metadata only)
    };

    // One file to an exact path. Throws DestinationInvalidError, RecoveryError.
    void RecoverFile(
        const RecoveryCandidate& file,
        const std::wstring& sourceVolume,
        const std::wstring& destinationPath,
        const ProgressCallback& onProgress
    );

    // Every recoverable file into a folder, its source folder recreated below.
    Outcome RecoverMultipleFiles(
        const std::vector<RecoveryCandidate>& files,
        const std::wstring& sourceVolume,
        const std::wstring& destinationFolder,
        const ProgressCallback& onProgress
    );

    // False when the destination lies on the source volume
    static bool ValidateDestination(const std::wstring& sourceVolume, const std::wstring& destPath);

private:
    VolumeGeometry BuildGeometry(DiskHandle& disk, const RecoveryCandidate& file);

    // Returns the number of bytes that could not be read (written as zeros)
    uint64_t WriteRecoveredData(
        VolumeReader& reader,
        const RecoveryCandidate& file,
        const std::wstring& outputPath
    );
};

// A name every Windows file system takes: reserved characters and device
// names replaced, trailing dots and spaces dropped, never empty.
std::wstring SanitizeFileName(const std::wstring& name);

} // namespace KVC
