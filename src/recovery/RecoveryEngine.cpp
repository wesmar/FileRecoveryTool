// ============================================================================
// RecoveryEngine.cpp - File Recovery Engine Implementation
// ============================================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "recovery/RecoveryEngine.h"
#include "core/RecoveryCandidate.h"
#include "support/SafetyLimits.h"
#include "io/VolumeLocator.h"
#include "filesystems/Lznt1.h"

#include <Windows.h>
#include <algorithm>
#include <climits>
#include <cwctype>
#include <string>
#include <vector>

namespace KVC {

namespace {

// how much of a file is read from the source volume at a time
constexpr uint64_t COPY_CHUNK_BYTES = 8 * 1024 * 1024;

// \\?\ form of an absolute path, so that paths past MAX_PATH work
std::wstring LongPath(const std::wstring& path) {
    std::vector<wchar_t> full(32768);
    DWORD n = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
    if (n == 0 || n >= full.size()) {
        return path;
    }
    std::wstring p(full.data(), n);
    if (p.rfind(L"\\\\?\\", 0) == 0) return p;
    if (p.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + p.substr(2);
    return L"\\\\?\\" + p;
}

bool FileExists(const std::wstring& path) {
    return GetFileAttributesW(LongPath(path).c_str()) != INVALID_FILE_ATTRIBUTES;
}

void CreateDirectories(const std::wstring& folder) {
    const std::wstring path = LongPath(folder);
    size_t start = 4;                                       // past the long-path prefix
    if (path.rfind(L"\\\\?\\UNC\\", 0) == 0) {
        start = path.find(L'\\', path.find(L'\\', 8) + 1);  // past the share
    } else {
        start = path.find(L'\\', 4);                        // past X:
    }
    for (size_t pos = path.find(L'\\', start + 1); ; pos = path.find(L'\\', pos + 1)) {
        const std::wstring part = path.substr(0, pos);
        if (!CreateDirectoryW(part.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
            throw RecoveryError("Cannot create the destination folder");
        }
        if (pos == std::wstring::npos) break;
    }
}

// "name.ext" -> "name (2).ext", ... until nothing is there
std::wstring UniquePath(const std::wstring& folder, const std::wstring& name) {
    std::wstring candidate = folder + L"\\" + name;
    if (!FileExists(candidate)) return candidate;
    const size_t dot = name.rfind(L'.');
    const std::wstring stem = dot == std::wstring::npos || dot == 0 ? name : name.substr(0, dot);
    const std::wstring ext = dot == std::wstring::npos || dot == 0 ? L"" : name.substr(dot);
    for (int n = 2; ; ++n) {
        candidate = folder + L"\\" + stem + L" (" + std::to_wstring(n) + L")" + ext;
        if (!FileExists(candidate)) return candidate;
    }
}

class OutputFile {
public:
    explicit OutputFile(const std::wstring& path) {
        m_handle = CreateFileW(LongPath(path).c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (m_handle == INVALID_HANDLE_VALUE) {
            throw RecoveryError("Failed to create output file");
        }
    }
    ~OutputFile() { if (m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }
    OutputFile(const OutputFile&) = delete;
    OutputFile& operator=(const OutputFile&) = delete;

    void Write(const uint8_t* data, uint64_t length) {
        while (length > 0) {
            const DWORD chunk = static_cast<DWORD>(std::min<uint64_t>(length, 1u << 30));
            DWORD written = 0;
            if (!WriteFile(m_handle, data, chunk, &written, nullptr) || written != chunk) {
                throw RecoveryError("Write error during recovery");
            }
            data += chunk;
            length -= chunk;
        }
    }
    void WriteZeros(uint64_t length) {
        static const std::vector<uint8_t> zeros(1024 * 1024, 0);
        while (length > 0) {
            const uint64_t n = std::min<uint64_t>(length, zeros.size());
            Write(zeros.data(), n);
            length -= n;
        }
    }
private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;
};

} // namespace

std::wstring SanitizeFileName(const std::wstring& name) {
    std::wstring out;
    out.reserve(name.size());
    for (wchar_t c : name) {
        if (c < 0x20 || wcschr(L"<>:\"/\\|?*", c) != nullptr) {
            out += L'_';
        } else {
            out += c;
        }
    }
    while (!out.empty() && (out.back() == L'.' || out.back() == L' ')) {
        out.pop_back();
    }
    if (out.empty()) {
        out = L"_";
    }
    // CON, PRN, AUX, NUL, COM1-9, LPT1-9 - with or without an extension
    std::wstring stem = out.substr(0, out.find(L'.'));
    std::transform(stem.begin(), stem.end(), stem.begin(), ::towupper);
    static const wchar_t* reserved[] = { L"CON", L"PRN", L"AUX", L"NUL" };
    bool isReserved = std::any_of(std::begin(reserved), std::end(reserved),
                                  [&](const wchar_t* r) { return stem == r; });
    if (stem.size() == 4 && (stem.rfind(L"COM", 0) == 0 || stem.rfind(L"LPT", 0) == 0) &&
        stem[3] >= L'1' && stem[3] <= L'9') {
        isReserved = true;
    }
    if (isReserved) {
        out = L"_" + out;
    }
    return out;
}

RecoveryEngine::RecoveryEngine() = default;
RecoveryEngine::~RecoveryEngine() = default;

bool RecoveryEngine::ValidateDestination(const std::wstring& sourceVolume, const std::wstring& destPath) {
    if (destPath.size() < 2 || PathsReferToSameFile(sourceVolume, destPath)) return false;
    const std::wstring normalized = NormalizeVolumePath(sourceVolume);
    const DWORD attributes = GetFileAttributesW(normalized.c_str());
    // A flat image may be read and recovered on its host volume. Its bytes
    // represent another disk; only overwriting the input itself is forbidden.
    if (attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY)) return true;
    const auto sourceDisks = PhysicalDisksOfSource(normalized);
    const auto destDisks = PhysicalDisksOfFolder(destPath);
    if (!sourceDisks || !destDisks) {
        // Unknown topology cannot establish that a local write is safe.
        // A network share has no local destination disk.
        return destPath.rfind(L"\\\\", 0) == 0 && destPath.rfind(L"\\\\?\\", 0) != 0 && destPath.rfind(L"\\\\.\\", 0) != 0;
    }
    for (const auto disk : *sourceDisks) {
        if (std::find(destDisks->begin(), destDisks->end(), disk) != destDisks->end()) return false;
    }
    return true;
}

VolumeGeometry RecoveryEngine::BuildGeometry(DiskHandle& disk, const RecoveryCandidate& file) {
    VolumeGeometry geom;
    geom.sectorSize = disk.GetSectorSize();
    geom.bytesPerCluster = file.file.GetFragments().BytesPerCluster();
    geom.totalClusters = geom.bytesPerCluster ? disk.GetDiskSize() / geom.bytesPerCluster : 0;
    geom.volumeStartOffset = file.volumeStartOffset;
    switch (file.source) {
    case RecoverySource::MFT:
    case RecoverySource::USN:   geom.fsType = FilesystemType::NTFS; break;
    case RecoverySource::ExFAT: geom.fsType = FilesystemType::ExFAT; break;
    case RecoverySource::FAT32: geom.fsType = FilesystemType::FAT32; break;
    case RecoverySource::Ext:   geom.fsType = FilesystemType::Ext; break;
    default:                    geom.fsType = FilesystemType::Unknown; break;
    }
    return geom;
}

void RecoveryEngine::RecoverFile(
    const RecoveryCandidate& file,
    const std::wstring& sourceVolume,
    const std::wstring& destinationPath,
    const ProgressCallback& onProgress)
{
    if (!ValidateDestination(sourceVolume, destinationPath)) {
        throw DestinationInvalidError("Invalid destination path");
    }
    DiskHandle disk(NormalizeVolumePath(sourceVolume));
    if (!disk.Open()) {
        throw DiskReadError(0, 0, GetLastError());
    }
    VolumeReader reader(disk, BuildGeometry(disk, file));
    const uint64_t unreadable = WriteRecoveredData(reader, file, destinationPath);
    if (onProgress) {
        wchar_t msg[512];
        swprintf_s(msg, L"Recovered %s (%llu bytes%s)", file.name.c_str(), file.fileSize,
                   unreadable ? L", some unreadable" : L"");
        onProgress(msg, -1.0f);
    }
}

RecoveryEngine::Outcome RecoveryEngine::RecoverMultipleFiles(
    const std::vector<RecoveryCandidate>& files,
    const std::wstring& sourceVolume,
    const std::wstring& destinationFolder,
    const ProgressCallback& onProgress)
{
    Outcome outcome;
    if (files.empty()) {
        if (onProgress) onProgress(L"No files to recover", 0.0f);
        return outcome;
    }
    if (!ValidateDestination(sourceVolume, destinationFolder)) {
        throw DestinationInvalidError("Invalid destination folder");
    }

    DiskHandle disk(NormalizeVolumePath(sourceVolume));
    if (!disk.Open()) {
        throw DiskReadError(0, 0, GetLastError());
    }

    const size_t total = files.size();
    for (size_t i = 0; i < total; ++i) {
        const auto& file = files[i];
        if (!file.IsRecoverable() && !file.file.HasResidentData()) {
            ++outcome.skipped;
            continue;
        }

        if (onProgress) {
            wchar_t msg[512];
            swprintf_s(msg, L"Recovering %s (%zu/%zu)", file.name.c_str(), i + 1, total);
            onProgress(msg, static_cast<float>(i) / total);
        }

        try {
            // the file's source folder below the destination, every part sanitized
            std::wstring folder = destinationFolder;
            size_t start = 0;
            while (start <= file.directory.size()) {
                size_t end = file.directory.find_first_of(L"\\/", start);
                if (end == std::wstring::npos) end = file.directory.size();
                if (end > start) {
                    folder += L"\\" + SanitizeFileName(file.directory.substr(start, end - start));
                }
                start = end + 1;
            }
            CreateDirectories(folder);
            const std::wstring target = UniquePath(folder, SanitizeFileName(file.name));

            VolumeReader reader(disk, BuildGeometry(disk, file));
            const uint64_t unreadable = WriteRecoveredData(reader, file, target);
            if (unreadable) {
                ++outcome.damaged;
            } else {
                ++outcome.recovered;
            }
        } catch (const std::exception& e) {
            ++outcome.failed;
            if (onProgress) {
                wchar_t msg[512];
                swprintf_s(msg, L"Failed to recover %s: %hs", file.name.c_str(), e.what());
                onProgress(msg, -1.0f);
            }
        }
    }

    if (onProgress) {
        wchar_t msg[256];
        swprintf_s(msg, L"Recovery complete: %d recovered, %d with unreadable parts, %d failed, %d without data",
                   outcome.recovered, outcome.damaged, outcome.failed, outcome.skipped);
        onProgress(msg, 1.0f);
    }
    return outcome;
}

uint64_t RecoveryEngine::WriteRecoveredData(
    VolumeReader& reader,
    const RecoveryCandidate& file,
    const std::wstring& outputPath)
{
    OutputFile out(outputPath);

    if (file.file.HasResidentData()) {
        const auto& data = file.file.GetResidentData();
        out.Write(data.data(), std::min<uint64_t>(data.size(), file.fileSize ? file.fileSize : data.size()));
        return 0;
    }
    if (file.fileSize == 0) {
        return 0;                                   // an empty file is recovered as one
    }

    const auto& fragments = file.file.GetFragments();
    if (fragments.IsEmpty()) {
        throw RecoveryError("Cluster locations lost - metadata exists but data location unknown");
    }
    const VolumeGeometry& geom = reader.Geometry();
    if (geom.bytesPerCluster == 0) {
        throw InvalidGeometryError("Invalid cluster size (0)");
    }

    if (file.encoding == DataEncoding::NtfsLznt1) {
        return WriteLznt1(reader, file, [&](const uint8_t* data, uint64_t length) { out.Write(data, length); },
                          [&](uint64_t length) { out.WriteZeros(length); });
    }

    std::vector<ClusterRun> runs = fragments.GetRuns();
    std::sort(runs.begin(), runs.end(), [](const ClusterRun& a, const ClusterRun& b) {
        return a.fileOffset < b.fileOffset;
    });

    const uint64_t size = file.fileSize;
    const uint64_t valid = std::min(size, file.validLength.value_or(size));
    const uint64_t chunkClusters = std::max<uint64_t>(1, COPY_CHUNK_BYTES / geom.bytesPerCluster);
    uint64_t position = 0;
    uint64_t unreadable = 0;

    auto emit = [&](const uint8_t* data, uint64_t length) {
        // bytes past the valid length are zeros, whatever the disk holds
        uint64_t real = position < valid ? std::min(length, valid - position) : 0;
        if (real) out.Write(data, real);
        if (length > real) out.WriteZeros(length - real);
        position += length;
    };

    for (const auto& run : runs) {
        if (position >= size) break;
        if (run.fileOffset > position) {            // a hole: sparse, or a gap in what is known
            const uint64_t gap = std::min(run.fileOffset, size) - position;
            out.WriteZeros(gap);
            position += gap;
        }
        if (run.fileOffset + run.clusterCount * geom.bytesPerCluster <= position) {
            continue;                               // overlaps what is written already
        }
        uint64_t cluster = run.startCluster + (position - run.fileOffset) / geom.bytesPerCluster;
        const uint64_t end = run.startCluster + run.clusterCount;
        while (cluster < end && position < size) {
            const uint64_t count = std::min(chunkClusters, end - cluster);
            const uint64_t want = std::min(count * geom.bytesPerCluster, size - position);
            std::vector<uint8_t> data;
            try {
                data = reader.ReadClusters(cluster, count);
            } catch (const ForensicsException&) {
                data.clear();
            }
            if (data.size() < want) {
                const uint64_t got = data.size();
                if (got) emit(data.data(), got);
                unreadable += want - got;
                out.WriteZeros(want - got);
                position += want - got;
            } else {
                emit(data.data(), want);
            }
            cluster += count;
        }
    }
    if (position < size) {                          // a sparse tail
        out.WriteZeros(size - position);
    }
    return unreadable;
}

} // namespace KVC
