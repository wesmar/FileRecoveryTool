// ============================================================================
// main_cli.cpp - Command-Line Interface Implementation
// ============================================================================
// Scriptable access to every recovery feature. Output goes to the console
// the tool was started from, or - when stdout is redirected to a file or a
// pipe - there, as UTF-8.
// ============================================================================

#include "app/main_cli.h"
#include "core/DiskForensicsCore.h"
#include "recovery/RecoveryEngine.h"
#include "carving/FileCarver.h"
#include "support/StringUtils.h"
#include "io/VolumeLocator.h"
#include "filesystems/FilesystemDetector.h"
#include "recovery/CsvExport.h"

#include <climits>
#include <atomic>
#include <cstdio>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <io.h>
#include <fcntl.h>

namespace KVC {

void PrintDiagnostics(const CarvingStatistics& stats);

struct CLIConfig {
    std::wstring volume;            // "D:" or a device path
    std::wstring folderFilter;
    std::wstring filenameFilter;
    std::wstring outputFolder;
    std::wstring csvPath;
    bool enableMft = false;
    bool enableUsn = false;
    bool enableCarving = false;
    bool rawMode = false;
    bool enableRecovery = false;
    bool enableDiagnostics = false;
    bool listVolumes = false;
    bool showHelp = false;
};

namespace {

std::vector<DeletedFileEntry> g_foundFiles;

void PrintHelp() {
    wprintf(L"\n");
    wprintf(L"KVC File Recovery Tool - Command-Line Interface\n");
    wprintf(L"===============================================\n\n");
    wprintf(L"USAGE:\n");
    wprintf(L"  FRT_x64.exe --cli --drive <LETTER> [OPTIONS]\n");
    wprintf(L"  FRT_x64.exe --cli --volume <DEVICE> [OPTIONS]\n");
    wprintf(L"  FRT_x64.exe --cli --list\n\n");
    wprintf(L"SOURCE:\n");
    wprintf(L"  --drive <LETTER>   Volume by drive letter (C, D, E ...)\n");
    wprintf(L"  --volume <DEVICE>  Volume by device path, also without a letter:\n");
    wprintf(L"                     \\\\.\\HarddiskVolume7 or \\\\?\\Volume{GUID}\n");
    wprintf(L"  --image <PATH>     Flat byte-for-byte image (not a VHD/VHDX container)\n");
    wprintf(L"  --list             List every volume with the file system it holds\n\n");
    wprintf(L"FILE SYSTEMS: NTFS, FAT12, FAT16, FAT32, exFAT, ext2, ext3, ext4\n\n");
    wprintf(L"SCAN MODES (at least one required):\n");
    wprintf(L"  --mft              The file system's own records: MFT, FAT/exFAT\n");
    wprintf(L"                     directories, ext inodes and journal (fast)\n");
    wprintf(L"  --usn              NTFS change journal (fast)\n");
    wprintf(L"  --carving          Scan free space for file signatures (slow)\n");
    wprintf(L"  --raw              Scan every byte for signatures, without a file system\n");
    wprintf(L"                     Separate mode; includes live files, no original names\n");
    wprintf(L"  --all              Enable all scan modes\n\n");
    wprintf(L"FILTERS (case-insensitive):\n");
    wprintf(L"  --folder <TEXT>    Folder path contains TEXT\n");
    wprintf(L"  --filename <NAME>  Name: *.jpg, IMG_????.*, several with ';',\n");
    wprintf(L"                     or plain text for a part of the name\n\n");
    wprintf(L"RECOVERY:\n");
    wprintf(L"  --recover          Save recovered files, source folders recreated\n");
    wprintf(L"  --output <PATH>    Output folder on another volume (required)\n\n");
    wprintf(L"REPORTING:\n");
    wprintf(L"  --diagnostics      Show fragmentation statistics (carving)\n");
    wprintf(L"  --csv <FILE>       Export results to a CSV file (UTF-8)\n\n");
    wprintf(L"EXAMPLES:\n");
    wprintf(L"  FRT_x64.exe --cli --drive D --mft --filename *.jpg;*.png\n");
    wprintf(L"  FRT_x64.exe --cli --drive D --all --recover --output E:\\recovered\n");
    wprintf(L"  FRT_x64.exe --cli --volume \\\\.\\HarddiskVolume7 --mft --csv ext4.csv\n\n");
    wprintf(L"EXIT CODES:\n");
    wprintf(L"  0 = Success (files found / recovered)\n");
    wprintf(L"  1 = No files found\n");
    wprintf(L"  2 = Invalid arguments\n");
    wprintf(L"  3 = Volume access error or unsupported file system\n");
    wprintf(L"  4 = Recovery failed\n\n");
}

bool ParseArguments(int argc, LPWSTR* argv, CLIConfig& config) {
    bool hasCliFlag = false;
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);
        const bool hasValue = i + 1 < argc;

        if (arg == L"--cli") hasCliFlag = true;
        else if (arg == L"--help" || arg == L"-h" || arg == L"/?") { config.showHelp = true; return true; }
        else if (arg == L"--drive" && hasValue) config.volume = argv[++i];
        else if ((arg == L"--volume" || arg == L"--device") && hasValue) config.volume = argv[++i];
        else if (arg == L"--image" && hasValue) config.volume = argv[++i];
        else if (arg == L"--list") config.listVolumes = true;
        else if (arg == L"--mft") config.enableMft = true;
        else if (arg == L"--usn") config.enableUsn = true;
        else if (arg == L"--carving") config.enableCarving = true;
        else if (arg == L"--raw") config.rawMode = true;
        else if (arg == L"--all") config.enableMft = config.enableUsn = config.enableCarving = true;
        else if (arg == L"--folder" && hasValue) config.folderFilter = argv[++i];
        else if (arg == L"--filename" && hasValue) config.filenameFilter = argv[++i];
        else if (arg == L"--recover") config.enableRecovery = true;
        else if (arg == L"--output" && hasValue) config.outputFolder = argv[++i];
        else if (arg == L"--diagnostics") config.enableDiagnostics = true;
        else if (arg == L"--csv" && hasValue) config.csvPath = argv[++i];
        else {
            wprintf(L"[ERROR] Unknown argument: %s\n", argv[i]);
            return false;
        }
    }

    if (!hasCliFlag) return false;
    if (config.listVolumes) return true;
    if (config.volume.empty()) {
        wprintf(L"[ERROR] Missing source: --drive or --volume\n");
        return false;
    }
    if (config.rawMode && (config.enableMft || config.enableUsn || config.enableCarving)) {
        wprintf(L"[ERROR] --raw is a separate mode; do not combine it with --mft, --usn, --carving or --all\n");
        return false;
    }
    if (!config.enableMft && !config.enableUsn && !config.enableCarving && !config.rawMode) {
        wprintf(L"[ERROR] At least one scan mode required (--mft, --usn, --carving, or --all)\n");
        return false;
    }
    if (config.enableRecovery && config.outputFolder.empty()) {
        wprintf(L"[ERROR] --output required when using --recover\n");
        return false;
    }
    return true;
}

void OnProgress(const std::wstring& message, float progress) {
    if (progress >= 0.0f && progress <= 1.0f) {
        wprintf(L"[PROGRESS] %s [%d%%]\n", message.c_str(), static_cast<int>(progress * 100));
    } else {
        wprintf(L"[INFO] %s\n", message.c_str());
    }
}

bool ExportToCSV(const std::wstring& csvPath, const std::vector<DeletedFileEntry>& files) {
    if (!ExportCandidatesToCsv(csvPath, files)) {
        wprintf(L"[ERROR] Failed to write CSV file: %s\n", csvPath.c_str());
        return false;
    }
    wprintf(L"[INFO] Exported %zu files to CSV: %s\n", files.size(), csvPath.c_str());
    return true;
}

int ListVolumes() {
    wprintf(L"%-28s %-8s %-10s %12s\n", L"Volume", L"Letter", L"FS", L"Size");
    for (const auto& v : EnumerateVolumes()) {
        DiskHandle disk(v.path);
        VolumeInfo info;
        if (disk.Open()) {
            info = DetectFilesystem(disk);
        }
        const std::wstring device = L"\\\\.\\" + v.ntDevice.substr(v.ntDevice.rfind(L'\\') + 1);
        wprintf(L"%-28s %-8s %-10s %12s\n", device.c_str(), v.letters.empty() ? L"-" : v.letters.c_str(),
                info.name.empty() ? L"(no access)" : info.name.c_str(),
                info.size ? StringUtils::FormatFileSize(info.size).c_str() : L"");
    }
    for (const auto& path : EnumeratePhysicalDisks()) {
        DiskHandle disk(path);
        if (disk.Open()) wprintf(L"%-28s %-8s %-10s %12s\n", path.c_str(), L"-", L"RAW disk", StringUtils::FormatFileSize(disk.GetDiskSize()).c_str());
    }
    fflush(stdout);
    return 0;
}

int RecoverFiles(const CLIConfig& config, const std::vector<DeletedFileEntry>& files) {
    if (files.empty()) {
        wprintf(L"[INFO] No files to recover\n");
        return 1;
    }
    wprintf(L"[INFO] Recovering %zu files to: %s\n", files.size(), config.outputFolder.c_str());

    if (!RecoveryEngine::ValidateDestination(config.volume, config.outputFolder)) {
        wprintf(L"[ERROR] Destination must be outside the source disk, with a verifiable storage location\n");
        return 4;
    }

    RecoveryEngine engine;
    const auto startTime = std::chrono::steady_clock::now();
    RecoveryEngine::Outcome outcome;
    try {
        outcome = engine.RecoverMultipleFiles(files, config.volume, config.outputFolder,
            [](const std::wstring& msg, float progress) {
                if (progress >= 0.0f && progress <= 1.0f) {
                    wprintf(L"[RECOVERY] %s [%d%%]\n", msg.c_str(), static_cast<int>(progress * 100));
                } else {
                    wprintf(L"[RECOVERY] %s\n", msg.c_str());
                }
            });
    } catch (const std::exception& e) {
        wprintf(L"[ERROR] Recovery failed: %hs\n", e.what());
        return 4;
    }
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();

    wprintf(L"[RESULT] recovered=%d damaged=%d failed=%d skipped=%d seconds=%lld\n",
            outcome.recovered, outcome.damaged, outcome.failed, outcome.skipped, seconds);
    return (outcome.recovered + outcome.damaged) > 0 ? 0 : 4;
}

// stdout redirected to a file or a pipe stays where it is; otherwise the
// console the tool was started from is used (this is a GUI-subsystem image)
void ConnectOutput() {
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const DWORD type = (out && out != INVALID_HANDLE_VALUE) ? GetFileType(out) : FILE_TYPE_UNKNOWN;
    if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE) {
        FILE* dummy;
        int fd = _open_osfhandle(reinterpret_cast<intptr_t>(out), _O_WRONLY);
        if (fd >= 0 && _fileno(stdout) < 0) {
            freopen_s(&dummy, "NUL", "w", stdout);
        }
        if (fd >= 0) {
            _dup2(fd, _fileno(stdout));
        }
        _setmode(_fileno(stdout), _O_U8TEXT);
        return;
    }
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();
    }
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    _setmode(_fileno(stdout), _O_U16TEXT);
}

} // namespace

void PrintDiagnostics(const CarvingStatistics& stats) {
    wprintf(L"\n=== FRAGMENTATION DIAGNOSTICS ===\n");
    wprintf(L"Total signatures found:     %llu\n", stats.totalSignaturesFound);
    wprintf(L"Files with known size:      %llu\n", stats.filesWithKnownSize);
    wprintf(L"Boundaries parsed:          %llu\n", stats.filesWithValidatedSize);
    wprintf(L"Scan units visited:         %llu\n", stats.clustersScanned);
    wprintf(L"Read-error batches:         %llu\n", stats.readErrorBatches);
    wprintf(L"Potentially fragmented:     %llu\n", stats.potentiallyFragmented);
    wprintf(L"Severely fragmented:        %llu\n", stats.severelyFragmented);
    wprintf(L"Unknown size (no header):   %llu\n", stats.unknownSize);
    if (!stats.byFormat.empty()) {
        wprintf(L"\nBy format:\n");
        for (const auto& [ext, count] : stats.byFormat) {
            std::wstring extWide(ext.begin(), ext.end());
            wprintf(L"  %-8s: %llu files", extWide.c_str(), count);
            auto fragIt = stats.fragmentedByFormat.find(ext);
            if (fragIt != stats.fragmentedByFormat.end() && fragIt->second > 0) {
                wprintf(L" (%llu fragmented, %.1f%%)", fragIt->second, (100.0f * fragIt->second) / count);
            }
            wprintf(L"\n");
        }
    }
    wprintf(L"\n");
}

int RunCLI(int argc, LPWSTR* argv) {
    ConnectOutput();

    CLIConfig config;
    if (!ParseArguments(argc, argv, config)) {
        if (config.showHelp) {
            PrintHelp();
            fflush(stdout);
            return 0;
        }
        wprintf(L"[ERROR] Invalid arguments. Use --help for usage information.\n");
        fflush(stdout);
        return 2;
    }
    if (config.showHelp) {
        PrintHelp();
        fflush(stdout);
        return 0;
    }
    if (config.listVolumes) {
        return ListVolumes();
    }

    config.volume = NormalizeVolumePath(config.volume);
    if ((!config.csvPath.empty() && !RecoveryEngine::ValidateDestination(config.volume, config.csvPath)) ||
        (config.enableRecovery && !RecoveryEngine::ValidateDestination(config.volume, config.outputFolder))) {
        wprintf(L"[ERROR] Choose a destination outside the source disk; the input image must not be overwritten\n");
        fflush(stdout);
        return 4;
    }

    wprintf(L"\n=== KVC File Recovery - CLI Mode ===\n");
    wprintf(L"Volume:        %s\n", config.volume.c_str());
    wprintf(L"Scan modes:    %s%s%s%s\n", config.enableMft ? L"FS-RECORDS " : L"",
            config.enableUsn ? L"USN " : L"", config.enableCarving ? L"CARVING" : L"", config.rawMode ? L"RAW" : L"");
    if (!config.folderFilter.empty()) wprintf(L"Folder filter: %s\n", config.folderFilter.c_str());
    if (!config.filenameFilter.empty()) wprintf(L"File filter:   %s\n", config.filenameFilter.c_str());
    if (config.enableRecovery) wprintf(L"Output:        %s\n", config.outputFolder.c_str());
    wprintf(L"\n");

    DiskForensicsCore forensics;
    const VolumeInfo info = forensics.DetectFilesystem(config.volume);
    wprintf(L"[INFO] File system: %s\n", info.name.empty() ? L"(volume not accessible)" : info.name.c_str());
    if (info.type == FilesystemType::Unknown && !config.rawMode) {
        wprintf(L"[ERROR] Unsupported or unreadable file system\n");
        fflush(stdout);
        return 3;
    }

    g_foundFiles.clear();

    const auto startTime = std::chrono::steady_clock::now();
    std::atomic<bool> shouldStop{ false };
    const bool scanSuccess = forensics.StartScan(
        config.volume, config.folderFilter, config.filenameFilter,
        [&](const DeletedFileEntry& file) {
            DeletedFileEntry copy = file;
            if (copy.filesystemType.empty()) copy.filesystemType = info.name;
            g_foundFiles.push_back(std::move(copy));
        },
        OnProgress, shouldStop, config.enableMft, config.enableUsn, config.enableCarving, config.rawMode);
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - startTime).count();

    wprintf(L"\n=== SCAN COMPLETE ===\n");
    wprintf(L"Files found:   %zu\n", g_foundFiles.size());
    wprintf(L"Scan time:     %lld seconds\n\n", seconds);
    if (!scanSuccess) {
        wprintf(L"[WARNING] Scan completed with errors\n");
    }
    if (config.enableDiagnostics && (config.enableCarving || config.rawMode)) {
        PrintDiagnostics(forensics.LastCarvingStatistics());
        wprintf(L"Scan unit: %s\n", config.rawMode ? L"byte" : L"file-system cluster");
    }
    if (!config.csvPath.empty() && !ExportToCSV(config.csvPath, g_foundFiles)) {
        fflush(stdout);
        return 4;
    }
    if (!scanSuccess) { fflush(stdout); return 3; }
    if (config.enableRecovery) {
        const int result = RecoverFiles(config, g_foundFiles);
        fflush(stdout);
        return result;
    }
    if (g_foundFiles.empty()) {
        wprintf(L"[INFO] No deleted files found\n");
        fflush(stdout);
        return 1;
    }
    fflush(stdout);
    return 0;
}

} // namespace KVC
