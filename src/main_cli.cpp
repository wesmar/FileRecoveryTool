// ============================================================================
// main_cli.cpp - Command-Line Interface Implementation
// ============================================================================
// Provides scriptable access to all recovery features without GUI.
// Supports automation, batch processing, and detailed diagnostics.
// ============================================================================

#include "main_cli.h"
#include "DiskForensicsCore.h"
#include "RecoveryEngine.h"
#include "FileCarver.h"
#include "StringUtils.h"

#include <climits>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <io.h>
#include <fcntl.h>

namespace KVC {

// Forward declaration
void PrintDiagnostics(const CarvingStatistics& stats);

// CLI configuration parsed from command-line arguments
struct CLIConfig {
    wchar_t driveLetter;
    std::wstring folderFilter;
    std::wstring filenameFilter;
    std::wstring outputFolder;
    std::wstring csvPath;
    bool enableMft;
    bool enableUsn;
    bool enableCarving;
    bool enableRecovery;
    bool enableDiagnostics;
    bool showHelp;
    
    CLIConfig() 
        : driveLetter(L'\0')
        , enableMft(false)
        , enableUsn(false)
        , enableCarving(false)
        , enableRecovery(false)
        , enableDiagnostics(false)
        , showHelp(false)
    {}
};

// Storage for discovered files
std::vector<DeletedFileEntry> g_foundFiles;
CarvingStatistics g_carvingStats;

// Display usage information
void PrintHelp() {
    wprintf(L"\n");
    wprintf(L"KVC File Recovery Tool - Command-Line Interface\n");
    wprintf(L"===============================================\n\n");
    wprintf(L"USAGE:\n");
    wprintf(L"  kvc_recovery.exe --cli --drive <LETTER> [OPTIONS]\n\n");
    wprintf(L"REQUIRED:\n");
    wprintf(L"  --cli              Enable command-line mode\n");
    wprintf(L"  --drive <LETTER>   Drive letter to scan (e.g., C, D, E)\n\n");
    wprintf(L"SCAN MODES (at least one required):\n");
    wprintf(L"  --mft              Scan Master File Table (ultra fast)\n");
    wprintf(L"  --usn              Scan USN Journal (fast)\n");
    wprintf(L"  --carving          Scan free space for file signatures (slow)\n");
    wprintf(L"  --all              Enable all scan modes\n\n");
    wprintf(L"FILTERS:\n");
    wprintf(L"  --folder <PATH>    Filter by folder path (case-insensitive)\n");
    wprintf(L"  --filename <NAME>  Filter by filename (case-insensitive, wildcards)\n\n");
    wprintf(L"RECOVERY:\n");
    wprintf(L"  --recover          Save recovered files to disk\n");
    wprintf(L"  --output <PATH>    Output folder (required with --recover)\n\n");
    wprintf(L"REPORTING:\n");
    wprintf(L"  --diagnostics      Show fragmentation statistics\n");
    wprintf(L"  --csv <FILE>       Export results to CSV file\n\n");
    wprintf(L"EXAMPLES:\n");
    wprintf(L"  Quick MFT scan:\n");
    wprintf(L"    kvc_recovery.exe --cli --drive C --mft\n\n");
    wprintf(L"  Full scan with recovery:\n");
    wprintf(L"    kvc_recovery.exe --cli --drive D --all --recover --output E:\\recovered\n\n");
    wprintf(L"  Filtered scan with diagnostics:\n");
    wprintf(L"    kvc_recovery.exe --cli --drive C --carving --filename *.jpg --diagnostics\n\n");
    wprintf(L"  Export to CSV:\n");
    wprintf(L"    kvc_recovery.exe --cli --drive E --mft --csv results.csv\n\n");
    wprintf(L"EXIT CODES:\n");
    wprintf(L"  0 = Success (files found)\n");
    wprintf(L"  1 = No files found\n");
    wprintf(L"  2 = Invalid arguments\n");
    wprintf(L"  3 = Drive access error\n");
    wprintf(L"  4 = Recovery failed\n\n");
}

// Parse command-line arguments into configuration
bool ParseArguments(int argc, LPWSTR* argv, CLIConfig& config) {
    bool hasCliFlag = false;
    bool hasDrive = false;
    
    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];
        std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);
        
        if (arg == L"--cli") {
            hasCliFlag = true;
        }
        else if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            config.showHelp = true;
            return true;
        }
        else if (arg == L"--drive" && i + 1 < argc) {
            config.driveLetter = towupper(argv[++i][0]);
            hasDrive = true;
        }
        else if (arg == L"--mft") {
            config.enableMft = true;
        }
        else if (arg == L"--usn") {
            config.enableUsn = true;
        }
        else if (arg == L"--carving") {
            config.enableCarving = true;
        }
        else if (arg == L"--all") {
            config.enableMft = true;
            config.enableUsn = true;
            config.enableCarving = true;
        }
        else if (arg == L"--folder" && i + 1 < argc) {
            config.folderFilter = argv[++i];
        }
        else if (arg == L"--filename" && i + 1 < argc) {
            config.filenameFilter = argv[++i];
        }
        else if (arg == L"--recover") {
            config.enableRecovery = true;
        }
        else if (arg == L"--output" && i + 1 < argc) {
            config.outputFolder = argv[++i];
        }
        else if (arg == L"--diagnostics") {
            config.enableDiagnostics = true;
        }
        else if (arg == L"--csv" && i + 1 < argc) {
            config.csvPath = argv[++i];
        }
        else {
            wprintf(L"[ERROR] Unknown argument: %s\n", argv[i]);
            return false;
        }
    }
    
    if (!hasCliFlag) {
        return false; // Not CLI mode
    }
    
    if (!hasDrive) {
        wprintf(L"[ERROR] Missing required argument: --drive\n");
        return false;
    }
    
    if (!config.enableMft && !config.enableUsn && !config.enableCarving) {
        wprintf(L"[ERROR] At least one scan mode required (--mft, --usn, --carving, or --all)\n");
        return false;
    }
    
    if (config.enableRecovery && config.outputFolder.empty()) {
        wprintf(L"[ERROR] --output required when using --recover\n");
        return false;
    }
    
    return true;
}

// Progress callback for console output
void OnProgress(const std::wstring& message, float progress) {
    if (progress >= 0.0f && progress <= 1.0f) {
        int percent = static_cast<int>(progress * 100);
        wprintf(L"[PROGRESS] %s [%d%%]\n", message.c_str(), percent);
    } else {
        wprintf(L"[INFO] %s\n", message.c_str());
    }
}

// File found callback for collecting results
void OnFileFound(const DeletedFileEntry& file) {
    g_foundFiles.push_back(file);
}

// Export results to CSV file
bool ExportToCSV(const std::wstring& csvPath, const std::vector<DeletedFileEntry>& files) {
    std::wofstream csv(csvPath);
    if (!csv.is_open()) {
        wprintf(L"[ERROR] Failed to create CSV file: %s\n", csvPath.c_str());
        return false;
    }
    
    // Write CSV header
    csv << L"Name,Path,Size,Size_Formatted,Filesystem,Recoverable,Has_Deleted_Time,Deleted_Time\n";
    
    // Write file entries
    for (const auto& file : files) {
        // Escape commas in strings
        std::wstring cleanName = file.name;
        std::wstring cleanPath = file.path;
        std::replace(cleanName.begin(), cleanName.end(), L',', L'_');
        std::replace(cleanPath.begin(), cleanPath.end(), L',', L'_');
        
        csv << cleanName << L","
            << cleanPath << L","
            << file.size << L","
            << file.sizeFormatted << L","
            << file.filesystemType << L","
            << (file.isRecoverable ? L"Yes" : L"No") << L","
            << (file.hasDeletedTime ? L"Yes" : L"No") << L",";
        
		if (file.hasDeletedTime && file.deletedTime.has_value()) {
            auto time_t_val = std::chrono::system_clock::to_time_t(file.deletedTime.value());
            std::tm tm_val;
            localtime_s(&tm_val, &time_t_val);
            wchar_t timeStr[64];
            wcsftime(timeStr, 64, L"%Y-%m-%d %H:%M:%S", &tm_val);
            csv << timeStr;
        }
        
        csv << L"\n";
    }
    
    csv.close();
    wprintf(L"[INFO] Exported %zu files to CSV: %s\n", files.size(), csvPath.c_str());
    return true;
}

// Print fragmentation diagnostics
void PrintDiagnostics(const CarvingStatistics& stats) {
    wprintf(L"\n");
    wprintf(L"=== FRAGMENTATION DIAGNOSTICS ===\n");
    wprintf(L"Total signatures found:     %llu\n", stats.totalSignaturesFound);
    wprintf(L"Files with known size:      %llu", stats.filesWithKnownSize);
    
    if (stats.totalSignaturesFound > 0) {
        float knownPct = (100.0f * stats.filesWithKnownSize) / stats.totalSignaturesFound;
        wprintf(L" (%.1f%%)\n", knownPct);
    } else {
        wprintf(L"\n");
    }
    
    wprintf(L"Files validated:            %llu\n", stats.filesWithValidatedSize);
    wprintf(L"Potentially fragmented:     %llu", stats.potentiallyFragmented);
    
    if (stats.filesWithKnownSize > 0) {
        float fragPct = (100.0f * stats.potentiallyFragmented) / stats.filesWithKnownSize;
        wprintf(L" (%.1f%%)\n", fragPct);
    } else {
        wprintf(L"\n");
    }
    
    wprintf(L"Severely fragmented:        %llu\n", stats.severelyFragmented);
    wprintf(L"Unknown size (no header):   %llu\n", stats.unknownSize);
    
	if (!stats.byFormat.empty()) {
		wprintf(L"\nBy format:\n");
		for (const auto& [ext, count] : stats.byFormat) {
			std::wstring extWide(ext.begin(), ext.end());
			wprintf(L"  %-8s: %llu files", extWide.c_str(), count);
			
			auto fragIt = stats.fragmentedByFormat.find(ext);
			if (fragIt != stats.fragmentedByFormat.end() && fragIt->second > 0) {
				float pct = (100.0f * fragIt->second) / count;
				wprintf(L" (%llu fragmented, %.1f%%)", fragIt->second, pct);
			}
			wprintf(L"\n");
		}
	}
    
    wprintf(L"\n");
    
    // Recommendation based on fragmentation
    if (stats.filesWithKnownSize > 0) {
        float fragPct = (100.0f * stats.potentiallyFragmented) / stats.filesWithKnownSize;
        
        if (fragPct < 15.0f) {
            wprintf(L"RECOMMENDATION: Low fragmentation (%.1f%%) - current carving sufficient\n", fragPct);
        } else if (fragPct < 30.0f) {
            wprintf(L"RECOMMENDATION: Moderate fragmentation (%.1f%%) - consider size-based carving\n", fragPct);
        } else {
            wprintf(L"RECOMMENDATION: High fragmentation (%.1f%%) - bifragment gap carving recommended\n", fragPct);
        }
    }
    
    wprintf(L"\n");
}

// Perform recovery of found files
int RecoverFiles(const CLIConfig& config, const std::vector<DeletedFileEntry>& files) {
    if (files.empty()) {
        wprintf(L"[INFO] No files to recover\n");
        fflush(stdout);
        return 1;
    }
    
    wprintf(L"[INFO] Recovering %zu files to: %s\n", files.size(), config.outputFolder.c_str());
    
    RecoveryEngine engine;
    
    // Validate destination
    if (!engine.ValidateDestination(config.driveLetter, config.outputFolder)) {
        wprintf(L"[ERROR] Cannot recover to source drive - choose different destination\n");
        fflush(stdout);
        return 4;
    }
    
    auto startTime = std::chrono::steady_clock::now();
    
    bool success = engine.RecoverMultipleFiles(
        files,
        config.driveLetter,
        config.outputFolder,
        [](const std::wstring& msg, float progress) {
            if (progress >= 0.0f && progress <= 1.0f) {
                int percent = static_cast<int>(progress * 100);
                wprintf(L"[RECOVERY] %s [%d%%]\n", msg.c_str(), percent);
            } else {
                wprintf(L"[RECOVERY] %s\n", msg.c_str());
            }
        }
    );
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    if (success) {
        wprintf(L"[SUCCESS] Recovery completed in %lld seconds\n", duration.count());
        fflush(stdout);
        return 0;
    } else {
        wprintf(L"[ERROR] Recovery failed\n");
        fflush(stdout);
        return 4;
    }
}

// Main CLI execution
int RunCLI(int argc, LPWSTR* argv) {
    // Attach to parent console for CLI output (required for GUI subsystem)
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
        AllocConsole();  // Create new console if no parent
    }
    
    // Redirect standard output to console
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONOUT$", "w", stderr);
    
    CLIConfig config;
    
    // Parse command-line arguments
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
    
    // Display scan configuration
    wprintf(L"\n");
    wprintf(L"=== KVC File Recovery - CLI Mode ===\n");
    wprintf(L"Drive:         %c:\n", config.driveLetter);
    wprintf(L"Scan modes:    ");
    if (config.enableMft) wprintf(L"MFT ");
    if (config.enableUsn) wprintf(L"USN ");
    if (config.enableCarving) wprintf(L"CARVING ");
    wprintf(L"\n");
    
    if (!config.folderFilter.empty()) {
        wprintf(L"Folder filter: %s\n", config.folderFilter.c_str());
    }
    if (!config.filenameFilter.empty()) {
        wprintf(L"File filter:   %s\n", config.filenameFilter.c_str());
    }
    if (config.enableRecovery) {
        wprintf(L"Output:        %s\n", config.outputFolder.c_str());
    }
    wprintf(L"\n");
    
    // Initialize forensics core
    DiskForensicsCore forensics;
    
    // Detect filesystem
    FilesystemType fsType = forensics.DetectFilesystem(config.driveLetter);
    const wchar_t* fsName = L"Unknown";
    switch (fsType) {
        case FilesystemType::NTFS: fsName = L"NTFS"; break;
        case FilesystemType::ExFAT: fsName = L"exFAT"; break;
        case FilesystemType::FAT32: fsName = L"FAT32"; break;
        default: break;
    }
    wprintf(L"[INFO] Filesystem: %s\n", fsName);
    
    if (fsType == FilesystemType::Unknown) {
        wprintf(L"[ERROR] Unsupported or unreadable filesystem\n");
        fflush(stdout);
        return 3;
    }
    
    // Clear global state
    g_foundFiles.clear();
    g_carvingStats = CreateCarvingDiagnostics();
    
    // Start scan
    auto startTime = std::chrono::steady_clock::now();
    bool shouldStop = false;
    
    bool scanSuccess = forensics.StartScan(
        config.driveLetter,
        config.folderFilter,
        config.filenameFilter,
        OnFileFound,
        OnProgress,
        shouldStop,
        config.enableMft,
        config.enableUsn,
        config.enableCarving
    );
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    // Report results
    wprintf(L"\n");
    wprintf(L"=== SCAN COMPLETE ===\n");
    wprintf(L"Files found:   %zu\n", g_foundFiles.size());
    wprintf(L"Scan time:     %lld seconds\n", duration.count());
    wprintf(L"\n");
    
    if (!scanSuccess) {
        wprintf(L"[WARNING] Scan completed with errors\n");
    }
    
    // Print diagnostics if requested
    if (config.enableDiagnostics && config.enableCarving) {
        PrintDiagnostics(g_carvingStats);
    }
    
    // Export to CSV if requested
    if (!config.csvPath.empty()) {
        if (!ExportToCSV(config.csvPath, g_foundFiles)) {
            fflush(stdout);
            return 4;
        }
    }
    
    // Perform recovery if requested
    if (config.enableRecovery) {
        int recoveryResult = RecoverFiles(config, g_foundFiles);
        return recoveryResult;
    }
    
    // Return appropriate exit code
    if (g_foundFiles.empty()) {
        wprintf(L"[INFO] No deleted files found\n");
        fflush(stdout);
        return 1;
    }
    
    fflush(stdout);
    return 0;
}

} // namespace KVC
