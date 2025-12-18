// FAT32Scanner.cpp
#include "FAT32Scanner.h"
#include "Constants.h"
#include "StringUtils.h"
#include <algorithm>
#include <cwctype>
#include <cstring>
#include <string>

namespace KVC {

FAT32Scanner::FAT32Scanner() = default;
FAT32Scanner::~FAT32Scanner() = default;

// Read and parse the FAT32 boot sector.
FAT32BootSector FAT32Scanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    FAT32BootSector boot = {};
    if (data.size() >= sizeof(FAT32BootSector)) {
        std::memcpy(&boot, data.data(), sizeof(FAT32BootSector));
    }
    
    return boot;
}

// Main FAT32 volume scanning routine for deleted file discovery.
bool FAT32Scanner::ScanVolume(
    DiskHandle& disk,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    bool& shouldStop,
    const ScanConfiguration& config)
{
    FAT32BootSector boot = ReadBootSector(disk);
    // Validate FAT32 signature.
    if (boot.signature != 0xAA55) {
        return false;
    }

    // FAT32 validation: rootEntryCount and fatSize16 must be 0.
    if (boot.rootEntryCount != 0 || boot.fatSize16 != 0) {
        return false;
    }

    // Validate reasonable values.
    if (boot.bytesPerSector == 0 || boot.sectorsPerCluster == 0) {
        return false;
    }

    ScanContext context;
    context.sectorSize = boot.bytesPerSector;
    context.sectorsPerCluster = boot.sectorsPerCluster;
    context.rootCluster = boot.rootCluster;
    context.clusterSize = context.sectorSize * context.sectorsPerCluster;
    // Calculate data area start sector: DataStart = ReservedSectors + (NumberOfFATs * FATSize32).
    context.dataStartSector = boot.reservedSectors + 
                             (static_cast<uint64_t>(boot.numberOfFATs) * boot.fatSize32);
    context.folderFilter = folderFilter;
    context.filenameFilter = filenameFilter;
    
    // Convert filters to lowercase for case-insensitive search.
    std::transform(context.folderFilter.begin(), context.folderFilter.end(), 
                  context.folderFilter.begin(), ::towlower);
    std::transform(context.filenameFilter.begin(), context.filenameFilter.end(), 
                  context.filenameFilter.begin(), ::towlower);
    // Queue for directory traversal.
    std::deque<DirectoryWorkItem> dirQueue;
    dirQueue.push_back({ context.rootCluster, L"" });

    uint64_t directoriesScanned = 0;
    uint64_t filesFound = 0;

    onProgress(L"Starting FAT32 structure scan...", 0.0f);

    // Breadth-first search of directory tree.
    while (!dirQueue.empty() && !shouldStop) {
        DirectoryWorkItem current = dirQueue.front();
        dirQueue.pop_front();

        ProcessDirectory(disk, current, dirQueue, [&](const DeletedFileEntry& file) {
            onFileFound(file);
            filesFound++;
        }, context);
        directoriesScanned++;

        // Update progress periodically.
        if ((directoriesScanned % 10) == 0) {
            wchar_t statusMsg[256];
            swprintf_s(statusMsg, L"FAT32 Scan: %llu directories, %llu deleted files found", 
                      directoriesScanned, filesFound);
            onProgress(statusMsg, 0.5f);
        }
        
        // Safety limit to prevent infinite loops.
        if (directoriesScanned > config.exfatDirectoryEntriesLimit) {
            onProgress(L"Directory limit reached", 0.9f);
            break;
        }
    }

    wchar_t completeMsg[256];
    swprintf_s(completeMsg, L"FAT32 scan complete: %llu files found", filesFound);
    onProgress(completeMsg, 1.0f);

    return true;
}

// Parse 8.3 short filename from directory entry.
std::wstring FAT32Scanner::ParseShortName(const uint8_t* name) {
    if (!name) return L"";
    
    std::string sName;
    // Extract base name (8 characters).
    for (int i = 0; i < 8; ++i) {
        if (name[i] != ' ' && name[i] != 0) {
            sName += static_cast<char>(name[i]);
        }
    }
    
    // Add extension if present (3 characters).
    if (name[8] != ' ' && name[8] != 0) {
        sName += ".";
        for (int i = 8; i < 11; ++i) {
            if (name[i] != ' ' && name[i] != 0) {
                sName += static_cast<char>(name[i]);
            }
        }
    }
    
    // Convert to wstring.
    return std::wstring(sName.begin(), sName.end());
}

// Process a single directory and extract deleted file entries.
void FAT32Scanner::ProcessDirectory(
    DiskHandle& disk, 
    const DirectoryWorkItem& dirItem,
    std::deque<DirectoryWorkItem>& subDirs,
    DiskForensicsCore::FileFoundCallback onFileFound,
    const ScanContext& context)
{
    // Read directory content (limit to 2MB to avoid huge corrupted chains).
    auto data = ReadClusterChain(disk, dirItem.firstCluster, context, Constants::DIRECTORY_READ_LIMIT);
    if (data.empty()) return;

    std::wstring lfnBuffer;
    
    // Process each 32-byte directory entry.
    for (size_t i = 0; i + 32 <= data.size(); i += 32) {
        const uint8_t* raw = data.data() + i;
        uint8_t marker = raw[0];
        uint8_t attr = raw[11];

        // End of directory marker.
        if (marker == 0x00) break;
        // ====================================================================
        // Handle Long File Name (LFN) entries (attr = 0x0F)
        // ====================================================================
        if (attr == 0x0F) {
            const FATLFNEntry* lfn = reinterpret_cast<const FATLFNEntry*>(raw);

            // If the entry is deleted (marker 0xE5), the sequence number starts with 0xE5 (11100101).
            // The 0x40 bit (6th bit) marks the "Last LFN entry".
            // Since 0xE5 & 0x40 is TRUE, every deleted LFN entry looks like the start of a name,
            // causing the buffer to clear constantly.
            bool isDeletedLfn = (marker == 0xE5);
            
            // Only clear buffer if it's a valid "Last Entry" marker AND not just a deletion artifact.
            if ((lfn->sequenceNo & 0x40) && !isDeletedLfn) {
                lfnBuffer.clear();
            }

            // Decode UTF-16 filename fragments.
            std::wstring part;
            // Name1 (5 characters).
            for (int k = 0; k < 5; k++) {
                if (lfn->name1[k] != 0xFFFF && lfn->name1[k] != 0) {
                    part += static_cast<wchar_t>(lfn->name1[k]);
                }
            }
            
            // Name2 (6 characters).
            for (int k = 0; k < 6; k++) {
                if (lfn->name2[k] != 0xFFFF && lfn->name2[k] != 0) {
                    part += static_cast<wchar_t>(lfn->name2[k]);
                }
            }
            
            // Name3 (2 characters).
            for (int k = 0; k < 2; k++) {
                if (lfn->name3[k] != 0xFFFF && lfn->name3[k] != 0) {
                    part += static_cast<wchar_t>(lfn->name3[k]);
                }
            }
            
            // Prepend to buffer (LFN entries are stored in reverse order).
            lfnBuffer = part + lfnBuffer;
            continue;
        }

        // ====================================================================
        // Handle standard 8.3 directory entry
        // ====================================================================
        const FATDirEntry* entry = reinterpret_cast<const FATDirEntry*>(raw);
        bool isDir = (attr & 0x10) != 0;
        bool isVolumeID = (attr & 0x08) != 0;
        bool isDeleted = (marker == 0xE5);

        // Skip volume ID entries.
        if (isVolumeID) {
            lfnBuffer.clear();
            continue;
        }

        // Skip "." and ".." entries.
        if (entry->name[0] == '.') {
            lfnBuffer.clear();
            continue;
        }

        // Determine filename (use LFN if available, otherwise parse short name).
        std::wstring name;
        if (!lfnBuffer.empty()) {
            name = lfnBuffer;
        } else {
            name = ParseShortName(entry->name);
            // For deleted files, first character of short name is replaced with 0xE5.
            // Replace it with underscore for display.
            if (isDeleted && !name.empty()) {
                name[0] = L'_';
            }
        }
        
        // Clear LFN buffer after use.
        lfnBuffer.clear();
        // Extract cluster number from high and low words.
        uint32_t cluster = (static_cast<uint32_t>(entry->clusterHigh) << 16) | entry->clusterLow;

        // Append cluster ID to deleted files to ensure unique naming.
        if (isDeleted && cluster >= 2) {
            // Find insertion point before extension.
            size_t dotPos = name.rfind(L'.');
            std::wstring suffix = L"_" + std::to_wstring(cluster);
            if (dotPos != std::wstring::npos) {
                name.insert(dotPos, suffix);
            } else {
                name += suffix;
            }
        }

        // Build full virtual path.
        std::wstring fullPath = dirItem.path.empty() ?
            name : (dirItem.path + L"\\" + name);

        // ====================================================================
        // Handle directory traversal (only for active directories)
        // ====================================================================
        if (isDir) {
            if (cluster >= 2) {
                subDirs.push_back({cluster, fullPath});
            }
        }

        // ====================================================================
        // Report deleted files
        // ====================================================================
        if (!isDir && isDeleted) {
            bool matchFolder = true;
            bool matchName = true;

            // Apply folder filter.
            if (!context.folderFilter.empty()) {
                std::wstring lowerPath = fullPath;
                std::transform(lowerPath.begin(), lowerPath.end(), 
                             lowerPath.begin(), ::towlower);
                if (lowerPath.find(context.folderFilter) == std::wstring::npos) {
                    matchFolder = false;
                }
            }

            // Apply filename filter.
            if (!context.filenameFilter.empty()) {
                std::wstring lowerName = name;
                std::transform(lowerName.begin(), lowerName.end(), 
                             lowerName.begin(), ::towlower);
                if (lowerName.find(context.filenameFilter) == std::wstring::npos) {
                    matchName = false;
                }
            }

            if (matchFolder && matchName) {
                DeletedFileEntry result;
                result.name = name;
                result.path = L"<FAT32>\\" + fullPath;
                result.size = entry->fileSize;
                result.sizeFormatted = StringUtils::FormatFileSize(entry->fileSize);
                result.filesystemType = L"FAT32";
                result.isRecoverable = true;
                result.clusterSize = context.clusterSize;
                
                // For deleted files, assume contiguous allocation (FAT chain is cleared on deletion).
                if (cluster >= 2 && result.size > 0) {

                    // RecoveryEngine expects a global LCN (Linear Cluster Number relative to disk start),
                    // but 'cluster' here is an index into the FAT data area.
                    // We must convert FAT Cluster Index -> Physical Cluster Index.
                    // PhysicalCluster = (DataStartSector / SPC) + (FATCluster - 2)
                    
                    uint64_t absoluteClusterBase = context.dataStartSector / context.sectorsPerCluster;
                    uint64_t startLCN = absoluteClusterBase + (static_cast<uint64_t>(cluster) - 2);

                    result.clusters.push_back(startLCN);

                    // Calculate additional clusters needed for file size.
                    uint64_t clustersNeeded = (result.size + context.clusterSize - 1) / context.clusterSize;
                    for (uint64_t c = 1; c < clustersNeeded; c++) {
                        result.clusters.push_back(startLCN + c);
                    }
                }

                onFileFound(result);
            }
        }
    }
}

// Read cluster chain assuming contiguous allocation.
std::vector<uint8_t> FAT32Scanner::ReadClusterChain(
    DiskHandle& disk, 
    uint32_t startCluster, 
    const ScanContext& context,
    uint64_t limitBytes)
{
    if (startCluster < 2) return {};
    std::vector<uint8_t> buffer;
    uint32_t currentCluster = startCluster;
    uint64_t bytesRead = 0;
    // Safety limit for loops (~8MB at 4KB clusters).
    int maxClusters = Constants::FAT32::MAX_CHAIN_CLUSTERS;

    while (currentCluster >= 2 && currentCluster < 0x0FFFFFF7 && maxClusters > 0) {
        // Calculate sector address: Sector = DataStart + (Cluster - 2) * SectorsPerCluster.
        uint64_t sector = context.dataStartSector + 
                         (static_cast<uint64_t>(currentCluster) - 2) * context.sectorsPerCluster;
        auto data = disk.ReadSectors(sector, context.sectorsPerCluster, context.sectorSize);
        if (data.empty()) break;

        buffer.insert(buffer.end(), data.begin(), data.end());
        bytesRead += data.size();
        if (limitBytes > 0 && bytesRead >= limitBytes) break;

        // For active directories, assume contiguous allocation and continue.
        // For deleted files, FAT chain is cleared so this is the only option.
        currentCluster++;
        maxClusters--;
    }

    return buffer;
}

// Format file size into human-readable string.
std::wstring FAT32Scanner::FormatFileSize(uint64_t bytes) {
    return StringUtils::FormatFileSize(bytes);
}

} // namespace KVC