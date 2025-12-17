// ExFATScanner.cpp
#include "ExFATScanner.h"
#include <algorithm>
#include <cwctype>
#include <vector>
#include <optional>

namespace KVC {

ExFATScanner::ExFATScanner() = default;
ExFATScanner::~ExFATScanner() = default;

// Main exFAT volume scanning routine for deleted file discovery.
bool ExFATScanner::ScanVolume(
    DiskHandle& disk,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    bool& shouldStop,
    const ScanConfiguration& config)
{
    onProgress(L"Reading exFAT Boot Sector...", 0.0f);

    ExFatBootSector boot = ReadBootSector(disk);

    // Validate exFAT signature in boot sector.
    if (std::memcmp(boot.oemName, "EXFAT   ", 8) != 0) {
        onProgress(L"Error: Not a valid exFAT drive (Signature missing)", 0.0f);
        return false;
    }

    ScanContext context;
    // Validate sector size parameters.
    if (boot.bytesPerSectorShift < 9 || boot.bytesPerSectorShift > 16) {
        onProgress(L"Error: Invalid sector size in Boot Sector", 0.0f);
        return false;
    }

    // Calculate disk geometry parameters.
    context.sectorSize = 1ULL << boot.bytesPerSectorShift;
    context.sectorsPerCluster = 1ULL << boot.sectorsPerClusterShift;
    context.clusterHeapOffset = boot.clusterHeapOffset;
    context.rootDirCluster = boot.rootDirectoryCluster;
    context.fatOffset = boot.fatOffset;
    context.fatLength = boot.fatLength;
    
    // Validate root directory cluster number.
    if (context.rootDirCluster < 2) {
        onProgress(L"Error: Invalid root directory cluster number", 0.0f);
        return false;
    }
    
    context.folderFilter = folderFilter;
    context.filenameFilter = filenameFilter;

    // Convert filters to lowercase for case-insensitive matching.
    std::transform(context.folderFilter.begin(), context.folderFilter.end(), 
                  context.folderFilter.begin(), ::towlower);
    std::transform(context.filenameFilter.begin(), context.filenameFilter.end(), 
                  context.filenameFilter.begin(), ::towlower);

    // Directory queue for breadth-first traversal.
    std::deque<DirectoryWorkItem> dirQueue;
    dirQueue.push_back({ context.rootDirCluster, L"" });

    uint64_t directoriesScanned = 0;
    uint64_t filesFound = 0;

    wchar_t startMsg[512];
    swprintf_s(startMsg, L"exFAT: Root=%u, FAT at sector %u (%.2f MB). Scanning...", 
              context.rootDirCluster,
              boot.fatOffset,
              (boot.fatOffset * context.sectorSize) / (1024.0 * 1024.0));
    onProgress(startMsg, 0.0f);

    // Process directory queue until empty or stopped.
    while (!dirQueue.empty() && !shouldStop) {
        DirectoryWorkItem currentDir = dirQueue.front();
        dirQueue.pop_front();

        ProcessDirectory(disk, currentDir, dirQueue, [&](const DeletedFileEntry& file) {
            onFileFound(file);
            filesFound++;
        }, context, shouldStop);

        directoriesScanned++;

        // Update progress status periodically.
        wchar_t statusMsg[256];
        swprintf_s(statusMsg, L"exFAT: Dir %llu, Found %llu files", 
                    directoriesScanned, filesFound);
        float visualProgress = (directoriesScanned % 100) / 100.0f; 
        onProgress(statusMsg, visualProgress);
        
        // Safety limit to prevent infinite loops.
        if (directoriesScanned > config.exfatDirectoryEntriesLimit) {
            onProgress(L"Directory limit reached", 0.9f);
            break;
        }
    }

    // Final status reporting.
    if (shouldStop) {
        onProgress(L"Scan stopped by user", 1.0f);
    } else {
        wchar_t completeMsg[256];
        swprintf_s(completeMsg, L"exFAT scan complete: %llu files found", filesFound);
        onProgress(completeMsg, 1.0f);
    }

    return true;
}

// Read and parse the exFAT boot sector.
ExFatBootSector ExFATScanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    ExFatBootSector boot = {};
    
    if (data.size() >= sizeof(ExFatBootSector)) {
        std::memcpy(&boot, data.data(), sizeof(ExFatBootSector));
    }
    
    return boot;
}

// Process a single directory and extract deleted file entries.
void ExFATScanner::ProcessDirectory(
    DiskHandle& disk, 
    const DirectoryWorkItem& dirItem,
    std::deque<DirectoryWorkItem>& subDirs,
    DiskForensicsCore::FileFoundCallback onFileFound,
    const ScanContext& context,
    bool& shouldStop)
{
    // Read directory cluster chain with size limit.
    auto dirData = ReadClusterChain(disk, dirItem.firstCluster, context, shouldStop, 2 * 1024 * 1024);
    if (dirData.empty()) {
        return;
    }

    size_t i = 0;
    // Process each 32-byte directory entry.
    while (i + 32 <= dirData.size()) {
        if (shouldStop) break;

        const uint8_t* p = dirData.data() + i;
        uint8_t type = p[0];
        
        // End of directory marker.
        if (type == 0x00) break;

        // File directory entry (type 0x85 active, 0x05 deleted).
        if ((type & 0x7F) == 0x05) {
            bool currentDeleted = !(type & 0x80);
            
            const auto* fileEntry = reinterpret_cast<const ExFatFileEntry*>(p);
            uint8_t secondaryCount = fileEntry->secondaryCount;
            bool currentIsDir = (fileEntry->fileAttributes & 0x10) != 0;

            // Validate secondary entries are within bounds.
            if (i + 32 + (secondaryCount * 32) > dirData.size()) break;

            i += 32;
            const uint8_t* pStream = dirData.data() + i;
            
            // Stream extension entry (type 0xC0 active, 0x40 deleted).
            if (((pStream[0] & 0x7F) == 0x40)) {
                const auto* streamEntry = reinterpret_cast<const ExFatStreamEntry*>(pStream);
                uint64_t currentSize = streamEntry->dataLength;
                uint32_t currentCluster = streamEntry->firstCluster;
                uint8_t nameLen = streamEntry->nameLength;

                std::wstring currentName;
                int remainingSecondaries = secondaryCount - 1;
                i += 32;

                // Parse file name entries (type 0xC1 active, 0x41 deleted).
                while (remainingSecondaries > 0 && i < dirData.size()) {
                    const auto* nameEntry = reinterpret_cast<const ExFatNameEntry*>(dirData.data() + i);
                    if ((nameEntry->entryType & 0x7F) == 0x41) {
                        for (int k = 0; k < 15 && currentName.length() < nameLen; k++) {
                            currentName += nameEntry->fileName[k];
                        }
                    }
                    i += 32;
                    remainingSecondaries--;
                }

                // Build full virtual path.
                std::wstring fullPath = dirItem.path;
                if (!fullPath.empty()) fullPath += L"\\";
                fullPath += currentName;

                // Queue subdirectories for processing.
                if (currentIsDir) {
                    if (currentCluster >= 2) {
                        subDirs.push_back({ currentCluster, fullPath });
                    }
                }

                // Process deleted files only.
                if (!currentIsDir && currentDeleted) {
                    // Sanity check for file size.
                    const uint64_t MAX_DELETED_FILE_SIZE = 10ULL * 1024 * 1024 * 1024; // 10GB
                    if (currentSize > MAX_DELETED_FILE_SIZE) {
                        continue;
                    }

                    bool matchFolder = true;
                    bool matchName = true;

                    // Apply folder filter if specified.
                    if (!context.folderFilter.empty()) {
                        std::wstring lowerPath = fullPath;
                        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                        if (lowerPath.find(context.folderFilter) == std::wstring::npos) matchFolder = false;
                    }
                    // Apply filename filter if specified.
                    if (!context.filenameFilter.empty()) {
                        std::wstring lowerName = currentName;
                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                        if (lowerName.find(context.filenameFilter) == std::wstring::npos) matchName = false;
                    }

                    if (matchFolder && matchName) {
                        DeletedFileEntry entry;
                        entry.name = currentName;
                        entry.path = L"<exFAT>\\" + fullPath;
                        entry.size = currentSize;
                        entry.sizeFormatted = FormatFileSize(currentSize);
                        entry.filesystemType = L"exFAT";
                        entry.isRecoverable = true;
                        entry.clusterSize = context.sectorSize * context.sectorsPerCluster;
                        
                        // Build cluster list for recovery.
                        if (currentCluster >= 2 && currentSize > 0) {
                            uint64_t clusterSize = context.sectorSize * context.sectorsPerCluster;
                            uint64_t clustersNeeded = (currentSize + clusterSize - 1) / clusterSize;
                            
                            uint64_t heapOffsetInClusters = context.clusterHeapOffset / context.sectorsPerCluster;
                            
                            // CRITICAL: For DELETED files, FAT entries are zeroed out!
                            // We MUST assume contiguous allocation (sequential clusters)
                            // DO NOT read FAT for deleted files - it will only give us the first cluster
                            const uint64_t MAX_DELETED_SEQUENTIAL_SIZE = 10ULL * 1024 * 1024 * 1024; // 10 GB
                            uint64_t maxClustersNeeded = MAX_DELETED_SEQUENTIAL_SIZE / entry.clusterSize;
                            uint64_t clustersToAdd = std::min(clustersNeeded, maxClustersNeeded);
                            for(uint64_t clusterIdx = 0; clusterIdx < clustersToAdd; clusterIdx++) {
                                uint32_t nextCluster = currentCluster + static_cast<uint32_t>(clusterIdx);
                                uint64_t absoluteCluster = heapOffsetInClusters + (static_cast<uint64_t>(nextCluster) - 2);
                                entry.clusters.push_back(absoluteCluster);
                            }
                            // Mark as partial if size limit exceeded.
                            if (clustersNeeded > clustersToAdd) {
                                entry.isRecoverable = false;
                                entry.sizeFormatted = L"Partial (size limit)";
                            }
                        }
                        onFileFound(entry);
                    }
                }
            }
        } else {
            i += 32;
        }
    }
}

// Read cluster chain following FAT entries for active directories.
std::vector<uint8_t> ExFATScanner::ReadClusterChain(
    DiskHandle& disk, 
    uint32_t startCluster, 
    const ScanContext& context,
    bool& shouldStop,
    uint64_t limitBytes)
{
    if (startCluster < 2) return {};
    
    std::vector<uint8_t> buffer;
    
    // Follow FAT chain to find all clusters in directory.
    auto clusters = FollowFATChain(disk, context, startCluster, 1024);
    
    for (uint32_t cluster : clusters) {
        if (shouldStop) break;

        // Calculate physical sector address.
        uint64_t sector = context.clusterHeapOffset + 
                         (static_cast<uint64_t>(cluster) - 2) * context.sectorsPerCluster;
        
        auto data = disk.ReadSectors(sector, context.sectorsPerCluster, context.sectorSize);
        if (data.empty()) break;

        size_t oldSize = buffer.size();
        buffer.insert(buffer.end(), data.begin(), data.end());

        // Check for end-of-directory marker (0x00).
        bool foundEndMarker = false;
        for (size_t k = oldSize; k < buffer.size(); k += 32) {
            if (buffer[k] == 0x00) {
                foundEndMarker = true;
                break;
            }
        }
        
        if (foundEndMarker) break;
        if (limitBytes > 0 && buffer.size() >= limitBytes) break;
    }

    return buffer;
}

// Read a single FAT entry for a given cluster.
std::optional<uint32_t> ExFATScanner::ReadFATEntry(
    DiskHandle& disk,
    const ScanContext& context,
    uint32_t cluster)
{
    // Calculate FAT entry offset (4 bytes per entry).
    uint64_t fatEntryOffset = static_cast<uint64_t>(cluster) * 4;
    uint64_t sectorSize = context.sectorSize;
    
    uint64_t sectorInFat = fatEntryOffset / sectorSize;
    size_t offsetInSector = static_cast<size_t>(fatEntryOffset % sectorSize);
    
    uint64_t fatSector = context.fatOffset + sectorInFat;
    
    auto data = disk.ReadSectors(fatSector, 1, sectorSize);
    if (data.empty() || offsetInSector + 4 > data.size()) {
        return std::nullopt;
    }
    
    // Parse 32-bit little-endian FAT entry.
    uint32_t entry = static_cast<uint32_t>(data[offsetInSector]) |
                    (static_cast<uint32_t>(data[offsetInSector + 1]) << 8) |
                    (static_cast<uint32_t>(data[offsetInSector + 2]) << 16) |
                    (static_cast<uint32_t>(data[offsetInSector + 3]) << 24);
    
    // Check for end-of-chain marker.
    if (entry >= 0xFFFFFFF8) {
        return std::nullopt;
    } else if (entry >= 2 && entry <= 0xFFFFFFF6) {
        return entry;
    } else {
        return std::nullopt;
    }
}

// Follow FAT chain from start cluster to build cluster list.
std::vector<uint32_t> ExFATScanner::FollowFATChain(
    DiskHandle& disk,
    const ScanContext& context,
    uint32_t startCluster,
    size_t maxClusters)
{
    std::vector<uint32_t> clusters;
    uint32_t currentCluster = startCluster;
    
    clusters.push_back(currentCluster);
    
    // Follow chain until end marker or limit reached.
    while (clusters.size() < maxClusters) {
        auto nextCluster = ReadFATEntry(disk, context, currentCluster);
        if (!nextCluster.has_value()) {
            break;
        }
        
        clusters.push_back(nextCluster.value());
        currentCluster = nextCluster.value();
    }
    
    return clusters;
}

// Format file size into human-readable string.
std::wstring ExFATScanner::FormatFileSize(uint64_t bytes) {
    wchar_t buffer[64];
    if (bytes >= 1000000000) {
        swprintf_s(buffer, L"%.2f GB", bytes / 1000000000.0);
    } else if (bytes >= 1000000) {
        swprintf_s(buffer, L"%.2f MB", bytes / 1000000.0);
    } else if (bytes >= 1000) {
        swprintf_s(buffer, L"%.2f KB", bytes / 1000.0);
    } else {
        swprintf_s(buffer, L"%llu bytes", bytes);
    }
    return buffer;
}

} // namespace KVC