// ============================================================================
// ExFATScanner.cpp - ExFAT Filesystem Scanner with VolumeReader
// ============================================================================

#include "ExFATScanner.h"
#include "RecoveryCandidate.h"
#include "Constants.h"
#include "StringUtils.h"
#include "VolumeReader.h"
#include "VolumeGeometry.h"

#include <climits>
#include <algorithm>
#include <cwctype>
#include <vector>
#include <deque>
#include <optional>

namespace KVC {

ExFATScanner::ExFATScanner() = default;
ExFATScanner::~ExFATScanner() = default;

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

    if (std::memcmp(boot.oemName, "EXFAT   ", 8) != 0) {
        onProgress(L"Error: Not a valid exFAT drive (Signature missing)", 0.0f);
        return false;
    }

    ScanContext context;

    if (boot.bytesPerSectorShift < 9 || boot.bytesPerSectorShift > 16) {
        onProgress(L"Error: Invalid sector size in Boot Sector", 0.0f);
        return false;
    }

    context.sectorSize = 1ULL << boot.bytesPerSectorShift;
    context.sectorsPerCluster = 1ULL << boot.sectorsPerClusterShift;
    context.clusterHeapOffset = boot.clusterHeapOffset;
    context.rootDirCluster = boot.rootDirectoryCluster;
    context.fatOffset = boot.fatOffset;
    context.fatLength = boot.fatLength;

    context.volumeStartOffset = context.clusterHeapOffset * context.sectorSize;
    
    if (context.rootDirCluster < 2) {
        onProgress(L"Error: Invalid root directory cluster number", 0.0f);
        return false;
    }
    
    context.folderFilter = folderFilter;
    context.filenameFilter = filenameFilter;

    std::transform(context.folderFilter.begin(), context.folderFilter.end(), 
                  context.folderFilter.begin(), ::towlower);
    std::transform(context.filenameFilter.begin(), context.filenameFilter.end(), 
                  context.filenameFilter.begin(), ::towlower);

    // Build VolumeGeometry for exFAT
    VolumeGeometry geom;
    geom.sectorSize = context.sectorSize;
    geom.bytesPerCluster = context.sectorSize * context.sectorsPerCluster;
    geom.totalClusters = disk.GetDiskSize() / geom.bytesPerCluster;
    // For exFAT: LCN 0 = cluster heap offset (first data cluster)
    geom.volumeStartOffset = context.clusterHeapOffset * context.sectorSize;
    geom.fsType = FilesystemType::ExFAT;
    
    VolumeReader reader(disk, geom);

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

    while (!dirQueue.empty() && !shouldStop) {
        DirectoryWorkItem currentDir = dirQueue.front();
        dirQueue.pop_front();

        ProcessDirectory(reader, currentDir, dirQueue, [&](const DeletedFileEntry& file) {
            onFileFound(file);
            filesFound++;
        }, context, shouldStop);

        directoriesScanned++;

        wchar_t statusMsg[256];
        swprintf_s(statusMsg, L"exFAT: Dir %llu, Found %llu files", 
                    directoriesScanned, filesFound);
        float visualProgress = (directoriesScanned % 100) / 100.0f; 
        onProgress(statusMsg, visualProgress);
        
        if (directoriesScanned > config.exfatDirectoryEntriesLimit) {
            onProgress(L"Directory limit reached", 0.9f);
            break;
        }
    }

    if (shouldStop) {
        onProgress(L"Scan stopped by user", 1.0f);
    } else {
        wchar_t completeMsg[256];
        swprintf_s(completeMsg, L"exFAT scan complete: %llu files found", filesFound);
        onProgress(completeMsg, 1.0f);
    }

    return true;
}

ExFatBootSector ExFATScanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    ExFatBootSector boot = {};
    
    if (data.size() >= sizeof(ExFatBootSector)) {
        std::memcpy(&boot, data.data(), sizeof(ExFatBootSector));
    }
    
    return boot;
}

void ExFATScanner::ProcessDirectory(
    VolumeReader& reader,
    const DirectoryWorkItem& dirItem,
    std::deque<DirectoryWorkItem>& subDirs,
    DiskForensicsCore::FileFoundCallback onFileFound,
    const ScanContext& context,
    bool& shouldStop)
{
    // Convert exFAT cluster number to LCN
    // exFAT clusters start at 2, LCN 0 = cluster heap start
    if (dirItem.firstCluster < 2) {
        return;
    }
    
    // Read directory cluster chain
    auto dirData = ReadClusterChain(reader, dirItem.firstCluster, context, shouldStop, Constants::DIRECTORY_READ_LIMIT);
    if (dirData.empty()) {
        return;
    }

    size_t i = 0;
    while (i + 32 <= dirData.size()) {
        if (shouldStop) break;

        const uint8_t* p = dirData.data() + i;
        uint8_t type = p[0];
        
        if (type == 0x00) break;

        if ((type & 0x7F) == 0x05) {
            bool currentDeleted = !(type & 0x80);
            
            const auto* fileEntry = reinterpret_cast<const ExFatFileEntry*>(p);
            uint8_t secondaryCount = fileEntry->secondaryCount;
            bool currentIsDir = (fileEntry->fileAttributes & 0x10) != 0;

            if (i + 32 + (secondaryCount * 32) > dirData.size()) break;

            i += 32;
            const uint8_t* pStream = dirData.data() + i;
            
            if (((pStream[0] & 0x7F) == 0x40)) {
                const auto* streamEntry = reinterpret_cast<const ExFatStreamEntry*>(pStream);
                uint64_t currentSize = streamEntry->dataLength;
                uint32_t currentCluster = streamEntry->firstCluster;
                uint8_t nameLen = streamEntry->nameLength;

                std::wstring currentName;
                int remainingSecondaries = secondaryCount - 1;
                i += 32;

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

                std::wstring fullPath = dirItem.path;
                if (!fullPath.empty()) fullPath += L"\\";
                fullPath += currentName;

                if (currentIsDir) {
                    if (currentCluster >= 2) {
                        subDirs.push_back({ currentCluster, fullPath });
                    }
                }

                if (!currentIsDir && currentDeleted) {
                    if (currentSize > Constants::ExFAT::MAX_DELETED_FILE_SIZE) {
                        continue;
                    }

                    bool matchFolder = true;
                    bool matchName = true;

                    if (!context.folderFilter.empty()) {
                        std::wstring lowerPath = fullPath;
                        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                        if (lowerPath.find(context.folderFilter) == std::wstring::npos) matchFolder = false;
                    }
                    if (!context.filenameFilter.empty()) {
                        std::wstring lowerName = currentName;
                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                        if (lowerName.find(context.filenameFilter) == std::wstring::npos) matchName = false;
                    }

                    if (matchFolder && matchName) {
                        RecoveryCandidate candidate;
                        candidate.name = currentName;
                        candidate.path = L"<exFAT>\\" + fullPath;
                        candidate.fileSize = currentSize;
                        candidate.sizeFormatted = StringUtils::FormatFileSize(currentSize);
                        candidate.source = RecoverySource::ExFAT;
                        candidate.quality = RecoveryQuality::Full;
                        uint64_t clusterSize = context.sectorSize * context.sectorsPerCluster;
                        candidate.file = FragmentedFile(0, clusterSize);
                        candidate.volumeStartOffset = context.volumeStartOffset;

						if (currentCluster >= 2 && currentSize > 0) {
                            uint64_t clustersNeeded = (currentSize + clusterSize - 1) / clusterSize;
                            uint64_t maxClustersNeeded = Constants::ExFAT::MAX_SEQUENTIAL_SIZE / clusterSize;
                            uint64_t clustersToAdd = std::min(clustersNeeded, maxClustersNeeded);

                            uint64_t lcn = static_cast<uint64_t>(currentCluster) - 2;

							candidate.file.SetFileSize(currentSize);
							candidate.file.Fragments().AddRun(lcn, clustersToAdd);
							candidate.file.Fragments().SetTotalSize(currentSize);

                            if (clustersNeeded > clustersToAdd) {
                                candidate.quality = RecoveryQuality::Partial;
                                candidate.sizeFormatted = L"Partial (size limit)";
                            }
                        }
                        onFileFound(candidate);
                    }
                }
            }
        } else {
            i += 32;
        }
    }
}

std::vector<uint8_t> ExFATScanner::ReadClusterChain(
    VolumeReader& reader,
    uint32_t startCluster,
    const ScanContext& context,
    bool& shouldStop,
    uint64_t limitBytes)
{
	(void)context;
    if (startCluster < 2) return {};
    
    std::vector<uint8_t> buffer;
    
    // Follow FAT chain for active directories
    auto clusters = FollowFATChain(reader, context, startCluster, 1024);
    
    for (uint32_t cluster : clusters) {
        if (shouldStop) break;

        // Convert exFAT cluster to LCN
        // exFAT cluster 2 = LCN 0
        if (cluster < 2) break;
        uint64_t lcn = static_cast<uint64_t>(cluster) - 2;
        
        try {
            auto data = reader.ReadClusters(lcn, 1);
            if (data.empty()) break;

            size_t oldSize = buffer.size();
            buffer.insert(buffer.end(), data.begin(), data.end());

            // Check for end-of-directory marker
            bool foundEndMarker = false;
            for (size_t k = oldSize; k < buffer.size(); k += 32) {
                if (buffer[k] == 0x00) {
                    foundEndMarker = true;
                    break;
                }
            }
            
            if (foundEndMarker) break;
            if (limitBytes > 0 && buffer.size() >= limitBytes) break;
            
        } catch (const std::exception&) {
            break;
        }
    }

    return buffer;
}

std::optional<uint32_t> ExFATScanner::ReadFATEntry(
    VolumeReader& reader,
    const ScanContext& context,
    uint32_t cluster)
{
    // FAT entry is 4 bytes per cluster
    uint64_t fatEntryOffset = static_cast<uint64_t>(cluster) * 4;
    uint64_t sectorSize = context.sectorSize;
    
    uint64_t sectorInFat = fatEntryOffset / sectorSize;
    size_t offsetInSector = static_cast<size_t>(fatEntryOffset % sectorSize);
    
    uint64_t fatSector = context.fatOffset + sectorInFat;
    
    // Read FAT sector using raw DiskHandle (FAT is not in cluster heap)
    auto data = reader.GetDiskHandle().ReadSectors(fatSector, 1, sectorSize);
    if (data.empty() || offsetInSector + 4 > data.size()) {
        return std::nullopt;
    }
    
    uint32_t entry = static_cast<uint32_t>(data[offsetInSector]) |
                    (static_cast<uint32_t>(data[offsetInSector + 1]) << 8) |
                    (static_cast<uint32_t>(data[offsetInSector + 2]) << 16) |
                    (static_cast<uint32_t>(data[offsetInSector + 3]) << 24);
    
    if (entry >= 0xFFFFFFF8) {
        return std::nullopt;
    } else if (entry >= 2 && entry <= 0xFFFFFFF6) {
        return entry;
    } else {
        return std::nullopt;
    }
}

std::vector<uint32_t> ExFATScanner::FollowFATChain(
    VolumeReader& reader,
    const ScanContext& context,
    uint32_t startCluster,
    size_t maxClusters)
{
    std::vector<uint32_t> clusters;
    uint32_t currentCluster = startCluster;
    
    clusters.push_back(currentCluster);
    
    while (clusters.size() < maxClusters) {
        auto nextCluster = ReadFATEntry(reader, context, currentCluster);
        if (!nextCluster.has_value()) {
            break;
        }
        
        clusters.push_back(nextCluster.value());
        currentCluster = nextCluster.value();
    }
    
    return clusters;
}

std::wstring ExFATScanner::FormatFileSize(uint64_t bytes) {
    return StringUtils::FormatFileSize(bytes);
}

} // namespace KVC