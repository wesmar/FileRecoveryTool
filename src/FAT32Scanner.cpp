// ============================================================================
// FAT32Scanner.cpp - FAT32 Filesystem Scanner with VolumeReader
// ============================================================================

#include "FAT32Scanner.h"
#include "RecoveryCandidate.h"
#include "Constants.h"
#include "StringUtils.h"
#include "VolumeReader.h"
#include "VolumeGeometry.h"

#include <climits>
#include <deque>
#include <algorithm>
#include <cwctype>
#include <cstring>
#include <string>

namespace KVC {

FAT32Scanner::FAT32Scanner() = default;
FAT32Scanner::~FAT32Scanner() = default;

FAT32BootSector FAT32Scanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    FAT32BootSector boot = {};
    if (data.size() >= sizeof(FAT32BootSector)) {
        std::memcpy(&boot, data.data(), sizeof(FAT32BootSector));
    }
    
    return boot;
}

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
    
    if (boot.signature != 0xAA55) {
        return false;
    }

    if (boot.rootEntryCount != 0 || boot.fatSize16 != 0) {
        return false;
    }

    if (boot.bytesPerSector == 0 || boot.sectorsPerCluster == 0) {
        return false;
    }

    ScanContext context;
    context.sectorSize = boot.bytesPerSector;
    context.sectorsPerCluster = boot.sectorsPerCluster;
    context.rootCluster = boot.rootCluster;
    context.clusterSize = context.sectorSize * context.sectorsPerCluster;
    context.dataStartSector = boot.reservedSectors +
                             (static_cast<uint64_t>(boot.numberOfFATs) * boot.fatSize32);
    context.folderFilter = folderFilter;
    context.filenameFilter = filenameFilter;

    context.volumeStartOffset = context.dataStartSector * context.sectorSize;
    
    std::transform(context.folderFilter.begin(), context.folderFilter.end(), 
                  context.folderFilter.begin(), ::towlower);
    std::transform(context.filenameFilter.begin(), context.filenameFilter.end(), 
                  context.filenameFilter.begin(), ::towlower);

    // Build VolumeGeometry for FAT32
    VolumeGeometry geom;
    geom.sectorSize = context.sectorSize;
    geom.bytesPerCluster = context.clusterSize;
    geom.totalClusters = disk.GetDiskSize() / geom.bytesPerCluster;
    // For FAT32: LCN 0 = first data cluster (FAT cluster 2)
    geom.volumeStartOffset = context.dataStartSector * context.sectorSize;
    geom.fsType = FilesystemType::FAT32;
    
    VolumeReader reader(disk, geom);

    std::deque<DirectoryWorkItem> dirQueue;
    dirQueue.push_back({ context.rootCluster, L"" });

    uint64_t directoriesScanned = 0;
    uint64_t filesFound = 0;

    onProgress(L"Starting FAT32 structure scan...", 0.0f);

    while (!dirQueue.empty() && !shouldStop) {
        DirectoryWorkItem current = dirQueue.front();
        dirQueue.pop_front();

        ProcessDirectory(reader, current, dirQueue, [&](const DeletedFileEntry& file) {
            onFileFound(file);
            filesFound++;
        }, context);
        directoriesScanned++;

        if ((directoriesScanned % 10) == 0) {
            wchar_t statusMsg[256];
            swprintf_s(statusMsg, L"FAT32 Scan: %llu directories, %llu deleted files found", 
                      directoriesScanned, filesFound);
            onProgress(statusMsg, 0.5f);
        }
        
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

std::wstring FAT32Scanner::ParseShortName(const uint8_t* name) {
    if (!name) return L"";
    
    std::string sName;
    
    for (int i = 0; i < 8; ++i) {
        if (name[i] != ' ' && name[i] != 0) {
            sName += static_cast<char>(name[i]);
        }
    }
    
    if (name[8] != ' ' && name[8] != 0) {
        sName += ".";
        for (int i = 8; i < 11; ++i) {
            if (name[i] != ' ' && name[i] != 0) {
                sName += static_cast<char>(name[i]);
            }
        }
    }
    
    return std::wstring(sName.begin(), sName.end());
}

void FAT32Scanner::ProcessDirectory(
    VolumeReader& reader,
    const DirectoryWorkItem& dirItem,
    std::deque<DirectoryWorkItem>& subDirs,
    DiskForensicsCore::FileFoundCallback onFileFound,
    const ScanContext& context)
{
    auto data = ReadClusterChain(reader, dirItem.firstCluster, context, Constants::DIRECTORY_READ_LIMIT);
    if (data.empty()) return;

    std::wstring lfnBuffer;
    
    for (size_t i = 0; i + 32 <= data.size(); i += 32) {
        const uint8_t* raw = data.data() + i;
        uint8_t marker = raw[0];
        uint8_t attr = raw[11];

        if (marker == 0x00) break;
        
        // ====================================================================
        // Handle Long File Name (LFN) entries
        // ====================================================================
        if (attr == 0x0F) {
            const FATLFNEntry* lfn = reinterpret_cast<const FATLFNEntry*>(raw);

            bool isDeletedLfn = (marker == 0xE5);
            
            if ((lfn->sequenceNo & 0x40) && !isDeletedLfn) {
                lfnBuffer.clear();
            }

            std::wstring part;
            
            for (int k = 0; k < 5; k++) {
                if (lfn->name1[k] != 0xFFFF && lfn->name1[k] != 0) {
                    part += static_cast<wchar_t>(lfn->name1[k]);
                }
            }
            
            for (int k = 0; k < 6; k++) {
                if (lfn->name2[k] != 0xFFFF && lfn->name2[k] != 0) {
                    part += static_cast<wchar_t>(lfn->name2[k]);
                }
            }
            
            for (int k = 0; k < 2; k++) {
                if (lfn->name3[k] != 0xFFFF && lfn->name3[k] != 0) {
                    part += static_cast<wchar_t>(lfn->name3[k]);
                }
            }
            
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

        if (isVolumeID) {
            lfnBuffer.clear();
            continue;
        }

        if (entry->name[0] == '.') {
            lfnBuffer.clear();
            continue;
        }

        std::wstring name;
        if (!lfnBuffer.empty()) {
            name = lfnBuffer;
        } else {
            name = ParseShortName(entry->name);
            if (isDeleted && !name.empty()) {
                name[0] = L'_';
            }
        }
        
        lfnBuffer.clear();
        
        uint32_t cluster = (static_cast<uint32_t>(entry->clusterHigh) << 16) | entry->clusterLow;

        if (isDeleted && cluster >= 2) {
            size_t dotPos = name.rfind(L'.');
            std::wstring suffix = L"_" + std::to_wstring(cluster);
            if (dotPos != std::wstring::npos) {
                name.insert(dotPos, suffix);
            } else {
                name += suffix;
            }
        }

        std::wstring fullPath = dirItem.path.empty() ?
            name : (dirItem.path + L"\\" + name);

        // ====================================================================
        // Handle directory traversal (only active directories)
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

            if (!context.folderFilter.empty()) {
                std::wstring lowerPath = fullPath;
                std::transform(lowerPath.begin(), lowerPath.end(), 
                             lowerPath.begin(), ::towlower);
                if (lowerPath.find(context.folderFilter) == std::wstring::npos) {
                    matchFolder = false;
                }
            }

            if (!context.filenameFilter.empty()) {
                std::wstring lowerName = name;
                std::transform(lowerName.begin(), lowerName.end(), 
                             lowerName.begin(), ::towlower);
                if (lowerName.find(context.filenameFilter) == std::wstring::npos) {
                    matchName = false;
                }
            }

            if (matchFolder && matchName) {
                RecoveryCandidate candidate;
                candidate.name = name;
                candidate.path = L"<FAT32>\\" + fullPath;
                candidate.fileSize = entry->fileSize;
                candidate.sizeFormatted = StringUtils::FormatFileSize(entry->fileSize);
                candidate.source = RecoverySource::FAT32;
                candidate.quality = RecoveryQuality::Full;
                candidate.file = FragmentedFile(0, context.clusterSize);
                candidate.volumeStartOffset = context.volumeStartOffset;

                if (cluster >= 2 && candidate.fileSize > 0) {
                    uint64_t lcn = static_cast<uint64_t>(cluster) - 2;
                    uint64_t clustersNeeded = (candidate.fileSize + context.clusterSize - 1) / context.clusterSize;

					candidate.file.SetFileSize(candidate.fileSize);
					candidate.file.Fragments().AddRun(lcn, clustersNeeded);
					candidate.file.Fragments().SetTotalSize(candidate.fileSize);
                }

                onFileFound(candidate);
            }
        }
    }
}

std::vector<uint8_t> FAT32Scanner::ReadClusterChain(
    VolumeReader& reader,
    uint32_t startCluster,
    const ScanContext& context,
    uint64_t limitBytes)
{
	(void)context;
    if (startCluster < 2) return {};
    
    std::vector<uint8_t> buffer;
    uint32_t currentCluster = startCluster;
    uint64_t bytesRead = 0;
    int maxClusters = Constants::FAT32::MAX_CHAIN_CLUSTERS;

    while (currentCluster >= 2 && currentCluster < 0x0FFFFFF7 && maxClusters > 0) {
        // Convert FAT cluster to LCN
        // FAT cluster 2 = LCN 0 (first data cluster)
        if (currentCluster < 2) break;
        uint64_t lcn = static_cast<uint64_t>(currentCluster) - 2;
        
        try {
            auto data = reader.ReadClusters(lcn, 1);
            if (data.empty()) break;

            buffer.insert(buffer.end(), data.begin(), data.end());
            bytesRead += data.size();
            if (limitBytes > 0 && bytesRead >= limitBytes) break;

            // For active directories, assume contiguous
            // For deleted files, FAT chain is cleared
            currentCluster++;
            maxClusters--;
            
        } catch (const std::exception&) {
            break;
        }
    }

    return buffer;
}

std::wstring FAT32Scanner::FormatFileSize(uint64_t bytes) {
    return StringUtils::FormatFileSize(bytes);
}

} // namespace KVC