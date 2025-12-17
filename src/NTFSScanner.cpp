// NTFSScanner.cpp
#include "NTFSScanner.h"
#include "RecoveryApplication.h"
#include <cstring>
#include <algorithm>

namespace KVC {

NTFSScanner::NTFSScanner() = default;
NTFSScanner::~NTFSScanner() = default;

// Read NTFS boot sector to obtain filesystem geometry.
NTFSBootSector NTFSScanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    
    NTFSBootSector boot = {};
    if (data.size() >= sizeof(NTFSBootSector)) {
        std::memcpy(&boot, data.data(), sizeof(NTFSBootSector));
    }
    
    return boot;
}

// Apply NTFS update sequence array (fixup) to repair sector boundaries.
bool NTFSScanner::ApplyFixups(std::vector<uint8_t>& recordData, uint16_t bytesPerSector) {
    if (recordData.size() < sizeof(MFTFileRecord)) return false;
    
    MFTFileRecord* header = reinterpret_cast<MFTFileRecord*>(recordData.data());
    uint16_t usaOffset = header->updateSequenceOffset;
    uint16_t usaCount = header->updateSequenceSize;
    
    if (static_cast<size_t>(usaOffset) + static_cast<size_t>(usaCount) * 2 > recordData.size()) return false;
    
    uint16_t* usaArray = reinterpret_cast<uint16_t*>(recordData.data() + usaOffset);
    uint16_t updateSequenceNumber = usaArray[0];
    
    // Replace sector end markers with actual data from USA
    for (uint16_t i = 1; i < usaCount; ++i) {
        uint32_t sectorEndOffset = (i * bytesPerSector) - 2;
        if (sectorEndOffset + 2 > recordData.size()) break;
        
        uint16_t* sectorFooter = reinterpret_cast<uint16_t*>(recordData.data() + sectorEndOffset);

        // This handles cases where fixups are already applied or not needed
        if (*sectorFooter == updateSequenceNumber) {
            *sectorFooter = usaArray[i];
        }
    }
    return true;
}

// Read a specific MFT record by its index number.
std::vector<uint8_t> NTFSScanner::ReadMFTRecord(DiskHandle& disk, const NTFSBootSector& boot, uint64_t recordNum) {
    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    uint64_t sectorSize = boot.bytesPerSector;
    
    // Calculate MFT record size (usually 1KB)
    uint64_t mftRecordSize = (boot.clustersPerMFTRecord >= 0) 
        ? boot.clustersPerMFTRecord * bytesPerCluster
        : (1ULL << (-boot.clustersPerMFTRecord));

    uint64_t mftOffset = boot.mftCluster * bytesPerCluster;
    uint64_t recordOffset = mftOffset + (recordNum * mftRecordSize);
    
    uint64_t startSector = recordOffset / sectorSize;
    uint64_t numSectors = (mftRecordSize + sectorSize - 1) / sectorSize;

    auto data = disk.ReadSectors(startSector, numSectors, sectorSize);
    if (data.empty()) return {};

    uint64_t offsetInSector = recordOffset % sectorSize;
    
    if (offsetInSector + mftRecordSize > data.size()) {
        mftRecordSize = data.size() - offsetInSector;
    }
    
    if (offsetInSector >= data.size()) return {};

	std::vector<uint8_t> result(
		data.begin() + static_cast<size_t>(offsetInSector), 
		data.begin() + static_cast<size_t>(offsetInSector + mftRecordSize)
	);
    
    // Some disks/pendrives may have fixups already applied or not need them
    ApplyFixups(result, boot.bytesPerSector);
    
    return result;
}

// Parse MFT record and extract deleted file information.
bool NTFSScanner::ParseMFTRecord(const std::vector<uint8_t>& data, uint64_t recordNum,
                                DiskForensicsCore::FileFoundCallback& callback,
                                DiskHandle& disk,
                                const NTFSBootSector& boot,
                                const std::wstring& folderFilter,
                                const std::wstring& filenameFilter) {
    if (data.size() < sizeof(MFTFileRecord)) return false;

    const MFTFileRecord* record = reinterpret_cast<const MFTFileRecord*>(data.data());
    
    // Verify FILE signature
    if (std::memcmp(record->signature, "FILE", 4) != 0) return false;

    const uint16_t FLAG_IN_USE = 0x0001;
    const uint16_t FLAG_IS_DIRECTORY = 0x0002;
    // Skip active files and directories
    if ((record->flags & FLAG_IN_USE) || (record->flags & FLAG_IS_DIRECTORY)) return false;

    DeletedFileEntry fileEntry = {};
    fileEntry.fileRecord = recordNum;
    fileEntry.filesystemType = L"NTFS";
    fileEntry.hasDeletedTime = false;
    fileEntry.size = 0;
    fileEntry.sizeFormatted = L"Unknown";
    fileEntry.isRecoverable = false;
    fileEntry.clusterSize = boot.bytesPerSector * boot.sectorsPerCluster;
    
    bool hasFileName = false;
    bool hasData = false;
    
    size_t offset = record->firstAttributeOffset;
    
    // Parse all attributes in the MFT record
    while (offset + sizeof(AttributeHeader) <= data.size()) {
        const AttributeHeader* attr = reinterpret_cast<const AttributeHeader*>(data.data() + offset);
        
        if (attr->type == 0xFFFFFFFF) break;     // End of attributes marker
        if (attr->length == 0 || offset > data.size() - attr->length) break;
        
        // Process $FILE_NAME attribute (0x30)
        if (attr->type == 0x30 && !hasFileName && attr->nonResident == 0) {
            const ResidentAttributeHeader* resAttr = 
                reinterpret_cast<const ResidentAttributeHeader*>(data.data() + offset);
            
            if (resAttr->valueOffset <= data.size() - sizeof(FileNameAttribute) &&
                offset <= data.size() - resAttr->valueOffset - sizeof(FileNameAttribute)) {
                
                const FileNameAttribute* fnAttr = 
                    reinterpret_cast<const FileNameAttribute*>(
                        data.data() + offset + resAttr->valueOffset);
                
                // Skip DOS 8.3 names (nameType == 0x02)
                if (fnAttr->nameType != 0x02) {
                    if (!hasFileName) {
                        size_t nameLen = std::min(static_cast<size_t>(fnAttr->nameLength), size_t(255));
                        size_t requiredSize = sizeof(FileNameAttribute) + (nameLen - 1) * sizeof(wchar_t);
                        
                        if (requiredSize <= data.size() && 
                            resAttr->valueOffset <= data.size() - requiredSize &&
                            offset <= data.size() - resAttr->valueOffset - requiredSize) {
                            
                            fileEntry.name.assign(fnAttr->name, nameLen);
                            hasFileName = true;
                        }
                    }
                }
            }
        }
        
        // Process $DATA attribute (0x80)
        if (attr->type == 0x80 && !hasData) {
            if (attr->nonResident == 0) {
                // Resident data: stored directly in MFT
                const ResidentAttributeHeader* resAttr = 
                    reinterpret_cast<const ResidentAttributeHeader*>(data.data() + offset);
                
                if (resAttr->valueLength <= data.size() &&
                    resAttr->valueOffset <= data.size() - resAttr->valueLength &&
                    offset <= data.size() - resAttr->valueOffset - resAttr->valueLength) {
                    
                    fileEntry.residentData.resize(resAttr->valueLength);
                    std::memcpy(fileEntry.residentData.data(), 
                               data.data() + offset + resAttr->valueOffset,
                               resAttr->valueLength);
                    
                    fileEntry.size = resAttr->valueLength;
                    fileEntry.sizeFormatted = FormatFileSize(resAttr->valueLength);
                    fileEntry.isRecoverable = true;
                    hasData = true;
                }
            } else {
                // Non-resident data: stored in clusters on disk
                const NonResidentAttributeHeader* nrAttr = 
                    reinterpret_cast<const NonResidentAttributeHeader*>(data.data() + offset);
                
                if (attr->length >= 64 && nrAttr->dataRunOffset <= data.size() &&
                    offset <= data.size() - nrAttr->dataRunOffset) {
                    
                    const uint8_t* runData = data.data() + offset + nrAttr->dataRunOffset;
                    size_t maxRunSize = data.size() - (offset + nrAttr->dataRunOffset);
                    
                    // Parse data runs to get cluster locations
                    fileEntry.clusterRanges = ParseDataRuns(runData, maxRunSize, boot.bytesPerSector * boot.sectorsPerCluster);
                    fileEntry.size = nrAttr->realSize;
                    fileEntry.sizeFormatted = FormatFileSize(nrAttr->realSize);
                    fileEntry.isRecoverable = !fileEntry.clusterRanges.empty();
                    hasData = true;
                }
            }
        }
        
        offset += attr->length;
    }
    
    if (hasFileName) {
        // Reconstruct full path by walking parent directories
        fileEntry.path = ReconstructPath(disk, boot, recordNum, fileEntry.name);
        
        if (!hasData) {
            fileEntry.size = 0;
            fileEntry.sizeFormatted = L"Unknown";
            fileEntry.isRecoverable = false;
        }
        
        // Apply folder filter
        if (!folderFilter.empty()) {
            std::wstring lowerPath = fileEntry.path;
            std::wstring lowerFilter = folderFilter;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::towlower);
            if (lowerPath.find(lowerFilter) == std::wstring::npos) return false;
        }
        
        // Apply filename filter
        if (!filenameFilter.empty()) {
            std::wstring lowerName = fileEntry.name;
            std::wstring lowerFilter = filenameFilter;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::towlower);
            if (lowerName.find(lowerFilter) == std::wstring::npos) return false;
        }
        
        callback(fileEntry);
        return true;
    }
    
    return false;
}

// Recursively reconstruct full path by following parent directory links.
std::wstring NTFSScanner::ReconstructPath(DiskHandle& disk, const NTFSBootSector& boot,
                                          uint64_t mftRecord, const std::wstring& filename) {
    // Check cache first
    auto it = m_pathCache.find(mftRecord);
    if (it != m_pathCache.end()) {
        return filename.empty() ? it->second : it->second + L"\\" + filename;
    }
    
    // Track visited records to prevent infinite loops
    static std::set<uint64_t> visitedRecords;
    
    // First call in chain - clear visited set
    if (visitedRecords.empty() || visitedRecords.size() > 100) {
        visitedRecords.clear();
    }
    
    // Detect circular reference
    if (visitedRecords.find(mftRecord) != visitedRecords.end()) {
        return L"<deleted>\\" + filename;
    }
    
    // Limit recursion depth
    if (visitedRecords.size() > 50) return L"<deleted>\\" + filename;
    
    visitedRecords.insert(mftRecord);
    
    // Root directory reached
    if (mftRecord == 5 || mftRecord == 0) {
        m_pathCache[mftRecord] = L"<deleted>";
        return filename.empty() ? L"<deleted>" : L"<deleted>\\" + filename;
    }
    
    auto data = ReadMFTRecord(disk, boot, mftRecord);
    if (data.size() < sizeof(MFTFileRecord)) return L"<deleted>\\" + filename;
    
    const MFTFileRecord* record = reinterpret_cast<const MFTFileRecord*>(data.data());
    if (std::memcmp(record->signature, "FILE", 4) != 0) return L"<deleted>\\" + filename;
    
    size_t offset = record->firstAttributeOffset;
    uint64_t parentMftRecord = 0;
    
    // Find parent directory reference in $FILE_NAME attributes
    while (offset + sizeof(AttributeHeader) <= data.size()) {
        const AttributeHeader* attr = reinterpret_cast<const AttributeHeader*>(data.data() + offset);
        if (attr->type == 0xFFFFFFFF) break;
        if (attr->length == 0 || offset > data.size() - attr->length) break;
        
        if (attr->type == 0x30 && attr->nonResident == 0) {
            const ResidentAttributeHeader* resAttr = 
                reinterpret_cast<const ResidentAttributeHeader*>(data.data() + offset);
            
            if (resAttr->valueOffset + sizeof(FileNameAttribute) <= data.size() - offset) {
                const FileNameAttribute* fnAttr = 
                    reinterpret_cast<const FileNameAttribute*>(
                        data.data() + offset + resAttr->valueOffset);
                
                uint64_t parent = fnAttr->parentDirectory & 0x0000FFFFFFFFFFFF;
                
                // Prefer Win32 name (0x01), fallback to POSIX (0x03) or DOS (0x02)
                if (fnAttr->nameType == 0x01) {
                    parentMftRecord = parent;
                    break;
                }
                else if (fnAttr->nameType == 0x03) {
                    parentMftRecord = parent;
                }
                else if (fnAttr->nameType == 0x02 && parentMftRecord == 0) {
                    parentMftRecord = parent;
                }
            }
        }
        offset += attr->length;
    }
    
    if (parentMftRecord == 0 || parentMftRecord == 5 || parentMftRecord == mftRecord) {
        m_pathCache[mftRecord] = L"<deleted>";
        visitedRecords.erase(mftRecord);
        return filename.empty() ? L"<deleted>" : L"<deleted>\\" + filename;
    }
    
    // Recursively resolve parent path
    std::wstring parentPath = ReconstructPath(disk, boot, parentMftRecord, L"");
    
    visitedRecords.erase(mftRecord);
    
    m_pathCache[mftRecord] = parentPath;
    return filename.empty() ? parentPath : parentPath + L"\\" + filename;
}

// Scan entire MFT for deleted file entries.
bool NTFSScanner::ScanVolume(
    DiskHandle& disk,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    bool& shouldStop,
    const ScanConfiguration& config)
{
    m_pathCache.clear();                        // Clear path reconstruction cache
    
    NTFSBootSector boot = ReadBootSector(disk);
    if (std::memcmp(boot.oemID, "NTFS    ", 8) != 0) return false;

    uint64_t maxRecords = config.ntfsMftSpareDriveLimit;
    uint64_t recordsScanned = 0;
    uint64_t filesFound = 0;
    
    const uint64_t RECORDS_PER_BATCH = 1024;    // Batch size for efficient I/O
    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    uint64_t mftRecordSize = (boot.clustersPerMFTRecord >= 0) 
        ? boot.clustersPerMFTRecord * bytesPerCluster
        : (1ULL << (-boot.clustersPerMFTRecord));

    uint64_t batchBufferSize = RECORDS_PER_BATCH * mftRecordSize;
    uint64_t sectorsPerBatch = (batchBufferSize + boot.bytesPerSector - 1) / boot.bytesPerSector;

    // Process MFT in batches for better performance
    for (uint64_t i = 0; i < maxRecords && !shouldStop; i += RECORDS_PER_BATCH) {
        if ((i % 100) == 0 && shouldStop) break;

        uint64_t mftOffset = boot.mftCluster * bytesPerCluster;
        uint64_t batchStartOffset = mftOffset + (i * mftRecordSize);
        uint64_t startSector = batchStartOffset / boot.bytesPerSector;
        
        auto batchData = disk.ReadSectors(startSector, sectorsPerBatch, boot.bytesPerSector);
        if (batchData.empty()) {
            if (i == 0) {
                onProgress(L"Failed to read MFT data from disk", 0.0f);
                return false;
            }
            recordsScanned += RECORDS_PER_BATCH;
            continue;
        }

        // Process each record in the batch
        for (uint64_t j = 0; j < RECORDS_PER_BATCH; ++j) {
            uint64_t currentRecordIdx = i + j;
            if (currentRecordIdx >= maxRecords || shouldStop) break;

            size_t offsetInBuffer = static_cast<size_t>(j * mftRecordSize);
            if (offsetInBuffer + mftRecordSize > batchData.size()) break;

			std::vector<uint8_t> recordData(
				batchData.begin() + static_cast<size_t>(offsetInBuffer), 
				batchData.begin() + static_cast<size_t>(offsetInBuffer + mftRecordSize)
			);

            ApplyFixups(recordData, boot.bytesPerSector);

            bool foundFile = ParseMFTRecord(recordData, currentRecordIdx, onFileFound, disk, boot,
                                          folderFilter, filenameFilter);
            if (foundFile) filesFound++;
            recordsScanned++;
        }

        // Update progress every 10240 records
        if ((i % 10240) == 0) {
            float progress = static_cast<float>(i) / maxRecords;
            wchar_t statusMsg[256];
            swprintf_s(statusMsg, L"Stage 1 (MFT): Scanned %llu records, found %llu deleted files", i, filesFound);
            onProgress(statusMsg, progress * 0.33f);
        }
    }

    wchar_t finalMsg[256];
    swprintf_s(finalMsg, L"MFT scan complete: %llu records scanned, %llu deleted files found", 
               recordsScanned, filesFound);
    onProgress(finalMsg, 0.33f);

    return true;
}

// Parse NTFS data runs to extract cluster locations.
std::vector<ClusterRange> NTFSScanner::ParseDataRuns(const uint8_t* runData, size_t maxSize, uint64_t bytesPerCluster) {
    std::vector<ClusterRange> ranges;
    if (maxSize == 0) return ranges;
    
    size_t offset = 0;
    int64_t currentLCN = 0;
    const uint64_t MAX_FRAGMENTS = 1000000;
    const uint64_t MAX_CLUSTERS_TOTAL = (100ULL * 1024 * 1024 * 1024) / (bytesPerCluster > 0 ? bytesPerCluster : 4096);
    
    uint64_t clustersAccumulated = 0;
    
    // Parse run-length encoded cluster locations
    while (offset < maxSize) {
        uint8_t header = runData[offset];
        if (header == 0) break;                 // End of runs marker
        
        uint8_t lengthBytes = header & 0x0F;
        uint8_t offsetBytes = (header >> 4) & 0x0F;
        
        if (lengthBytes == 0 || lengthBytes > 8 || offsetBytes > 8) break;
        
        offset++;
        
        if (offset + lengthBytes + offsetBytes > maxSize) {
            break;
        }
        
        // Read run length (little-endian)
        uint64_t runLength = 0;
        for (uint8_t i = 0; i < lengthBytes; i++) {
            runLength |= (static_cast<uint64_t>(runData[offset + i]) << (i * 8));
        }
        offset += lengthBytes;

        // Read LCN offset (signed, little-endian)
        int64_t lcnOffset = 0;
        for (uint8_t i = 0; i < offsetBytes; i++) {
            lcnOffset |= (static_cast<int64_t>(runData[offset + i]) << (i * 8));
        }
        
        clustersAccumulated += runLength;
        
        // Check limits to prevent excessive fragmentation
        if (ranges.size() > MAX_FRAGMENTS || clustersAccumulated > MAX_CLUSTERS_TOTAL) {
            break;
        }
        
        // Sign-extend if negative
        if (offsetBytes > 0 && (runData[offset + offsetBytes - 1] & 0x80)) {
            for (uint8_t i = offsetBytes; i < 8; i++) {
                lcnOffset |= (static_cast<int64_t>(0xFF) << (i * 8));
            }
        }
        
        offset += offsetBytes;
        currentLCN += lcnOffset;
        
        if (offsetBytes > 0 && currentLCN > 0) {
            ClusterRange range;
            range.start = static_cast<uint64_t>(currentLCN);
            range.count = runLength;
            ranges.push_back(range);
        }
    }

    // Merge adjacent ranges for efficiency
    if (ranges.empty()) return ranges;
    
    std::vector<ClusterRange> merged;
    merged.reserve(ranges.size());
    
    ClusterRange current = ranges[0];
    
    for (size_t i = 1; i < ranges.size(); i++) {
        if (current.start + current.count == ranges[i].start) {
            current.count += ranges[i].count;   // Merge adjacent runs
        } else {
            merged.push_back(current);
            current = ranges[i];
        }
    }
    merged.push_back(current);
    
    return merged;
}

} // namespace KVC