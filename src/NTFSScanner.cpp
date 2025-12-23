// ============================================================================
// NTFSScanner.cpp - NTFS Filesystem Scanner with VolumeReader
// ============================================================================

#include "NTFSScanner.h"
#include "RecoveryCandidate.h"
#include "Constants.h"
#include "StringUtils.h"

#include <climits>
#include <algorithm>
#include <cwctype>
#include <vector>
#include <set>

namespace KVC {

// ============================================================================
// NTFSDataRunParser Implementation
// ============================================================================

uint64_t NTFSDataRunParser::ReadVarInt(const uint8_t* data, uint8_t numBytes) {
    if (numBytes == 0 || numBytes > 8) return 0;
    
    uint64_t value = 0;
    for (uint8_t i = 0; i < numBytes; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * 8);
    }
    return value;
}

int64_t NTFSDataRunParser::ReadSignedVarInt(const uint8_t* data, uint8_t numBytes) {
    if (numBytes == 0 || numBytes > 8) return 0;
    
    int64_t value = 0;
    for (uint8_t i = 0; i < numBytes; ++i) {
        value |= static_cast<int64_t>(data[i]) << (i * 8);
    }
    
    // Sign extend
    if (numBytes > 0 && (data[numBytes - 1] & 0x80)) {
        for (uint8_t i = numBytes; i < 8; ++i) {
            value |= static_cast<int64_t>(0xFF) << (i * 8);
        }
    }
    
    return value;
}

NTFSDataRunParser::ParseResult NTFSDataRunParser::Parse(
    const uint8_t* runData,
    size_t maxSize,
    uint64_t bytesPerCluster,
    uint64_t maxClusterNumber)
{
    ParseResult result;
    result.valid = false;
    
    if (runData == nullptr || maxSize == 0 || bytesPerCluster == 0) {
        result.errorMessage = "Invalid parameters";
        return result;
    }
    
    size_t offset = 0;
    int64_t currentLCN = 0;
    uint64_t currentFileOffset = 0;
    
    constexpr size_t MAX_FRAGMENTS = 1000000;
    
    while (offset < maxSize && result.runs.size() < MAX_FRAGMENTS) {
        uint8_t header = runData[offset];
        
        if (header == 0) {
            result.valid = true;
            break;
        }
        
        uint8_t lengthBytes = header & 0x0F;
        uint8_t offsetBytes = (header >> 4) & 0x0F;
        
        if (lengthBytes == 0 || lengthBytes > 8 || offsetBytes > 8) {
            result.errorMessage = "Invalid data run header at offset " + std::to_string(offset);
            return result;
        }
        
        offset++;
        
        if (offset + lengthBytes + offsetBytes > maxSize) {
            result.errorMessage = "Data run extends beyond buffer";
            return result;
        }
        
        uint64_t runLength = ReadVarInt(runData + offset, lengthBytes);
        offset += lengthBytes;
        
        if (runLength == 0) {
            result.errorMessage = "Zero-length run at offset " + std::to_string(offset - lengthBytes);
            return result;
        }
        
        if (runLength > 0x0FFFFFFFFFFFF) {
            result.errorMessage = "Run length exceeds maximum value";
            return result;
        }
        
        int64_t lcnOffset = 0;
        if (offsetBytes > 0) {
            lcnOffset = ReadSignedVarInt(runData + offset, offsetBytes);
            offset += offsetBytes;
        }
        
        currentLCN += lcnOffset;
        
        // Skip sparse runs (offsetBytes == 0)
        if (offsetBytes > 0) {
            if (currentLCN < 0) {
                result.errorMessage = "Negative LCN calculated: " + std::to_string(currentLCN);
                return result;
            }
            
            if (maxClusterNumber > 0) {
                uint64_t runEndCluster = static_cast<uint64_t>(currentLCN) + runLength;
                if (runEndCluster > maxClusterNumber) {
                    result.errorMessage = "Run extends beyond disk: cluster " + 
                        std::to_string(runEndCluster) + " > max " + std::to_string(maxClusterNumber);
                    return result;
                }
            }
            
            ClusterRun run;
            run.startCluster = static_cast<uint64_t>(currentLCN);
            run.clusterCount = runLength;
            run.fileOffset = currentFileOffset;
            
            result.runs.push_back(run);
            result.totalClusters += runLength;
        }
        
        currentFileOffset += runLength * bytesPerCluster;
    }
    
    if (result.runs.size() >= MAX_FRAGMENTS) {
        result.errorMessage = "Maximum fragment count exceeded";
        result.valid = false;
        return result;
    }
    
    result.totalBytes = result.totalClusters * bytesPerCluster;
    result.valid = true;
    
    return result;
}

bool NTFSDataRunParser::ValidateRuns(
    const std::vector<ClusterRun>& runs,
    uint64_t maxClusterNumber,
    std::string* errorOut)
{
    for (size_t i = 0; i < runs.size(); ++i) {
        const auto& run = runs[i];
        
        if (run.clusterCount == 0) {
            if (errorOut) *errorOut = "Zero-length run at index " + std::to_string(i);
            return false;
        }
        
        if (run.startCluster >= maxClusterNumber) {
            if (errorOut) *errorOut = "Start cluster out of bounds: " + std::to_string(run.startCluster);
            return false;
        }
        
        uint64_t endCluster = run.startCluster + run.clusterCount;
        if (endCluster > maxClusterNumber) {
            if (errorOut) *errorOut = "Run extends beyond disk";
            return false;
        }
        
        if (i > 0) {
            const auto& prevRun = runs[i - 1];
            if (run.fileOffset < prevRun.fileOffset) {
                if (errorOut) *errorOut = "Non-monotonic file offsets detected";
                return false;
            }
        }
    }
    
    return true;
}

// ============================================================================
// NTFSScanner Implementation
// ============================================================================

NTFSScanner::NTFSScanner() 
    : m_diskTotalClusters(0)
{}

NTFSScanner::~NTFSScanner() = default;

NTFSBootSector NTFSScanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    
    NTFSBootSector boot = {};
    if (data.size() >= sizeof(NTFSBootSector)) {
        std::memcpy(&boot, data.data(), sizeof(NTFSBootSector));
    }
    
    return boot;
}

bool NTFSScanner::ApplyFixups(std::vector<uint8_t>& recordData, uint16_t bytesPerSector) {
    if (recordData.size() < sizeof(MFTFileRecord)) return false;
    
    MFTFileRecord* header = reinterpret_cast<MFTFileRecord*>(recordData.data());
    uint16_t usaOffset = header->updateSequenceOffset;
    uint16_t usaCount = header->updateSequenceSize;
    
    if (static_cast<size_t>(usaOffset) + static_cast<size_t>(usaCount) * 2 > recordData.size()) return false;
    
    uint16_t* usaArray = reinterpret_cast<uint16_t*>(recordData.data() + usaOffset);
    uint16_t updateSequenceNumber = usaArray[0];
    
    for (uint16_t i = 1; i < usaCount; ++i) {
        uint32_t sectorEndOffset = (i * bytesPerSector) - 2;
        if (sectorEndOffset + 2 > recordData.size()) break;
        
        uint16_t* sectorFooter = reinterpret_cast<uint16_t*>(recordData.data() + sectorEndOffset);

        if (*sectorFooter == updateSequenceNumber) {
            *sectorFooter = usaArray[i];
        }
    }
    return true;
}

std::vector<uint8_t> NTFSScanner::ReadMFTRecord(DiskHandle& disk, const NTFSBootSector& boot, uint64_t recordNum) {
    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    uint64_t sectorSize = boot.bytesPerSector;
    
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
    
    ApplyFixups(result, boot.bytesPerSector);
    
    return result;
}

NTFSDataRunParser::ParseResult NTFSScanner::ParseDataRunsEnhanced(
    const uint8_t* runData,
    size_t maxSize,
    uint64_t bytesPerCluster,
    uint64_t maxCluster)
{
    return NTFSDataRunParser::Parse(runData, maxSize, bytesPerCluster, maxCluster);
}

std::vector<ClusterRange> NTFSScanner::ParseDataRuns(const uint8_t* runData, size_t maxSize, uint64_t bytesPerCluster) {
    auto result = NTFSDataRunParser::Parse(runData, maxSize, bytesPerCluster, m_diskTotalClusters);
    
    if (!result.valid) {
        return {};
    }
    
    std::vector<ClusterRange> ranges;
    ranges.reserve(result.runs.size());
    
    for (const auto& run : result.runs) {
        ClusterRange range;
        range.start = run.startCluster;
        range.count = run.clusterCount;
        ranges.push_back(range);
    }
    
    if (ranges.empty()) return ranges;
    
    std::vector<ClusterRange> merged;
    merged.reserve(ranges.size());
    
    ClusterRange current = ranges[0];
    
    for (size_t i = 1; i < ranges.size(); i++) {
        if (current.start + current.count == ranges[i].start) {
            current.count += ranges[i].count;
        } else {
            merged.push_back(current);
            current = ranges[i];
        }
    }
    merged.push_back(current);
    
    return merged;
}

std::optional<FragmentedFile> NTFSScanner::ParseMFTRecordToFragmentedFile(
    const std::vector<uint8_t>& data,
    uint64_t /*recordNum*/,
    const NTFSBootSector& boot)
{
    if (data.size() < sizeof(MFTFileRecord)) {
        return std::nullopt;
    }
    
    const MFTFileRecord* record = reinterpret_cast<const MFTFileRecord*>(data.data());
    
    if (std::memcmp(record->signature, "FILE", 4) != 0) {
        return std::nullopt;
    }
    
    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    FragmentedFile file(0, bytesPerCluster);
    
    size_t offset = record->firstAttributeOffset;
    
    while (offset + sizeof(AttributeHeader) <= data.size()) {
        const AttributeHeader* attr = reinterpret_cast<const AttributeHeader*>(data.data() + offset);
        
        if (attr->type == 0xFFFFFFFF) break;
        if (attr->length == 0 || offset > data.size() - attr->length) break;
        
        if (attr->type == 0x80) {
            if (attr->nonResident == 0) {
                const ResidentAttributeHeader* resAttr = 
                    reinterpret_cast<const ResidentAttributeHeader*>(data.data() + offset);
                
                if (resAttr->valueLength <= data.size() &&
                    resAttr->valueOffset <= data.size() - resAttr->valueLength &&
                    offset <= data.size() - resAttr->valueOffset - resAttr->valueLength) {
                    
                    std::vector<uint8_t> residentData(resAttr->valueLength);
                    std::memcpy(residentData.data(), 
                               data.data() + offset + resAttr->valueOffset,
                               resAttr->valueLength);
                    
                    file.SetResidentData(std::move(residentData));
                    return file;
                }
            } else {
                const NonResidentAttributeHeader* nrAttr = 
                    reinterpret_cast<const NonResidentAttributeHeader*>(data.data() + offset);
                
                if (attr->length >= 64 && nrAttr->dataRunOffset <= data.size() &&
                    offset <= data.size() - nrAttr->dataRunOffset) {
                    
                    const uint8_t* runData = data.data() + offset + nrAttr->dataRunOffset;
                    size_t maxRunSize = data.size() - (offset + nrAttr->dataRunOffset);
                    
                    auto parseResult = ParseDataRunsEnhanced(
                        runData, maxRunSize, bytesPerCluster, m_diskTotalClusters);
                    
                    if (parseResult.valid && !parseResult.runs.empty()) {
                        FragmentMap fragments(bytesPerCluster, m_diskTotalClusters);
                        for (const auto& run : parseResult.runs) {
                            fragments.AddRun(run);
                        }
                        fragments.SetTotalSize(nrAttr->realSize);
                        
                        file.SetFileSize(nrAttr->realSize);
                        file.SetFragmentMap(std::move(fragments));
                        return file;
                    }
                }
            }
        }
        
        offset += attr->length;
    }
    
    return std::nullopt;
}

bool NTFSScanner::ParseMFTRecord(const std::vector<uint8_t>& data, uint64_t recordNum,
                                DiskForensicsCore::FileFoundCallback& callback,
                                DiskHandle& disk,
                                const NTFSBootSector& boot,
                                const std::wstring& folderFilter,
                                const std::wstring& filenameFilter) {
    if (data.size() < sizeof(MFTFileRecord)) return false;

    const MFTFileRecord* record = reinterpret_cast<const MFTFileRecord*>(data.data());
    
    if (std::memcmp(record->signature, "FILE", 4) != 0) return false;

    const uint16_t FLAG_IN_USE = 0x0001;
    const uint16_t FLAG_IS_DIRECTORY = 0x0002;
    if ((record->flags & FLAG_IN_USE) || (record->flags & FLAG_IS_DIRECTORY)) return false;

    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;

    RecoveryCandidate candidate = {};
    candidate.mftRecord = recordNum;
    candidate.source = RecoverySource::MFT;
    candidate.fileSize = 0;
    candidate.sizeFormatted = L"Unknown";
    candidate.quality = RecoveryQuality::Unrecoverable;
    candidate.file = FragmentedFile(0, bytesPerCluster);
    
    bool hasFileName = false;
    bool hasData = false;
    
    size_t offset = record->firstAttributeOffset;
    
    while (offset + sizeof(AttributeHeader) <= data.size()) {
        const AttributeHeader* attr = reinterpret_cast<const AttributeHeader*>(data.data() + offset);
        
        if (attr->type == 0xFFFFFFFF) break;
        if (attr->length == 0 || offset > data.size() - attr->length) break;
        
        if (attr->type == 0x30 && !hasFileName && attr->nonResident == 0) {
            const ResidentAttributeHeader* resAttr = 
                reinterpret_cast<const ResidentAttributeHeader*>(data.data() + offset);
            
            if (resAttr->valueOffset <= data.size() - sizeof(FileNameAttribute) &&
                offset <= data.size() - resAttr->valueOffset - sizeof(FileNameAttribute)) {
                
                const FileNameAttribute* fnAttr = 
                    reinterpret_cast<const FileNameAttribute*>(
                        data.data() + offset + resAttr->valueOffset);
                
                if (fnAttr->nameType != 0x02) {
                    if (!hasFileName) {
                        size_t nameLen = std::min(static_cast<size_t>(fnAttr->nameLength), size_t(255));
                        size_t requiredSize = sizeof(FileNameAttribute) + (nameLen - 1) * sizeof(wchar_t);

                        if (requiredSize <= data.size() &&
                            resAttr->valueOffset <= data.size() - requiredSize &&
                            offset <= data.size() - resAttr->valueOffset - requiredSize) {

                            candidate.name.assign(fnAttr->name, nameLen);
                            hasFileName = true;
                        }
                    }
                }
            }
        }
        
        if (attr->type == 0x80 && !hasData) {
            if (attr->nonResident == 0) {
                const ResidentAttributeHeader* resAttr = 
                    reinterpret_cast<const ResidentAttributeHeader*>(data.data() + offset);
                
                if (resAttr->valueLength <= data.size() &&
                    resAttr->valueOffset <= data.size() - resAttr->valueLength &&
                    offset <= data.size() - resAttr->valueOffset - resAttr->valueLength) {

                    std::vector<uint8_t> residentData(resAttr->valueLength);
                    std::memcpy(residentData.data(),
                               data.data() + offset + resAttr->valueOffset,
                               resAttr->valueLength);
                    candidate.file.SetResidentData(std::move(residentData));

                    candidate.fileSize = resAttr->valueLength;
                    candidate.sizeFormatted = StringUtils::FormatFileSize(resAttr->valueLength);
                    candidate.quality = RecoveryQuality::Full;
                    hasData = true;
                }
            } else {
                const NonResidentAttributeHeader* nrAttr = 
                    reinterpret_cast<const NonResidentAttributeHeader*>(data.data() + offset);
                
				if (attr->length >= 64 && nrAttr->dataRunOffset <= data.size() &&
                    offset <= data.size() - nrAttr->dataRunOffset) {
                    const uint8_t* runData = data.data() + offset + nrAttr->dataRunOffset;
                    size_t maxRunSize = data.size() - (offset + nrAttr->dataRunOffset);
                    auto parseResult = ParseDataRunsEnhanced(
                        runData, maxRunSize, bytesPerCluster, m_diskTotalClusters);
					if (parseResult.valid && !parseResult.runs.empty()) {
						for (const auto& run : parseResult.runs) {
							candidate.file.Fragments().AddRun(run.startCluster, run.clusterCount);
						}
						candidate.file.Fragments().SetTotalSize(nrAttr->realSize);
                        candidate.fileSize = nrAttr->realSize;
                        candidate.sizeFormatted = StringUtils::FormatFileSize(nrAttr->realSize);
                        candidate.quality = RecoveryQuality::Full;
                        hasData = true;
					} else {
						auto clusterRanges = ParseDataRuns(runData, maxRunSize, bytesPerCluster);
						if (!clusterRanges.empty()) {
							for (const auto& range : clusterRanges) {
								candidate.file.Fragments().AddRun(range.start, range.count);
							}
							candidate.file.Fragments().SetTotalSize(nrAttr->realSize);
						}
                        candidate.fileSize = nrAttr->realSize;
                        candidate.sizeFormatted = StringUtils::FormatFileSize(nrAttr->realSize);
                        candidate.quality = clusterRanges.empty() ? RecoveryQuality::Unrecoverable : RecoveryQuality::Full;
                        hasData = true;
                    }
                }

            }
        }
        
        offset += attr->length;
    }
    
    if (hasFileName) {
        candidate.path = ReconstructPath(disk, boot, recordNum, candidate.name);

        if (!hasData) {
            candidate.fileSize = 0;
            candidate.sizeFormatted = L"Unknown";
            candidate.quality = RecoveryQuality::Unrecoverable;
        }

        if (!folderFilter.empty()) {
            std::wstring lowerPath = candidate.path;
            std::wstring lowerFilter = folderFilter;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::towlower);
            if (lowerPath.find(lowerFilter) == std::wstring::npos) return false;
        }

        if (!filenameFilter.empty()) {
            std::wstring lowerName = candidate.name;
            std::wstring lowerFilter = filenameFilter;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), ::towlower);
            if (lowerName.find(lowerFilter) == std::wstring::npos) return false;
        }

        callback(candidate);
        return true;
    }

    return false;
}

std::wstring NTFSScanner::ReconstructPath(DiskHandle& disk, const NTFSBootSector& boot,
                                          uint64_t mftRecord, const std::wstring& filename) {
    auto it = m_pathCache.find(mftRecord);
    if (it != m_pathCache.end()) {
        return filename.empty() ? it->second : it->second + L"\\" + filename;
    }
    
    static std::set<uint64_t> visitedRecords;
    
    if (visitedRecords.empty() || visitedRecords.size() > Constants::NTFS::PATH_CACHE_SIZE_LIMIT) {
        visitedRecords.clear();
    }
    
    if (visitedRecords.find(mftRecord) != visitedRecords.end()) {
        return L"<deleted>\\" + filename;
    }
    
    if (visitedRecords.size() > Constants::NTFS::PATH_CACHE_DEPTH_LIMIT) return L"<deleted>\\" + filename;
    
    visitedRecords.insert(mftRecord);
    
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
    
    std::wstring parentPath = ReconstructPath(disk, boot, parentMftRecord, L"");
    
    visitedRecords.erase(mftRecord);
    
    m_pathCache[mftRecord] = parentPath;
    return filename.empty() ? parentPath : parentPath + L"\\" + filename;
}

bool NTFSScanner::ScanVolume(
    DiskHandle& disk,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    bool& shouldStop,
    const ScanConfiguration& config)
{
    m_pathCache.clear();
    
    NTFSBootSector boot = ReadBootSector(disk);
    if (std::memcmp(boot.oemID, "NTFS    ", 8) != 0) return false;

    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    uint64_t diskSize = disk.GetDiskSize();
    m_diskTotalClusters = diskSize / bytesPerCluster;

    uint64_t maxRecords = config.ntfsMftSpareDriveLimit;
    uint64_t recordsScanned = 0;
    uint64_t filesFound = 0;
    
    uint64_t mftRecordSize = (boot.clustersPerMFTRecord >= 0) 
        ? boot.clustersPerMFTRecord * bytesPerCluster
        : (1ULL << (-boot.clustersPerMFTRecord));

    uint64_t batchBufferSize = Constants::NTFS::RECORDS_PER_BATCH * mftRecordSize;
    uint64_t sectorsPerBatch = (batchBufferSize + boot.bytesPerSector - 1) / boot.bytesPerSector;

    for (uint64_t i = 0; i < maxRecords && !shouldStop; i += Constants::NTFS::RECORDS_PER_BATCH) {
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
            recordsScanned += Constants::NTFS::RECORDS_PER_BATCH;
            continue;
        }

        for (uint64_t j = 0; j < Constants::NTFS::RECORDS_PER_BATCH; ++j) {
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

        if ((i % Constants::Progress::MFT_SCAN_INTERVAL) == 0) {
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
} // namespace KVC