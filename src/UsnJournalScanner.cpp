// UsnJournalScanner.cpp

#include "UsnJournalScanner.h"
#include "Constants.h"

#include <climits>
#include <cstring>
#include <algorithm>
#include <map>
#include <vector>

namespace KVC {

UsnJournalScanner::UsnJournalScanner() = default;
UsnJournalScanner::~UsnJournalScanner() = default;

// Parse USN Journal and group records by MFT record number.
std::map<uint64_t, std::vector<UsnRecord>> UsnJournalScanner::ParseJournal(
    DiskHandle& disk,
    uint64_t maxRecords)
{
    std::map<uint64_t, std::vector<UsnRecord>> recordsByMft;

    try {
        auto boot = ReadBootSector(disk);
        
        // $Extend\$UsnJrnl is usually at MFT record 38.
        auto usnjrnlData = ReadMFTRecord(disk, boot, Constants::NTFS::USNJRNL_RECORD_NUMBER);
        if (usnjrnlData.empty()) {
            return recordsByMft;
        }

        // Find $J stream location within the MFT record.
        auto jStreamClusters = ParseJStreamLocation(usnjrnlData);
        if (jStreamClusters.empty()) {
            return recordsByMft;
        }

        // Read $J stream data from disk.
        auto jData = ReadClusters(disk, boot, jStreamClusters);
        if (jData.empty()) {
            return recordsByMft;
        }

        // Parse all USN records from the buffer.
        auto records = ParseRecordsFromBuffer(jData);
        
        // Group by MFT record number and apply limit.
        uint64_t count = 0;
        for (const auto& record : records) {
            if (count >= maxRecords) break;
            
            uint64_t mftNum = record.MftRecordNumber();
            recordsByMft[mftNum].push_back(record);
            count++;
        }
    }
    catch (...) {
        // Silent failure - USN Journal is optional and may not exist.
    }

    return recordsByMft;
}

// Read and parse the NTFS boot sector.
UsnJournalScanner::NtfsBootSector UsnJournalScanner::ReadBootSector(DiskHandle& disk) {
    auto data = disk.ReadSectors(0, 1, disk.GetSectorSize());
    
    NtfsBootSector boot = {};
    if (data.size() >= 512) {
        // Extract bytes per sector (offset 11-12).
        boot.bytesPerSector = static_cast<uint16_t>(data[11]) | 
                             (static_cast<uint16_t>(data[12]) << 8);
        // Extract sectors per cluster (offset 13).
        boot.sectorsPerCluster = data[13];
        // Extract MFT cluster location (offset 48-55, 8 bytes).
        boot.mftCluster = 0;
        for (int i = 0; i < 8; i++) {
            boot.mftCluster |= static_cast<uint64_t>(data[48 + i]) << (i * 8);
        }
        // Extract clusters per MFT record (offset 64, signed byte).
        boot.clustersPerMFTRecord = static_cast<int8_t>(data[64]);
    }
    
    return boot;
}

// Read a specific MFT record from the Master File Table.
std::vector<uint8_t> UsnJournalScanner::ReadMFTRecord(
    DiskHandle& disk, 
    const NtfsBootSector& boot, 
    uint64_t recordNum)
{
    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    uint64_t sectorSize = boot.bytesPerSector;
    
    // Calculate MFT record size (either fixed or computed from negative value).
    uint64_t mftRecordSize = (boot.clustersPerMFTRecord >= 0) 
        ? boot.clustersPerMFTRecord * bytesPerCluster
        : (1ULL << (-boot.clustersPerMFTRecord));

    // Calculate physical offset of the MFT record.
    uint64_t mftOffset = boot.mftCluster * bytesPerCluster;
    uint64_t recordOffset = mftOffset + (recordNum * mftRecordSize);
    
    uint64_t startSector = recordOffset / sectorSize;
    uint64_t numSectors = (mftRecordSize + sectorSize - 1) / sectorSize;

    auto data = disk.ReadSectors(startSector, numSectors, sectorSize);
    
    // Extract the exact MFT record from the sector buffer.
    uint64_t offsetInSector = recordOffset % sectorSize;
    size_t end = std::min(static_cast<size_t>(offsetInSector + mftRecordSize), data.size());
    
    if (offsetInSector < data.size()) {
        return std::vector<uint8_t>(data.begin() + static_cast<size_t>(offsetInSector), data.begin() + static_cast<size_t>(end));
    }
    
    return {};
}

// Parse MFT record to find $J stream data runs.
std::vector<ClusterRange> UsnJournalScanner::ParseJStreamLocation(
    const std::vector<uint8_t>& mftData)
{
    if (mftData.size() < 48) {
        return {};
    }

    // Check FILE signature at the beginning.
    if (std::memcmp(mftData.data(), "FILE", 4) != 0) {
        return {};
    }

    // Extract offset to first attribute (bytes 20-21).
    uint16_t firstAttrOffset = static_cast<uint16_t>(mftData[20]) | 
                               (static_cast<uint16_t>(mftData[21]) << 8);
    size_t offset = firstAttrOffset;

    // Look for $DATA attribute with name "$J".
    while (offset + 16 < mftData.size()) {
        // Read attribute type (4 bytes, little-endian).
        uint32_t attrType = 0;
        for (int i = 0; i < 4; i++) {
            attrType |= static_cast<uint32_t>(mftData[offset + i]) << (i * 8);
        }

        // End of attributes marker.
        if (attrType == 0xFFFFFFFF) {
            break;
        }

        // Read attribute length (4 bytes, little-endian).
        uint32_t attrLength = 0;
        for (int i = 0; i < 4; i++) {
            attrLength |= static_cast<uint32_t>(mftData[offset + 4 + i]) << (i * 8);
        }

        // Validate attribute length.
        if (attrLength == 0 || offset + attrLength > mftData.size()) {
            break;
        }

        // 0x80 = $DATA attribute.
        if (attrType == 0x80) {
            uint8_t nameLength = mftData[offset + 9];
            uint16_t nameOffset = static_cast<uint16_t>(mftData[offset + 10]) | 
                                 (static_cast<uint16_t>(mftData[offset + 11]) << 8);

            if (nameLength > 0 && offset + nameOffset + nameLength * 2 <= mftData.size()) {
                // Read attribute name (UTF-16 LE).
                std::wstring name;
                for (size_t i = 0; i < nameLength; i++) {
                    wchar_t c = static_cast<wchar_t>(mftData[offset + nameOffset + i * 2]) |
                               (static_cast<wchar_t>(mftData[offset + nameOffset + i * 2 + 1]) << 8);
                    name += c;
                }

                // Found the $J stream - parse its data runs.
                if (name == L"$J") {
                    return ParseDataRuns(mftData.data() + offset, attrLength);
                }
            }
        }

        offset += attrLength;
    }

    return {};
}

// Parse NTFS data runs to extract cluster locations.
std::vector<ClusterRange> UsnJournalScanner::ParseDataRuns(
    const uint8_t* attrData, 
    size_t attrLength)
{
    if (attrLength < 24) {
        return {};
    }

    // Check if attribute is non-resident (byte 8).
    uint8_t nonResident = attrData[8];
    if (nonResident == 0) {
        return {};
    }

    if (attrLength < 64) {
        return {};
    }

    // Extract offset to data run list (bytes 32-33).
    uint16_t runlistOffset = static_cast<uint16_t>(attrData[32]) | 
                            (static_cast<uint16_t>(attrData[33]) << 8);

    if (runlistOffset >= attrLength) {
        return {};
    }

    std::vector<ClusterRange> ranges;
    size_t offset = runlistOffset;
    int64_t currentLCN = 0;

    // Parse each data run.
    while (offset < attrLength) {
        uint8_t header = attrData[offset];
        if (header == 0) {
            break;
        }

        // Extract size fields from header byte.
        uint8_t lengthSize = header & 0x0F;
        uint8_t lcnSize = (header >> 4) & 0x0F;

        // Validate field sizes.
        if (lengthSize == 0 || lengthSize > 8 || lcnSize > 8) {
            break;
        }

        offset++;

        if (offset + lengthSize + lcnSize > attrLength) {
            break;
        }

        // Parse run length (cluster count).
        uint64_t runLength = 0;
        for (uint8_t i = 0; i < lengthSize; i++) {
            runLength |= static_cast<uint64_t>(attrData[offset + i]) << (i * 8);
        }
        offset += lengthSize;

        // Parse LCN offset (signed).
        int64_t lcnOffset = 0;
        for (uint8_t i = 0; i < lcnSize; i++) {
            lcnOffset |= static_cast<int64_t>(attrData[offset + i]) << (i * 8);
        }

        // Sign-extend LCN offset if necessary.
        if (lcnSize > 0 && (attrData[offset + lcnSize - 1] & 0x80)) {
            for (uint8_t i = lcnSize; i < 8; i++) {
                lcnOffset |= static_cast<int64_t>(0xFF) << (i * 8);
            }
        }

        offset += lcnSize;

        // Update current LCN (cumulative offset).
        currentLCN += lcnOffset;

        // Add range if valid (non-sparse).
        if (lcnSize > 0 && currentLCN > 0) {
            ClusterRange range;
            range.start = static_cast<uint64_t>(currentLCN);
            range.count = runLength;
            ranges.push_back(range);
        }

        // Safety limit to prevent infinite loops.
        if (ranges.size() > 10000) {
            break;
        }
    }

    return ranges;
}

// Read clusters from disk based on cluster ranges.
std::vector<uint8_t> UsnJournalScanner::ReadClusters(
    DiskHandle& disk,
    const NtfsBootSector& boot,
    const std::vector<ClusterRange>& ranges)
{
    std::vector<uint8_t> result;
    uint64_t bytesPerCluster = boot.bytesPerSector * boot.sectorsPerCluster;
    uint64_t sectorSize = boot.bytesPerSector;
    uint64_t sectorsPerCluster = bytesPerCluster / sectorSize;

    // Limit total read to avoid excessive memory (~400MB at 4KB clusters).
    uint64_t clustersRead = 0;

    for (const auto& range : ranges) {
        if (clustersRead >= Constants::NTFS::MAX_CLUSTER_CHAIN_READ) {
            break;
        }

        uint64_t clustersToRead = std::min(range.count, Constants::NTFS::MAX_CLUSTER_CHAIN_READ - clustersRead);
        
        // Read each cluster in the range.
        for (uint64_t i = 0; i < clustersToRead; i++) {
            uint64_t cluster = range.start + i;
            uint64_t sector = cluster * sectorsPerCluster;

            auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
            result.insert(result.end(), data.begin(), data.end());
            clustersRead++;
        }
    }

    return result;
}

// Parse USN records from raw buffer data.
std::vector<UsnRecord> UsnJournalScanner::ParseRecordsFromBuffer(
    const std::vector<uint8_t>& buffer)
{
    std::vector<UsnRecord> records;
    size_t offset = 0;

    while (offset + 60 < buffer.size()) {
        // Read record length (first 4 bytes).
        uint32_t recordLength = 0;
        for (int i = 0; i < 4; i++) {
            recordLength |= static_cast<uint32_t>(buffer[offset + i]) << (i * 8);
        }

        // Validate record length.
        if (recordLength < 60 || recordLength > 65536 || 
            offset + recordLength > buffer.size()) {
            offset += 8; // Try to skip ahead
            continue;
        }

        // Parse USN_RECORD_V2 structure.
        UsnRecord rec;
        rec.recordLength = recordLength;
        
        // Major version (bytes 4-5).
        rec.majorVersion = static_cast<uint16_t>(buffer[offset + 4]) | 
                          (static_cast<uint16_t>(buffer[offset + 5]) << 8);
        // Minor version (bytes 6-7).
        rec.minorVersion = static_cast<uint16_t>(buffer[offset + 6]) | 
                          (static_cast<uint16_t>(buffer[offset + 7]) << 8);

        // File reference number (bytes 8-15).
        rec.fileReferenceNumber = 0;
        for (int i = 0; i < 8; i++) {
            rec.fileReferenceNumber |= static_cast<uint64_t>(buffer[offset + 8 + i]) << (i * 8);
        }

        // Parent file reference number (bytes 16-23).
        rec.parentFileReferenceNumber = 0;
        for (int i = 0; i < 8; i++) {
            rec.parentFileReferenceNumber |= static_cast<uint64_t>(buffer[offset + 16 + i]) << (i * 8);
        }

        // USN (Update Sequence Number, bytes 24-31).
        rec.usn = 0;
        for (int i = 0; i < 8; i++) {
            rec.usn |= static_cast<int64_t>(buffer[offset + 24 + i]) << (i * 8);
        }

        // Timestamp (FILETIME format, bytes 32-39).
        uint64_t filetime = 0;
        for (int i = 0; i < 8; i++) {
            filetime |= static_cast<uint64_t>(buffer[offset + 32 + i]) << (i * 8);
        }
        
        // Convert FILETIME to system_clock (simplified conversion).
        auto ticks = static_cast<int64_t>(filetime - 116444736000000000ULL) / 10000000;
        rec.timestamp = std::chrono::system_clock::from_time_t(ticks);

        // Reason flags (bytes 40-43).
        rec.reason = 0;
        for (int i = 0; i < 4; i++) {
            rec.reason |= static_cast<uint32_t>(buffer[offset + 40 + i]) << (i * 8);
        }

        // Source info (bytes 44-47).
        rec.sourceInfo = 0;
        for (int i = 0; i < 4; i++) {
            rec.sourceInfo |= static_cast<uint32_t>(buffer[offset + 44 + i]) << (i * 8);
        }

        // Security ID (bytes 48-51).
        rec.securityId = 0;
        for (int i = 0; i < 4; i++) {
            rec.securityId |= static_cast<uint32_t>(buffer[offset + 48 + i]) << (i * 8);
        }

        // File attributes (bytes 52-55).
        rec.fileAttributes = 0;
        for (int i = 0; i < 4; i++) {
            rec.fileAttributes |= static_cast<uint32_t>(buffer[offset + 52 + i]) << (i * 8);
        }

        // Filename length and offset (bytes 56-59).
        uint16_t filenameLength = static_cast<uint16_t>(buffer[offset + 56]) | 
                                 (static_cast<uint16_t>(buffer[offset + 57]) << 8);
        uint16_t filenameOffset = static_cast<uint16_t>(buffer[offset + 58]) | 
                                 (static_cast<uint16_t>(buffer[offset + 59]) << 8);

        // Read filename (UTF-16 LE).
        if (filenameOffset > 0 && filenameLength > 0 && 
            offset + filenameOffset + filenameLength <= buffer.size()) {
            
            size_t nameChars = filenameLength / 2;
            for (size_t i = 0; i < nameChars; i++) {
                wchar_t c = static_cast<wchar_t>(buffer[offset + filenameOffset + i * 2]) |
                           (static_cast<wchar_t>(buffer[offset + filenameOffset + i * 2 + 1]) << 8);
                rec.filename += c;
            }
        }

        records.push_back(rec);
        
        offset += recordLength;
        
        // Align to 8-byte boundary for next record.
        offset = (offset + 7) & ~7ULL;
    }

    return records;
}

// ============================================================================
// UsnRecord Helper Methods
// ============================================================================

// Check if record represents a file deletion
bool UsnRecord::IsDeletion() const {
    return (reason & USN_REASON_FILE_DELETE) != 0;
}

// Check if record represents a directory
bool UsnRecord::IsDirectory() const {
    return (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Extract MFT record number (lower 48 bits of file reference)
uint64_t UsnRecord::MftRecordNumber() const {
    return fileReferenceNumber & 0x0000FFFFFFFFFFFFULL;
}

// Alias for MftRecordNumber (same value)
uint64_t UsnRecord::MftIndex() const {
    return MftRecordNumber();
}

// Extract sequence number (upper 16 bits of file reference)
uint16_t UsnRecord::SequenceNumber() const {
    return static_cast<uint16_t>((fileReferenceNumber >> 48) & 0xFFFF);
}

} // namespace KVC