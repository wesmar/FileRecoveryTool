// FileCarver.cpp
#include "FileCarver.h"
#include "Constants.h"
#include <cstring>
#include <algorithm>

namespace KVC {

FileCarver::FileCarver() = default;
FileCarver::~FileCarver() = default;

// Scan a single cluster for known file signatures.
std::optional<FileSignature> FileCarver::ScanClusterForSignature(
    DiskHandle& disk,
    uint64_t cluster,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const std::vector<FileSignature>& signatures)
{
    if (cluster < 2) {
        return std::nullopt;                    // Invalid cluster number
    }

    uint64_t sector = clusterHeapOffset + ((cluster - 2) * sectorsPerCluster);
    auto data = disk.ReadSectors(sector, sectorsPerCluster, sectorSize);
    
    if (data.empty()) {
        return std::nullopt;                    // Read failed
    }

    // Check each signature against cluster header
    for (const auto& sig : signatures) {
        if (data.size() >= sig.signatureSize) {
            if (std::memcmp(data.data(), sig.signature, sig.signatureSize) == 0) {
                return sig;                     // Signature match found
            }
        }
    }

    return std::nullopt;                        // No signature matched
}

// Parse file size from header using format-specific logic.
std::optional<uint64_t> FileCarver::ParseFileSize(
    DiskHandle& disk,
    uint64_t cluster,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const FileSignature& signature)
{
    uint64_t sector = clusterHeapOffset + ((cluster - 2) * sectorsPerCluster);
    
    // Read 256KB for header parsing
    auto data = disk.ReadSectors(sector, sectorsPerCluster * Constants::Carving::HEADER_READ_CLUSTERS, sectorSize);
    
    if (data.empty()) {
        return std::nullopt;
    }

    // Dispatch to appropriate parser based on file type
    if (std::strcmp(signature.extension, "png") == 0) {
        return ParsePngSize(data);
    } else if (std::strcmp(signature.extension, "jpg") == 0) {
        return ParseJpegSize(data);
    } else if (std::strcmp(signature.extension, "gif") == 0) {
        return ParseGifSize(data);
    } else if (std::strcmp(signature.extension, "bmp") == 0) {
        return ParseBmpSize(data);
    } else if (std::strcmp(signature.extension, "pdf") == 0) {
        return ParsePdfSize(data);
    } else if (std::strcmp(signature.extension, "zip") == 0 ||
               std::strcmp(signature.extension, "docx") == 0 ||
               std::strcmp(signature.extension, "xlsx") == 0 ||
               std::strcmp(signature.extension, "pptx") == 0) {
        return ParseZipSize(data);
    } else if (std::strcmp(signature.extension, "mp4") == 0) {
        return ParseMp4Size(data);
    } else if (std::strcmp(signature.extension, "avi") == 0) {
        return ParseAviSize(data);
    } else if (std::strcmp(signature.extension, "wav") == 0) {
        return ParseWavSize(data);
    } else if (std::strcmp(signature.extension, "doc") == 0 ||
               std::strcmp(signature.extension, "xls") == 0 ||
               std::strcmp(signature.extension, "ppt") == 0) {
        return ParseOle2Size(data);
    } else if (std::strcmp(signature.extension, "rar") == 0) {
        return ParseRarSize(data);
    } else if (std::strcmp(signature.extension, "7z") == 0) {
        return Parse7zSize(data);
    }

    return std::nullopt;                        // Unknown format
}

// PNG: Find IEND chunk to determine file end.
std::optional<uint64_t> FileCarver::ParsePngSize(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    // Verify PNG signature
    const uint8_t pngSig[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (std::memcmp(data.data(), pngSig, 8) != 0) {
        return std::nullopt;
    }

    size_t offset = 8;
    // Iterate through PNG chunks
    while (offset + 12 <= data.size()) {
        // Read chunk length (big-endian)
        uint32_t chunkLen = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           static_cast<uint32_t>(data[offset + 3]);

        // Check if IEND chunk (marks end of PNG)
        if (std::memcmp(data.data() + offset + 4, "IEND", 4) == 0) {
            return offset + 12 + chunkLen;
        }

        offset += 12 + chunkLen;
    }

    return std::nullopt;                        // IEND not found
}

// JPEG: Find EOI marker (0xFFD9) to determine file end.
std::optional<uint64_t> FileCarver::ParseJpegSize(const std::vector<uint8_t>& data) {
    if (data.size() < 3) {
        return std::nullopt;
    }

    // Verify JPEG signature
    if (data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF) {
        return std::nullopt;
    }

    // Search for EOI marker
    for (size_t i = 2; i < data.size() - 1; i++) {
        if (data[i] == 0xFF && data[i + 1] == 0xD9) {
            return i + 2;                       // Found end of image
        }
    }

    return std::nullopt;                        // EOI not found
}

// GIF: Find trailer (0x3B) to determine file end.
std::optional<uint64_t> FileCarver::ParseGifSize(const std::vector<uint8_t>& data) {
    if (data.size() < 6) {
        return std::nullopt;
    }

    // Verify GIF signature
    if (std::memcmp(data.data(), "GIF8", 4) != 0) {
        return std::nullopt;
    }

    // Search for GIF trailer
    for (size_t i = 6; i < data.size(); i++) {
        if (data[i] == 0x3B) {
            return i + 1;                       // Found trailer
        }
    }

    return std::nullopt;                        // Trailer not found
}

// BMP: Read size from header (offset 2, 4 bytes).
std::optional<uint64_t> FileCarver::ParseBmpSize(const std::vector<uint8_t>& data) {
    if (data.size() < 6) {
        return std::nullopt;
    }

    // Verify BM signature
    if (data[0] != 0x42 || data[1] != 0x4D) {
        return std::nullopt;
    }

    // File size at offset 2 (little-endian)
    uint32_t fileSize = static_cast<uint32_t>(data[2]) |
                       (static_cast<uint32_t>(data[3]) << 8) |
                       (static_cast<uint32_t>(data[4]) << 16) |
                       (static_cast<uint32_t>(data[5]) << 24);

    return fileSize;
}

// PDF: Find %%EOF marker to determine file end.
std::optional<uint64_t> FileCarver::ParsePdfSize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return std::nullopt;
    }

    // Verify PDF signature
    if (std::memcmp(data.data(), "%PDF", 4) != 0) {
        return std::nullopt;
    }

    // Search for %%EOF marker (from end)
    for (size_t i = data.size() - 5; i > 0; i--) {
        if (std::memcmp(data.data() + i, "%%EOF", 5) == 0) {
            return i + 5;                       // Found end of file
        }
    }

    return std::nullopt;                        // EOF marker not found
}

// ZIP: Find end of central directory to determine file end.
std::optional<uint64_t> FileCarver::ParseZipSize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return std::nullopt;
    }

    // Verify ZIP signature
    const uint8_t zipSig[] = {0x50, 0x4B, 0x03, 0x04};
    if (std::memcmp(data.data(), zipSig, 4) != 0) {
        return std::nullopt;
    }

    // Search for end of central directory (0x50 0x4B 0x05 0x06)
    for (size_t i = data.size() - 22; i > 0; i--) {
        if (data[i] == 0x50 && data[i+1] == 0x4B && 
            data[i+2] == 0x05 && data[i+3] == 0x06) {
            
            // Comment length at offset i+20
            if (i + 22 <= data.size()) {
                uint16_t commentLen = static_cast<uint16_t>(data[i + 20]) |
                                     (static_cast<uint16_t>(data[i + 21]) << 8);
                return i + 22 + commentLen;     // Total file size
            }
        }
    }

    return std::nullopt;                        // End of central directory not found
}

// MP4: Parse atom sizes to determine file end.
std::optional<uint64_t> FileCarver::ParseMp4Size(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    // Check for ftyp atom
    if (std::memcmp(data.data() + 4, "ftyp", 4) == 0) {
        // For simplicity, sum all top-level atoms
        uint64_t totalSize = 0;
        size_t offset = 0;
        
        while (offset + 8 <= data.size()) {
            uint32_t size = (static_cast<uint32_t>(data[offset]) << 24) |
                           (static_cast<uint32_t>(data[offset + 1]) << 16) |
                           (static_cast<uint32_t>(data[offset + 2]) << 8) |
                           static_cast<uint32_t>(data[offset + 3]);
            
            if (size == 0) break;               // Invalid atom
            totalSize += size;
            offset += size;
            
            if (offset >= data.size()) break;
        }
        
        if (totalSize > 0) {
            return totalSize;
        }
    }

    return std::nullopt;                        // Cannot determine size
}

// AVI: Parse RIFF size from header.
std::optional<uint64_t> FileCarver::ParseAviSize(const std::vector<uint8_t>& data) {
    if (data.size() < 12) {
        return std::nullopt;
    }

    // Verify RIFF signature
    if (std::memcmp(data.data(), "RIFF", 4) != 0) {
        return std::nullopt;
    }

    // File size at offset 4 (little-endian) + 8 for header
    uint32_t riffSize = static_cast<uint32_t>(data[4]) |
                       (static_cast<uint32_t>(data[5]) << 8) |
                       (static_cast<uint32_t>(data[6]) << 16) |
                       (static_cast<uint32_t>(data[7]) << 24);

    return riffSize + 8;
}

// WAV: Same as AVI (both use RIFF format).
std::optional<uint64_t> FileCarver::ParseWavSize(const std::vector<uint8_t>& data) {
    return ParseAviSize(data);                  // Reuse RIFF parser
}

// OLE2: Parse sector allocation table for file size.
std::optional<uint64_t> FileCarver::ParseOle2Size(const std::vector<uint8_t>& data) {
    if (data.size() < 512) {
        return std::nullopt;
    }

    // Verify OLE2 signature
    const uint8_t ole2Sig[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    if (std::memcmp(data.data(), ole2Sig, 8) != 0) {
        return std::nullopt;
    }

    // Simplified: estimate based on sector count
    // Sector size at offset 30
    uint16_t sectorShift = static_cast<uint16_t>(data[30]) |
                          (static_cast<uint16_t>(data[31]) << 8);
    uint32_t sectorSize = 1 << sectorShift;

    // Total sectors at offset 80
    uint32_t totalSectors = static_cast<uint32_t>(data[80]) |
                           (static_cast<uint32_t>(data[81]) << 8) |
                           (static_cast<uint32_t>(data[82]) << 16) |
                           (static_cast<uint32_t>(data[83]) << 24);

    if (totalSectors > 0 && totalSectors < 1000000) {
        return static_cast<uint64_t>(totalSectors) * sectorSize;
    }

    return std::nullopt;                        // Invalid sector count
}

// RAR: Parse archive header (complex format, return nullopt).
std::optional<uint64_t> FileCarver::ParseRarSize(const std::vector<uint8_t>& data) {
    if (data.size() < 7) {
        return std::nullopt;
    }

    // Verify RAR signature
    const uint8_t rarSig[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
    if (std::memcmp(data.data(), rarSig, 6) != 0) {
        return std::nullopt;
    }

    // RAR has complex structure, estimate conservatively
    return std::nullopt;                        // Fallback to cluster estimation
}

// 7z: Parse header (complex format, return nullopt).
std::optional<uint64_t> FileCarver::Parse7zSize(const std::vector<uint8_t>& data) {
    if (data.size() < 32) {
        return std::nullopt;
    }

    // Verify 7z signature
    const uint8_t sig7z[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
    if (std::memcmp(data.data(), sig7z, 6) != 0) {
        return std::nullopt;
    }

    // 7z has complex structure, estimate conservatively
    return std::nullopt;                        // Fallback to cluster estimation
}

// Scan disk region using memory-mapped I/O for optimal performance.
std::vector<FileCarver::CarvedFile> FileCarver::ScanRegionMemoryMapped(
    DiskHandle& disk,
    uint64_t startCluster,
    uint64_t clusterCount,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const std::vector<FileSignature>& signatures,
    uint64_t maxFiles)
{
    std::vector<CarvedFile> results;
    
    if (clusterCount == 0) {
        return results;                         // Nothing to scan
    }
    
    uint64_t bytesPerCluster = sectorsPerCluster * sectorSize;
    uint64_t startOffset = (clusterHeapOffset + (startCluster - 2) * sectorsPerCluster) * sectorSize;
    uint64_t regionSize = clusterCount * bytesPerCluster;
    
    const uint8_t* data = nullptr;
    uint64_t dataSize = 0;
    std::vector<uint8_t> buffer;
    bool usedMapping = false;
    
    // Try memory-mapped access first (faster)
    auto region = disk.MapDiskRegion(startOffset, regionSize);
    if (region.IsValid()) {
        data = region.data;
        dataSize = region.size;
        usedMapping = true;
    } else {
        // Fallback to traditional read
        uint64_t sectorsToRead = (regionSize + sectorSize - 1) / sectorSize;
        uint64_t startSector = startOffset / sectorSize;
        buffer = disk.ReadSectors(startSector, sectorsToRead, sectorSize);
        
        if (buffer.empty()) {
            return results;                     // Read failed
        }
        
        data = buffer.data();
        dataSize = buffer.size();
    }
    
    // Scan mapped region for file signatures
    for (uint64_t offset = 0; offset < dataSize && results.size() < maxFiles; ) {
        uint64_t currentCluster = startCluster + (offset / bytesPerCluster);
        
        bool foundSignature = false;
        
        // Check all signatures at current offset
        for (const auto& sig : signatures) {
            if (offset + sig.signatureSize > dataSize) {
                continue;                       // Not enough data for signature
            }
            
            if (std::memcmp(data + offset, sig.signature, sig.signatureSize) == 0) {
                size_t remainingData = static_cast<size_t>(dataSize - offset);
                auto fileSize = ParseFileSizeFromMemory(data + offset, remainingData, sig);
                
                if (fileSize.has_value() && fileSize.value() > 0) {
                    CarvedFile carved;
                    carved.signature = sig;
                    carved.startCluster = currentCluster;
                    carved.fileSize = fileSize.value();
                    results.push_back(carved);
                    
                    // Skip over detected file (with safety limit)
                    uint64_t detectedSize = fileSize.value();
                    
                    uint64_t safeSkipSize = std::min(detectedSize, Constants::Carving::MAX_SAFE_SKIP);
                    uint64_t clustersUsed = (safeSkipSize + bytesPerCluster - 1) / bytesPerCluster;
                    uint64_t alignedSkip = clustersUsed * bytesPerCluster;
                    
                    offset += alignedSkip;
                    foundSignature = true;
                    break;
                }
            }
        }
        
        if (!foundSignature) {
            offset += bytesPerCluster;          // Move to next cluster
        }
    }
    
    // Clean up memory mapping if used
    if (usedMapping) {
        disk.UnmapRegion(region);
    }
    
    return results;
}

// Parse file size from memory buffer (used by memory-mapped scanner).
std::optional<uint64_t> FileCarver::ParseFileSizeFromMemory(
    const uint8_t* data,
    size_t dataSize,
    const FileSignature& signature)
{
    if (dataSize < 4) {
        return std::nullopt;
    }

    // Use same parsers but from memory buffer instead of disk I/O
    std::vector<uint8_t> buffer(data, data + std::min<size_t>(dataSize, Constants::Carving::HEADER_READ_SIZE));
    
    if (std::strcmp(signature.extension, "png") == 0) {
        return ParsePngSize(buffer);
    } else if (std::strcmp(signature.extension, "jpg") == 0) {
        return ParseJpegSize(buffer);
    } else if (std::strcmp(signature.extension, "gif") == 0) {
        return ParseGifSize(buffer);
    } else if (std::strcmp(signature.extension, "bmp") == 0) {
        return ParseBmpSize(buffer);
    } else if (std::strcmp(signature.extension, "pdf") == 0) {
        return ParsePdfSize(buffer);
    } else if (std::strcmp(signature.extension, "zip") == 0 ||
               std::strcmp(signature.extension, "docx") == 0 ||
               std::strcmp(signature.extension, "xlsx") == 0 ||
               std::strcmp(signature.extension, "pptx") == 0) {
        return ParseZipSize(buffer);
    } else if (std::strcmp(signature.extension, "mp4") == 0) {
        return ParseMp4Size(buffer);
    } else if (std::strcmp(signature.extension, "avi") == 0) {
        return ParseAviSize(buffer);
    } else if (std::strcmp(signature.extension, "wav") == 0) {
        return ParseWavSize(buffer);
    } else if (std::strcmp(signature.extension, "doc") == 0 ||
               std::strcmp(signature.extension, "xls") == 0 ||
               std::strcmp(signature.extension, "ppt") == 0) {
        return ParseOle2Size(buffer);
    } else if (std::strcmp(signature.extension, "rar") == 0) {
        return ParseRarSize(buffer);
    } else if (std::strcmp(signature.extension, "7z") == 0) {
        return Parse7zSize(buffer);
    }

    return std::nullopt;                        // Unknown format
}

// Enhanced scanning with fragmentation diagnostics and statistics.
FileCarver::DiagnosticResult FileCarver::ScanRegionWithDiagnostics(
    DiskHandle& disk,
    uint64_t startCluster,
    uint64_t clusterCount,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const std::vector<FileSignature>& signatures,
    uint64_t maxFiles)
{
    DiagnosticResult result;
    
    if (clusterCount == 0) {
        return result;                          // Nothing to scan
    }
    
    uint64_t bytesPerCluster = sectorsPerCluster * sectorSize;
    uint64_t startOffset = (clusterHeapOffset + (startCluster - 2) * sectorsPerCluster) * sectorSize;
    uint64_t regionSize = clusterCount * bytesPerCluster;
    
    const uint8_t* data = nullptr;
    uint64_t dataSize = 0;
    std::vector<uint8_t> buffer;
    bool usedMapping = false;
    
    // Try memory-mapped access first (faster)
    auto region = disk.MapDiskRegion(startOffset, regionSize);
    if (region.IsValid()) {
        data = region.data;
        dataSize = region.size;
        usedMapping = true;
    } else {
        // Fallback to traditional read
        uint64_t sectorsToRead = (regionSize + sectorSize - 1) / sectorSize;
        uint64_t startSector = startOffset / sectorSize;
        buffer = disk.ReadSectors(startSector, sectorsToRead, sectorSize);
        
        if (buffer.empty()) {
            return result;                      // Read failed
        }
        
        data = buffer.data();
        dataSize = buffer.size();
    }
    
    // Scan mapped region for file signatures with diagnostics
    for (uint64_t offset = 0; offset < dataSize && result.files.size() < maxFiles; ) {
        uint64_t currentCluster = startCluster + (offset / bytesPerCluster);
        bool foundSignature = false;
        
        // Check all signatures at current offset
        for (const auto& sig : signatures) {
            if (offset + sig.signatureSize > dataSize) {
                continue;                       // Not enough data for signature
            }
            
            if (std::memcmp(data + offset, sig.signature, sig.signatureSize) == 0) {
                result.stats.totalSignaturesFound++;
                result.stats.byFormat[sig.extension]++;
                
                // Validate file size and detect fragmentation
                size_t remainingData = static_cast<size_t>(dataSize - offset);
                size_t safeDataSize = static_cast<size_t>(std::min<uint64_t>(dataSize, SIZE_MAX));
                auto sizeValidation = ValidateFileSize(data, safeDataSize, offset, sig, bytesPerCluster);
                
                if (sizeValidation.hasSize) {
                    result.stats.filesWithKnownSize++;
                    
                    // Calculate gap between expected and actual size
                    uint64_t gap = 0;
                    if (sizeValidation.actualSize > sizeValidation.expectedSize) {
                        gap = (sizeValidation.actualSize - sizeValidation.expectedSize) / bytesPerCluster;
                    }
                    
                    if (gap > 1) {
                        result.stats.potentiallyFragmented++;
                        result.stats.fragmentedByFormat[sig.extension]++;
                        
                        if (gap > Constants::Carving::MAX_REASONABLE_GAP) {
                            result.stats.severelyFragmented++;
                        }
                    }
                    
                    if (sizeValidation.isValid) {
                        result.stats.filesWithValidatedSize++;
                    }
                } else {
                    result.stats.unknownSize++;
                }
                
                // Perform actual file carving
                auto fileSize = ParseFileSizeFromMemory(data + offset, remainingData, sig);
                
                if (fileSize.has_value() && fileSize.value() > 0) {
                    CarvedFile carved;
                    carved.signature = sig;
                    carved.startCluster = currentCluster;
                    carved.fileSize = fileSize.value();
                    result.files.push_back(carved);
                    
                    // Skip over detected file (with safety limit)
                    uint64_t detectedSize = fileSize.value();
                    uint64_t safeSkipSize = std::min(detectedSize, Constants::Carving::MAX_SAFE_SKIP);
                    uint64_t clustersUsed = (safeSkipSize + bytesPerCluster - 1) / bytesPerCluster;
                    uint64_t alignedSkip = clustersUsed * bytesPerCluster;
                    
                    offset += alignedSkip;
                    foundSignature = true;
                    break;
                }
            }
        }
        
        if (!foundSignature) {
            offset += bytesPerCluster;          // Move to next cluster
        }
    }
    
    // Clean up memory mapping if used
    if (usedMapping) {
        disk.UnmapRegion(region);
    }
    
    return result;
}

// Validate file size from header and detect potential fragmentation.
FileCarver::SizeValidation FileCarver::ValidateFileSize(
    const uint8_t* data,
    size_t dataSize,
    uint64_t offsetInData,
    const FileSignature& sig,
    uint64_t bytesPerCluster)
{
    (void)bytesPerCluster;                      // Reserved for future fragmentation analysis
    
    SizeValidation result;
    result.hasSize = false;
    result.expectedSize = 0;
    result.actualSize = 0;
    result.isValid = false;
    
    if (offsetInData >= dataSize) {
        return result;                          // Offset beyond data bounds
    }
    
    const uint8_t* fileData = data + offsetInData;
    size_t remainingSize = static_cast<size_t>(dataSize - offsetInData);
    
    if (remainingSize < 64) {
        return result;                          // Too small to parse header
    }
    
    // PNG - parse chunks to find IEND marker
    if (std::strcmp(sig.extension, "png") == 0) {
        result.hasSize = true;
        
        // PNG consists of chunks: length (4 bytes) + type (4 bytes) + data + CRC (4 bytes)
        for (size_t i = 8; i + 12 < remainingSize; ) {
            if (i + 12 > remainingSize) break;
            
            // Read chunk length (big-endian)
            uint32_t chunkLen = (static_cast<uint32_t>(fileData[i]) << 24) |
                               (static_cast<uint32_t>(fileData[i+1]) << 16) |
                               (static_cast<uint32_t>(fileData[i+2]) << 8) |
                               static_cast<uint32_t>(fileData[i+3]);
            
            // Check for IEND chunk (marks end of PNG)
            if (std::memcmp(fileData + i + 4, "IEND", 4) == 0) {
                result.actualSize = i + 12 + chunkLen;
                result.expectedSize = result.actualSize;
                result.isValid = true;
                return result;
            }
            
            i += 12 + chunkLen;
            
            // Sanity check to prevent infinite loops
            if (chunkLen > 10000000) break;
        }
        return result;
    }
    
    // BMP - file size is stored in header at offset 2
    if (std::strcmp(sig.extension, "bmp") == 0) {
        if (remainingSize >= 6) {
            result.hasSize = true;
            
            // Read 4-byte file size (little-endian)
            result.expectedSize = static_cast<uint32_t>(fileData[2]) |
                                 (static_cast<uint32_t>(fileData[3]) << 8) |
                                 (static_cast<uint32_t>(fileData[4]) << 16) |
                                 (static_cast<uint32_t>(fileData[5]) << 24);
            
            result.actualSize = result.expectedSize;
            
            // Validate size is reasonable (header + some data)
            result.isValid = (result.expectedSize > 54 && result.expectedSize < 1000000000);
        }
        return result;
    }
    
    // WAV / AVI - RIFF format with size in header
    if (std::strcmp(sig.extension, "wav") == 0 || std::strcmp(sig.extension, "avi") == 0) {
        if (remainingSize >= 8 && std::memcmp(fileData, "RIFF", 4) == 0) {
            result.hasSize = true;
            
            // Read RIFF chunk size (little-endian) + 8 bytes for header
            result.expectedSize = (static_cast<uint32_t>(fileData[4]) |
                                  (static_cast<uint32_t>(fileData[5]) << 8) |
                                  (static_cast<uint32_t>(fileData[6]) << 16) |
                                  (static_cast<uint32_t>(fileData[7]) << 24)) + 8;
            
            result.actualSize = result.expectedSize;
            
            // Validate size is reasonable
            result.isValid = (result.expectedSize > 44 && result.expectedSize < 10000000000ULL);
        }
        return result;
    }
    
    // JPEG - no size in header, must scan for EOI marker
    // ZIP - complex structure with central directory
    // Other formats - return hasSize=false
    
    return result;
}

} // namespace KVC