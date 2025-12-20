// FileCarver.cpp
#include "FileCarver.h"
#include "Constants.h"
#include <cstring>
#include <algorithm>

namespace KVC {

// ============================================================================
// SequentialReader Implementation
// ============================================================================

SequentialReader::SequentialReader(DiskHandle& disk, uint64_t startOffset, uint64_t maxSize, uint64_t sectorSize)
    : m_disk(disk)
    , m_startOffset(startOffset)
    , m_maxSize(maxSize)
    , m_position(0)
    , m_sectorSize(sectorSize)
    , m_bufferPos(0)
    , m_bufferValid(0)
{
    m_buffer.resize(BUFFER_SIZE);
}

void SequentialReader::FillBuffer() {
    uint64_t diskOffset = m_startOffset + m_position;
    uint64_t remaining = m_maxSize - m_position;
    
    if (remaining == 0) {
        m_bufferValid = 0;
        return;
    }
    
    // Calculate how much to read (min of buffer size and remaining bytes)
    uint64_t toRead = std::min<uint64_t>(BUFFER_SIZE, remaining);
    uint64_t startSector = diskOffset / m_sectorSize;
    // Read extra sector to handle misalignment
    uint64_t sectorsNeeded = (toRead + m_sectorSize - 1) / m_sectorSize + 1;
    
    auto data = m_disk.ReadSectors(startSector, sectorsNeeded, m_sectorSize);
    
    if (data.empty()) {
        m_bufferValid = 0;
        return;
    }
    
    // Handle sector alignment - extract bytes starting at our offset
    uint64_t offsetInSector = diskOffset % m_sectorSize;
    size_t available = data.size() > offsetInSector ? data.size() - static_cast<size_t>(offsetInSector) : 0;
    size_t toCopy = std::min<size_t>(available, static_cast<size_t>(toRead));
    
    std::memcpy(m_buffer.data(), data.data() + offsetInSector, toCopy);
    m_bufferValid = toCopy;
    m_bufferPos = 0;
}

bool SequentialReader::ReadByte(uint8_t& byte) {
    if (m_position >= m_maxSize) {
        return false;
    }
    
    // Refill buffer if exhausted
    if (m_bufferPos >= m_bufferValid) {
        FillBuffer();
        if (m_bufferValid == 0) {
            return false;
        }
    }
    
    byte = m_buffer[m_bufferPos++];
    m_position++;
    return true;
}

size_t SequentialReader::Read(uint8_t* buffer, size_t count) {
    size_t totalRead = 0;
    
    while (totalRead < count && m_position < m_maxSize) {
        // Refill internal buffer if needed
        if (m_bufferPos >= m_bufferValid) {
            FillBuffer();
            if (m_bufferValid == 0) {
                break;
            }
        }
        
        // Copy as much as possible from current buffer
        size_t available = m_bufferValid - m_bufferPos;
        size_t toRead = std::min(available, count - totalRead);
        
        std::memcpy(buffer + totalRead, m_buffer.data() + m_bufferPos, toRead);
        m_bufferPos += toRead;
        m_position += toRead;
        totalRead += toRead;
    }
    
    return totalRead;
}

bool SequentialReader::Skip(uint64_t count) {
    if (m_position + count > m_maxSize) {
        m_position = m_maxSize;
        m_bufferValid = 0;
        return false;
    }
    
    // Optimization: if skip is within current buffer, just advance pointer
    uint64_t bufferRemaining = m_bufferValid - m_bufferPos;
    if (count <= bufferRemaining) {
        m_bufferPos += static_cast<size_t>(count);
        m_position += count;
        return true;
    }
    
    // Skip beyond buffer - invalidate and update position
    m_position += count;
    m_bufferValid = 0;
    m_bufferPos = 0;
    return true;
}

// ============================================================================
// FileCarver Implementation
// ============================================================================

FileCarver::FileCarver() = default;
FileCarver::~FileCarver() = default;

// Scan a single cluster for known file signatures.
std::optional<FileSignature> FileCarver::ScanClusterForSignature(
    DiskHandle& disk,
    uint64_t cluster,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const std::vector<FileSignature>& signatures,
    bool useNTFSAddressing)
{
    // For NTFS, cluster 0 is valid (boot sector); for FAT/exFAT, cluster < 2 is invalid
    if (!useNTFSAddressing && cluster < 2) {
        return std::nullopt;                    // Invalid cluster number for FAT/exFAT
    }

    // CRITICAL: Different addressing schemes for NTFS vs FAT/exFAT
    // NTFS: Cluster numbers are absolute LCNs from partition start
    // FAT/exFAT: Cluster 2 is first data cluster (0,1 are reserved)
    uint64_t sector;
    if (useNTFSAddressing) {
        sector = clusterHeapOffset + (cluster * sectorsPerCluster);
    } else {
        sector = clusterHeapOffset + ((cluster - 2) * sectorsPerCluster);
    }
    
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
    const FileSignature& signature,
    bool useNTFSAddressing)
{
    // CRITICAL: Use correct addressing for NTFS vs FAT/exFAT
    uint64_t sector;
    if (useNTFSAddressing) {
        // NTFS mode: cluster numbers are absolute LCNs
        sector = clusterHeapOffset + (cluster * sectorsPerCluster);
    } else {
        // FAT/exFAT mode: subtract 2 and add heap offset
        sector = clusterHeapOffset + ((cluster - 2) * sectorsPerCluster);
    }
    
    // Read 256KB for header parsing (enough for most file format headers)
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

// ============================================================================
// Sequential Format Parsers (Digler-style)
// ============================================================================

// Parse file end using sequential reading (allows handling files beyond buffer size)
std::optional<uint64_t> FileCarver::ParseFileEnd(
    SequentialReader& reader,
    const FileSignature& signature)
{
    // Dispatch to format-specific sequential parser
    if (std::strcmp(signature.extension, "jpg") == 0) {
        return ParseJpegEnd(reader);
    } else if (std::strcmp(signature.extension, "png") == 0) {
        return ParsePngEnd(reader);
    } else if (std::strcmp(signature.extension, "pdf") == 0) {
        return ParsePdfEnd(reader);
    } else if (std::strcmp(signature.extension, "zip") == 0 ||
               std::strcmp(signature.extension, "docx") == 0 ||
               std::strcmp(signature.extension, "xlsx") == 0 ||
               std::strcmp(signature.extension, "pptx") == 0) {
        return ParseZipEnd(reader);
    } else if (std::strcmp(signature.extension, "mp4") == 0) {
        return ParseMp4End(reader);
    } else if (std::strcmp(signature.extension, "gif") == 0) {
        return ParseGifEnd(reader);
    } else if (std::strcmp(signature.extension, "bmp") == 0) {
        return ParseBmpEnd(reader);
    }
    
    return std::nullopt;
}

// JPEG: Parse segment structure to find true EOI marker (Digler-style).
// Handles byte stuffing (0xFF 0x00), restart markers, and entropy-coded data.
std::optional<uint64_t> FileCarver::ParseJpegEnd(SequentialReader& reader) {
    uint8_t tmp[2];
    
    // Check for SOI marker (Start of Image: 0xFF 0xD8)
    if (reader.Read(tmp, 2) != 2) {
        return std::nullopt;
    }
    
    if (tmp[0] != 0xFF || tmp[1] != 0xD8) {
        return std::nullopt;                    // Missing SOI marker
    }
    
    constexpr uint8_t EOI_MARKER = 0xD9;        // End of Image
    constexpr uint8_t SOS_MARKER = 0xDA;        // Start of Scan (entropy-coded data follows)
    constexpr uint8_t RST0_MARKER = 0xD0;       // Restart markers (no payload)
    constexpr uint8_t RST7_MARKER = 0xD7;
        
    // Process segments until EOI
    while (!reader.AtEOF()) {
        if (reader.Read(tmp, 2) != 2) {
            return std::nullopt;
        }
        
        // Find 0xFF marker prefix
        while (tmp[0] != 0xFF) {
            tmp[0] = tmp[1];
            if (!reader.ReadByte(tmp[1])) {
                return std::nullopt;
            }
        }
        
        uint8_t marker = tmp[1];
        
        // Handle byte stuffing (0xFF 0x00 = literal 0xFF in data)
        if (marker == 0x00) {
            continue;
        }
        
        // Skip fill bytes (multiple 0xFF in sequence)
        while (marker == 0xFF) {
            if (!reader.ReadByte(marker)) {
                return std::nullopt;
            }
        }
        
        // Check for EOI (end of file)
        if (marker == EOI_MARKER) {
            return reader.Position();
        }
        
        // Restart markers have no payload - continue scanning
        if (marker >= RST0_MARKER && marker <= RST7_MARKER) {
            continue;
        }
        
        // Read segment length (for markers with payload)
        if (reader.Read(tmp, 2) != 2) {
            return std::nullopt;
        }
        
        // Segment length is big-endian, includes length bytes themselves
        int segmentLen = (static_cast<int>(tmp[0]) << 8) + static_cast<int>(tmp[1]) - 2;
        if (segmentLen < 0) {
            return std::nullopt;                // Invalid segment length
        }
        
        // Skip segment data
        if (!reader.Skip(static_cast<uint64_t>(segmentLen))) {
            return std::nullopt;
        }
        
        // After SOS marker, scan entropy-coded data for next marker
        // This is the actual image data - markers can appear but need special handling
        if (marker == SOS_MARKER) {
            while (!reader.AtEOF()) {
                uint8_t byte;
                if (!reader.ReadByte(byte)) {
                    return std::nullopt;
                }
                
                if (byte == 0xFF) {
                    uint8_t nextByte;
                    if (!reader.ReadByte(nextByte)) {
                        return std::nullopt;
                    }
                    
                    // Byte stuffing (0xFF 0x00 = literal 0xFF)
                    if (nextByte == 0x00) {
                        continue;
                    }
                    
                    // Restart markers within scan data
                    if (nextByte >= RST0_MARKER && nextByte <= RST7_MARKER) {
                        continue;
                    }
                    
                    // Fill bytes
                    if (nextByte == 0xFF) {
                        // Put back to process in outer loop
                        continue;
                    }
                    
                    // Found real marker - check if EOI
                    if (nextByte == EOI_MARKER) {
                        return reader.Position();
                    }
                    
                    // Other marker - will be processed in next iteration
                    break;
                }
            }
        }
    }
    
    return std::nullopt;
}

// PNG: Parse chunk structure to find IEND (Digler-style).
std::optional<uint64_t> FileCarver::ParsePngEnd(SequentialReader& reader) {
    uint8_t header[8];
    
    // Verify PNG signature (8 bytes)
    if (reader.Read(header, 8) != 8) {
        return std::nullopt;
    }
    
    const uint8_t pngSig[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (std::memcmp(header, pngSig, 8) != 0) {
        return std::nullopt;
    }
    
    // Parse chunks: each chunk = length(4) + type(4) + data(length) + CRC(4)
    while (!reader.AtEOF()) {
        uint8_t chunkHeader[8];
        if (reader.Read(chunkHeader, 8) != 8) {
            return std::nullopt;
        }
        
        // Chunk length (big-endian)
        uint32_t chunkLen = (static_cast<uint32_t>(chunkHeader[0]) << 24) |
                           (static_cast<uint32_t>(chunkHeader[1]) << 16) |
                           (static_cast<uint32_t>(chunkHeader[2]) << 8) |
                           static_cast<uint32_t>(chunkHeader[3]);
        
        // Sanity check to prevent infinite loops on corrupted data
        if (chunkLen > 100 * 1024 * 1024) {
            return std::nullopt;
        }
        
        // Check for IEND chunk (marks end of PNG)
        if (std::memcmp(chunkHeader + 4, "IEND", 4) == 0) {
            // Skip chunk data + CRC (4 bytes)
            if (!reader.Skip(chunkLen + 4)) {
                return std::nullopt;
            }
            return reader.Position();
        }
        
        // Skip chunk data + CRC (4 bytes)
        if (!reader.Skip(chunkLen + 4)) {
            return std::nullopt;
        }
    }
    
    return std::nullopt;
}
// PDF: Find last %%EOF marker (Digler-style with max file size).
std::optional<uint64_t> FileCarver::ParsePdfEnd(SequentialReader& reader) {
    uint8_t header[5];
    
    // Verify PDF signature
    if (reader.Read(header, 5) != 5) {
        return std::nullopt;
    }
    
    if (std::memcmp(header, "%PDF-", 5) != 0) {
        return std::nullopt;
    }
    
    constexpr uint64_t MAX_PDF_SIZE = 64 * 1024 * 1024;  // 64MB limit for scanning
    
    // Search for %%EOF marker (can appear multiple times in incremental updates)
    uint64_t lastEofPos = 0;
    uint8_t searchBuf[5] = {0};
    
    while (!reader.AtEOF() && reader.Position() < MAX_PDF_SIZE) {
        // Maintain a 5-byte sliding window to search for "%%EOF"
        std::memmove(searchBuf, searchBuf + 1, 4);
        
        if (!reader.ReadByte(searchBuf[4])) {
            break;
        }
        
        // Check if we found "%%EOF"
        if (std::memcmp(searchBuf, "%%EOF", 5) == 0) {
            lastEofPos = reader.Position();
        }
    }
    
    if (lastEofPos > 0) {
        return lastEofPos;
    }
    
    return std::nullopt;
}

// ZIP: Find end of central directory (Digler-style).
std::optional<uint64_t> FileCarver::ParseZipEnd(SequentialReader& reader) {
    uint8_t header[4];
    
    // Verify ZIP signature (local file header)
    if (reader.Read(header, 4) != 4) {
        return std::nullopt;
    }
    
    const uint8_t zipSig[] = {0x50, 0x4B, 0x03, 0x04};
    if (std::memcmp(header, zipSig, 4) != 0) {
        return std::nullopt;
    }
    
    constexpr uint64_t MAX_ZIP_SIZE = 100 * 1024 * 1024;  // 100MB limit
    
    // Search for EOCD signature (0x50 0x4B 0x05 0x06)
    uint8_t searchBuf[4] = {0};
    uint64_t eocdPos = 0;
    
    while (!reader.AtEOF() && reader.Position() < MAX_ZIP_SIZE) {
        // Maintain a 4-byte sliding window
        std::memmove(searchBuf, searchBuf + 1, 3);
        
        if (!reader.ReadByte(searchBuf[3])) {
            break;
        }
        
        // Check for End of Central Directory signature
        if (searchBuf[0] == 0x50 && searchBuf[1] == 0x4B &&
            searchBuf[2] == 0x05 && searchBuf[3] == 0x06) {
            eocdPos = reader.Position() - 4;
        }
    }
    
    if (eocdPos > 0) {
        // EOCD is 22 bytes minimum + optional comment
        // Comment length is at offset 20-21 from EOCD start
        return eocdPos + 22;  // Simplified - doesn't include comment
    }
    
    return std::nullopt;
}

// MP4: Parse atom structure (Digler-style).
std::optional<uint64_t> FileCarver::ParseMp4End(SequentialReader& reader) {
    uint8_t header[8];
    
    // Read first atom header
    if (reader.Read(header, 8) != 8) {
        return std::nullopt;
    }
    
    // Verify ftyp atom (file type box - must be first)
    if (std::memcmp(header + 4, "ftyp", 4) != 0) {
        return std::nullopt;
    }
    
    // Get ftyp size and skip it
    uint32_t ftypSize = (static_cast<uint32_t>(header[0]) << 24) |
                        (static_cast<uint32_t>(header[1]) << 16) |
                        (static_cast<uint32_t>(header[2]) << 8) |
                        static_cast<uint32_t>(header[3]);
    
    if (ftypSize < 8) {
        return std::nullopt;
    }
    
    if (!reader.Skip(ftypSize - 8)) {
        return std::nullopt;
    }
    
    uint64_t totalSize = ftypSize;
    
    // Parse remaining top-level atoms (moov, mdat, etc.)
    while (!reader.AtEOF()) {
        if (reader.Read(header, 8) != 8) {
            break;  // EOF - return what we have
        }
        
        uint64_t atomSize = (static_cast<uint32_t>(header[0]) << 24) |
                            (static_cast<uint32_t>(header[1]) << 16) |
                            (static_cast<uint32_t>(header[2]) << 8) |
                            static_cast<uint32_t>(header[3]);
        
        // Size 0 means atom extends to EOF
        if (atomSize == 0) {
            return reader.Position();  // Current position is the answer
        }
        
        // Size 1 means 64-bit extended size follows
        if (atomSize == 1) {
            uint8_t extSize[8];
            if (reader.Read(extSize, 8) != 8) {
                break;
            }
            
            // Read 64-bit size (big-endian)
            atomSize = (static_cast<uint64_t>(extSize[0]) << 56) |
                       (static_cast<uint64_t>(extSize[1]) << 48) |
                       (static_cast<uint64_t>(extSize[2]) << 40) |
                       (static_cast<uint64_t>(extSize[3]) << 32) |
                       (static_cast<uint64_t>(extSize[4]) << 24) |
                       (static_cast<uint64_t>(extSize[5]) << 16) |
                       (static_cast<uint64_t>(extSize[6]) << 8) |
                       static_cast<uint64_t>(extSize[7]);
            
            if (atomSize < 16) {
                break;
            }
            
            totalSize += atomSize;
            if (!reader.Skip(atomSize - 16)) {
                return totalSize;  // Partial file
            }
        } else {
            if (atomSize < 8) {
                break;
            }
            
            totalSize += atomSize;
            if (!reader.Skip(atomSize - 8)) {
                return totalSize;  // Partial file
            }
        }
    }
    
    if (totalSize > 0) {
        return totalSize;
    }
    
    return std::nullopt;
}

// GIF: Find trailer 0x3B (Digler-style).
std::optional<uint64_t> FileCarver::ParseGifEnd(SequentialReader& reader) {
    uint8_t header[6];
    
    // Verify GIF signature (GIF87a or GIF89a)
    if (reader.Read(header, 6) != 6) {
        return std::nullopt;
    }
    
    if (std::memcmp(header, "GIF8", 4) != 0) {
        return std::nullopt;
    }
    
    constexpr uint64_t MAX_GIF_SIZE = 50 * 1024 * 1024;  // 50MB limit
    
    // Search for trailer byte (0x3B marks end of GIF)
    uint8_t byte;
    while (!reader.AtEOF() && reader.Position() < MAX_GIF_SIZE) {
        if (!reader.ReadByte(byte)) {
            break;
        }
        
        if (byte == 0x3B) {
            return reader.Position();
        }
    }
    
    return std::nullopt;
}

// BMP: Read size from header.
std::optional<uint64_t> FileCarver::ParseBmpEnd(SequentialReader& reader) {
    uint8_t header[6];
    
    // Read BMP header
    if (reader.Read(header, 6) != 6) {
        return std::nullopt;
    }
    
    // Verify BM signature
    if (header[0] != 0x42 || header[1] != 0x4D) {
        return std::nullopt;
    }
    
    // File size at offset 2 (little-endian)
    uint32_t fileSize = static_cast<uint32_t>(header[2]) |
                       (static_cast<uint32_t>(header[3]) << 8) |
                       (static_cast<uint32_t>(header[4]) << 16) |
                       (static_cast<uint32_t>(header[5]) << 24);
    
    return fileSize;
}

// ============================================================================
// Header-based Parsers (kept for compatibility)
// ============================================================================

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

        // Sanity check to prevent reading corrupted data
        if (chunkLen > 100 * 1024 * 1024) {
            return std::nullopt;
        }

        // Check if IEND chunk (marks end of PNG)
        if (std::memcmp(data.data() + offset + 4, "IEND", 4) == 0) {
            return offset + 12 + chunkLen;
        }

        offset += 12 + chunkLen;
    }

    return std::nullopt;
}

// JPEG: Parse segment structure to find true EOI marker (Digler-style).
std::optional<uint64_t> FileCarver::ParseJpegSize(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return std::nullopt;
    }

    // Verify JPEG SOI marker (Start of Image)
    if (data[0] != 0xFF || data[1] != 0xD8) {
        return std::nullopt;
    }

    constexpr uint8_t SOI_MARKER = 0xD8;        // Start of Image
    constexpr uint8_t EOI_MARKER = 0xD9;        // End of Image
    constexpr uint8_t SOS_MARKER = 0xDA;        // Start of Scan
    constexpr uint8_t RST0_MARKER = 0xD0;       // Restart markers
    constexpr uint8_t RST7_MARKER = 0xD7;

    size_t pos = 2;

    while (pos < data.size()) {
        // Find next marker (0xFF prefix)
        while (pos < data.size() && data[pos] != 0xFF) {
            pos++;
        }
        
        if (pos >= data.size()) {
            return std::nullopt;
        }

        // Skip padding 0xFF bytes
        while (pos < data.size() && data[pos] == 0xFF) {
            pos++;
        }

        if (pos >= data.size()) {
            return std::nullopt;
        }

        uint8_t marker = data[pos];
        pos++;

        // Byte stuffing (0xFF 0x00 = literal 0xFF in data)
        if (marker == 0x00) {
            continue;
        }

        // EOI marker - end of file
        if (marker == EOI_MARKER) {
            return pos;
        }

        // Restart markers have no payload
        if (marker >= RST0_MARKER && marker <= RST7_MARKER) {
            continue;
        }

        // Standalone markers (no payload)
        if (marker == SOI_MARKER || marker == 0x01) {
            continue;
        }

        // Read segment length (big-endian, includes length bytes)
        if (pos + 2 > data.size()) {
            return std::nullopt;
        }

        uint16_t segmentLen = (static_cast<uint16_t>(data[pos]) << 8) |
                              static_cast<uint16_t>(data[pos + 1]);

        if (segmentLen < 2) {
            return std::nullopt;
        }

        pos += segmentLen;

        // After SOS marker, scan entropy-coded data for next real marker
        if (marker == SOS_MARKER) {
            while (pos < data.size() - 1) {
                if (data[pos] == 0xFF) {
                    uint8_t nextByte = data[pos + 1];
                    
                    // Byte stuffing
                    if (nextByte == 0x00) {
                        pos += 2;
                        continue;
                    }
                    
                    // Restart markers
                    if (nextByte >= RST0_MARKER && nextByte <= RST7_MARKER) {
                        pos += 2;
                        continue;
                    }
                    
                    // Fill bytes
                    if (nextByte == 0xFF) {
                        pos++;
                        continue;
                    }
                    
                    // Found real marker - exit scan loop
                    break;
                }
                pos++;
            }
        }
    }

    return std::nullopt;
}
// GIF: Find trailer (0x3B).
std::optional<uint64_t> FileCarver::ParseGifSize(const std::vector<uint8_t>& data) {
    if (data.size() < 6) {
        return std::nullopt;
    }

    // Verify GIF signature
    if (std::memcmp(data.data(), "GIF8", 4) != 0) {
        return std::nullopt;
    }

    // Search from end for trailer (more efficient for complete files)
    for (size_t i = data.size(); i > 6; i--) {
        if (data[i - 1] == 0x3B) {
            return i;
        }
    }

    return std::nullopt;
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

// PDF: Find LAST %%EOF marker (PDFs can have multiple for incremental updates).
std::optional<uint64_t> FileCarver::ParsePdfSize(const std::vector<uint8_t>& data) {
    if (data.size() < 9) {
        return std::nullopt;
    }

    // Verify PDF signature
    if (std::memcmp(data.data(), "%PDF", 4) != 0) {
        return std::nullopt;
    }

    const char* eofMarker = "%%EOF";
    size_t markerLen = 5;
    
    // Search backwards to find LAST %%EOF
    for (size_t i = data.size(); i >= markerLen; i--) {
        if (std::memcmp(data.data() + i - markerLen, eofMarker, markerLen) == 0) {
            // Skip trailing whitespace after %%EOF
            size_t endPos = i;
            while (endPos < data.size() && 
                   (data[endPos] == '\r' || data[endPos] == '\n' || data[endPos] == ' ')) {
                endPos++;
            }
            return endPos;
        }
    }

    return std::nullopt;
}

// ZIP: Find end of central directory (scan backwards from end).
std::optional<uint64_t> FileCarver::ParseZipSize(const std::vector<uint8_t>& data) {
    if (data.size() < 22) {
        return std::nullopt;
    }

    // Verify ZIP signature
    const uint8_t zipSig[] = {0x50, 0x4B, 0x03, 0x04};
    if (std::memcmp(data.data(), zipSig, 4) != 0) {
        return std::nullopt;
    }

    // Search backwards for EOCD signature (0x50 0x4B 0x05 0x06)
    for (size_t i = data.size(); i >= 22; i--) {
        size_t pos = i - 22;
        if (data[pos] == 0x50 && data[pos + 1] == 0x4B && 
            data[pos + 2] == 0x05 && data[pos + 3] == 0x06) {
            
            // Read comment length (little-endian)
            uint16_t commentLen = static_cast<uint16_t>(data[pos + 20]) |
                                 (static_cast<uint16_t>(data[pos + 21]) << 8);
            
            uint64_t totalSize = pos + 22 + commentLen;
            if (totalSize <= data.size()) {
                return totalSize;
            }
        }
    }

    return std::nullopt;
}

// MP4: Parse atom structure (box-based format).
std::optional<uint64_t> FileCarver::ParseMp4Size(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    // Verify ftyp atom (file type box must be first)
    if (std::memcmp(data.data() + 4, "ftyp", 4) != 0) {
        return std::nullopt;
    }

    uint64_t totalSize = 0;
    size_t offset = 0;
    
    // Sum all top-level atom sizes
    while (offset + 8 <= data.size()) {
        // Read atom size (big-endian)
        uint32_t atomSize32 = (static_cast<uint32_t>(data[offset]) << 24) |
                              (static_cast<uint32_t>(data[offset + 1]) << 16) |
                              (static_cast<uint32_t>(data[offset + 2]) << 8) |
                              static_cast<uint32_t>(data[offset + 3]);
        
        uint64_t atomSize = atomSize32;
        size_t headerSize = 8;

        // Size 0 means atom extends to EOF
        if (atomSize32 == 0) {
            return data.size();
        }

        // Size 1 means 64-bit extended size follows
        if (atomSize32 == 1) {
            if (offset + 16 > data.size()) {
                break;
            }
            // Read 64-bit size (big-endian)
            atomSize = (static_cast<uint64_t>(data[offset + 8]) << 56) |
                       (static_cast<uint64_t>(data[offset + 9]) << 48) |
                       (static_cast<uint64_t>(data[offset + 10]) << 40) |
                       (static_cast<uint64_t>(data[offset + 11]) << 32) |
                       (static_cast<uint64_t>(data[offset + 12]) << 24) |
                       (static_cast<uint64_t>(data[offset + 13]) << 16) |
                       (static_cast<uint64_t>(data[offset + 14]) << 8) |
                       static_cast<uint64_t>(data[offset + 15]);
            headerSize = 16;
        }

        // Sanity check: validate atom size is reasonable
        if (atomSize < headerSize || atomSize > 100ULL * 1024 * 1024 * 1024) {
            break;
        }

        totalSize = offset + atomSize;
        offset += static_cast<size_t>(atomSize);

        // If atom extends beyond buffer, return accumulated size
        if (offset > data.size()) {
            return totalSize;
        }
    }
    
    if (totalSize > 0) {
        return totalSize;
    }

    return std::nullopt;
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

    // File size at offset 4 (little-endian) + 8 bytes for RIFF header
    uint32_t riffSize = static_cast<uint32_t>(data[4]) |
                       (static_cast<uint32_t>(data[5]) << 8) |
                       (static_cast<uint32_t>(data[6]) << 16) |
                       (static_cast<uint32_t>(data[7]) << 24);

    return riffSize + 8;
}

// WAV: Same as AVI (both use RIFF container format).
std::optional<uint64_t> FileCarver::ParseWavSize(const std::vector<uint8_t>& data) {
    return ParseAviSize(data);                  // Reuse RIFF parser
}

// OLE2: Parse sector allocation table for file size (used by .doc, .xls, .ppt).
std::optional<uint64_t> FileCarver::ParseOle2Size(const std::vector<uint8_t>& data) {
    if (data.size() < 512) {
        return std::nullopt;
    }

    // Verify OLE2 signature (Compound File Binary Format)
    const uint8_t ole2Sig[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    if (std::memcmp(data.data(), ole2Sig, 8) != 0) {
        return std::nullopt;
    }

    // Read sector size from header (offset 30, 2 bytes)
    uint16_t sectorShift = static_cast<uint16_t>(data[30]) |
                          (static_cast<uint16_t>(data[31]) << 8);
    uint32_t sectorSize = 1 << sectorShift;

    // Read total sectors from header (offset 80, 4 bytes)
    uint32_t totalSectors = static_cast<uint32_t>(data[80]) |
                           (static_cast<uint32_t>(data[81]) << 8) |
                           (static_cast<uint32_t>(data[82]) << 16) |
                           (static_cast<uint32_t>(data[83]) << 24);

    // Validate sector count is reasonable
    if (totalSectors > 0 && totalSectors < 1000000) {
        return static_cast<uint64_t>(totalSectors) * sectorSize;
    }

    return std::nullopt;
}

// RAR: Complex archive format (too complex for simple size detection).
std::optional<uint64_t> FileCarver::ParseRarSize(const std::vector<uint8_t>& data) {
    if (data.size() < 7) {
        return std::nullopt;
    }

    // Verify RAR signature
    const uint8_t rarSig[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
    if (std::memcmp(data.data(), rarSig, 6) != 0) {
        return std::nullopt;
    }

    // RAR has complex multi-volume structure - return nullopt for cluster estimation
    return std::nullopt;
}

// 7z: Complex archive format (too complex for simple size detection).
std::optional<uint64_t> FileCarver::Parse7zSize(const std::vector<uint8_t>& data) {
    if (data.size() < 32) {
        return std::nullopt;
    }

    // Verify 7z signature
    const uint8_t sig7z[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
    if (std::memcmp(data.data(), sig7z, 6) != 0) {
        return std::nullopt;
    }

    // 7z has complex header structure - return nullopt for cluster estimation
    return std::nullopt;
}

// ============================================================================
// Memory-Mapped Scanning
// ============================================================================

// Scan disk region using memory-mapped I/O for optimal performance.
std::vector<FileCarver::CarvedFile> FileCarver::ScanRegionMemoryMapped(
    DiskHandle& disk,
    uint64_t startCluster,
    uint64_t clusterCount,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const std::vector<FileSignature>& signatures,
    uint64_t maxFiles,
    bool useNTFSAddressing)
{
    std::vector<CarvedFile> results;
    
    if (clusterCount == 0) {
        return results;                         // Nothing to scan
    }
    
    uint64_t bytesPerCluster = sectorsPerCluster * sectorSize;
    uint64_t startOffset;
    
    // CRITICAL: Use correct addressing for NTFS vs FAT/exFAT
    if (useNTFSAddressing) {
        // NTFS: LCN (Logical Cluster Number) is absolute from partition start
        startOffset = (clusterHeapOffset + startCluster * sectorsPerCluster) * sectorSize;
    } else {
        // FAT/exFAT: Cluster 2 is first data cluster (0,1 reserved)
        startOffset = (clusterHeapOffset + (startCluster - 2) * sectorsPerCluster) * sectorSize;
    }
    
    uint64_t regionSize = clusterCount * bytesPerCluster;
    
    const uint8_t* data = nullptr;
    uint64_t dataSize = 0;
    std::vector<uint8_t> buffer;
    bool usedMapping = false;
    
    // Try memory-mapped access first (much faster than ReadSectors)
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
                    
                    // Skip over detected file (with safety limit to prevent huge skips)
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
    if (dataSize < 8) {
        return std::nullopt;
    }

    // Create vector view for compatibility with existing parsers
    std::vector<uint8_t> buffer(data, data + dataSize);
    
    // Dispatch to appropriate format parser
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

// ============================================================================
// Diagnostics
// ============================================================================

// Enhanced scanning with fragmentation diagnostics and statistics.
FileCarver::DiagnosticResult FileCarver::ScanRegionWithDiagnostics(
    DiskHandle& disk,
    uint64_t startCluster,
    uint64_t clusterCount,
    uint64_t sectorsPerCluster,
    uint64_t clusterHeapOffset,
    uint64_t sectorSize,
    const std::vector<FileSignature>& signatures,
    uint64_t maxFiles,
    bool useNTFSAddressing)
{
    DiagnosticResult result;
    
    if (clusterCount == 0) {
        return result;                          // Nothing to scan
    }
    
    uint64_t bytesPerCluster = sectorsPerCluster * sectorSize;
    uint64_t startOffset;
    
    // CRITICAL: Use correct addressing for NTFS vs FAT/exFAT
    if (useNTFSAddressing) {
        startOffset = (clusterHeapOffset + startCluster * sectorsPerCluster) * sectorSize;
    } else {
        startOffset = (clusterHeapOffset + (startCluster - 2) * sectorsPerCluster) * sectorSize;
    }
    
    uint64_t regionSize = clusterCount * bytesPerCluster;
    
    const uint8_t* data = nullptr;
    uint64_t dataSize = 0;
    std::vector<uint8_t> buffer;
    bool usedMapping = false;
    
    // Try memory-mapped access first
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
    
    // Scan with diagnostic collection
    for (uint64_t offset = 0; offset < dataSize && result.files.size() < maxFiles; ) {
        uint64_t currentCluster = startCluster + (offset / bytesPerCluster);
        bool foundSignature = false;
        
        for (const auto& sig : signatures) {
            if (offset + sig.signatureSize > dataSize) {
                continue;
            }
            
            if (std::memcmp(data + offset, sig.signature, sig.signatureSize) == 0) {
                // Collect diagnostic statistics
                result.stats.totalSignaturesFound++;
                result.stats.byFormat[sig.extension]++;
                
                size_t remainingData = static_cast<size_t>(dataSize - offset);
                size_t safeDataSize = static_cast<size_t>(std::min<uint64_t>(dataSize, SIZE_MAX));
                auto sizeValidation = ValidateFileSize(data, safeDataSize, offset, sig, bytesPerCluster);
                
                if (sizeValidation.hasSize) {
                    result.stats.filesWithKnownSize++;
                    
                    // Calculate gap between expected and actual size (fragmentation indicator)
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
                    
                    // Skip over detected file with safety limit
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
            offset += bytesPerCluster;
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
        
        // PNG chunks: length(4) + type(4) + data + CRC(4)
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
            if (chunkLen > 100 * 1024 * 1024) break;
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
            
            // Validate size is reasonable (header=54 bytes minimum)
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
            
            // Validate size is reasonable (WAV header=44 bytes minimum)
            result.isValid = (result.expectedSize > 44 && result.expectedSize < 10000000000ULL);
        }
        return result;
    }
    
    // JPEG - no size in header, must scan for EOI marker
    // ZIP - complex structure with central directory
    // Other formats - return hasSize=false for cluster-based estimation
    
    return result;
}

} // namespace KVC