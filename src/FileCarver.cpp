// ============================================================================
// FileCarver.cpp - Complete Rewrite with VolumeReader Integration
// ============================================================================


#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "FileCarver.h"
#include "Constants.h"
#include "StringUtils.h"

#include <climits>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <atomic>
#include <unordered_set>
#include <optional>

namespace KVC {

// ============================================================================
// SequentialReader Implementation - Fragment-Aware
// ============================================================================

SequentialReader::SequentialReader(DiskHandle& disk, uint64_t startOffset, uint64_t maxSize, uint64_t sectorSize)
    : m_disk(disk)
    , m_startOffset(startOffset)
    , m_maxSize(maxSize)
    , m_position(0)
    , m_sectorSize(sectorSize)
    , m_volumeStartOffset(0)
    , m_fragmentMode(false)
    , m_bufferPos(0)
    , m_bufferValid(0)
    , m_bufferFileOffset(0)
{
    m_buffer.resize(BUFFER_SIZE);
}

SequentialReader::SequentialReader(DiskHandle& disk, const FragmentMap& fragments, uint64_t sectorSize, uint64_t volumeStartOffset)
    : m_disk(disk)
    , m_startOffset(0)
    , m_maxSize(fragments.TotalSize())
    , m_position(0)
    , m_sectorSize(sectorSize)
    , m_volumeStartOffset(volumeStartOffset)
    , m_fragmentMode(true)
    , m_fragments(fragments)
    , m_bufferPos(0)
    , m_bufferValid(0)
    , m_bufferFileOffset(0)
{
    m_buffer.resize(BUFFER_SIZE);
}

SequentialReader::SequentialReader(DiskHandle& disk, FragmentMap&& fragments, uint64_t sectorSize, uint64_t volumeStartOffset)
    : m_disk(disk)
    , m_startOffset(0)
    , m_maxSize(fragments.TotalSize())
    , m_position(0)
    , m_sectorSize(sectorSize)
    , m_volumeStartOffset(volumeStartOffset)
    , m_fragmentMode(true)
    , m_fragments(std::move(fragments))
    , m_bufferPos(0)
    , m_bufferValid(0)
    , m_bufferFileOffset(0)
{
    m_buffer.resize(BUFFER_SIZE);
}

std::optional<uint64_t> SequentialReader::TranslatePositionToDisk() const {
    if (!m_fragmentMode) {
        return m_startOffset + m_position;
    }

    auto loc = m_fragments.TranslateOffset(m_position);
    if (!loc.valid) {
        return std::nullopt;
    }

    uint64_t bytesPerCluster = m_fragments.BytesPerCluster();
    uint64_t sectorsPerCluster = bytesPerCluster / m_sectorSize;

    return m_volumeStartOffset + (loc.cluster * sectorsPerCluster * m_sectorSize) + loc.offsetInCluster;
}

void SequentialReader::FillBuffer() {
    if (m_fragmentMode) {
        FillBufferFragmented();
    } else {
        FillBufferLinear();
    }
}

void SequentialReader::FillBufferLinear() {
    uint64_t diskOffset = m_startOffset + m_position;
    uint64_t remaining = m_maxSize - m_position;

    if (remaining == 0) {
        m_bufferValid = 0;
        return;
    }

    uint64_t toRead = std::min<uint64_t>(BUFFER_SIZE, remaining);

    // FIX: Calculate offset BEFORE reading
    uint64_t offsetInSector = diskOffset % m_sectorSize;
    uint64_t startSector = diskOffset / m_sectorSize;

    // FIX: No unconditional +1
    uint64_t sectorsNeeded = (offsetInSector + toRead + m_sectorSize - 1) / m_sectorSize;

    auto data = m_disk.ReadSectors(startSector, sectorsNeeded, m_sectorSize);

    if (data.empty()) {
        m_bufferValid = 0;
        return;
    }

    size_t available = data.size() > offsetInSector ? data.size() - static_cast<size_t>(offsetInSector) : 0;
    size_t toCopy = std::min<size_t>(available, static_cast<size_t>(toRead));

    std::memcpy(m_buffer.data(), data.data() + offsetInSector, toCopy);
    m_bufferValid = toCopy;
    m_bufferPos = 0;
    m_bufferFileOffset = m_position;
}

void SequentialReader::FillBufferFragmented() {
    uint64_t remaining = m_maxSize - m_position;

    if (remaining == 0) {
        m_bufferValid = 0;
        return;
    }

    size_t bufferFilled = 0;
    uint64_t currentPos = m_position;

    while (bufferFilled < BUFFER_SIZE && currentPos < m_maxSize) {
        uint64_t contiguousBytes = m_fragments.ContiguousBytesFrom(currentPos);
        if (contiguousBytes == 0) {
            break;
        }

        size_t toRead = static_cast<size_t>(std::min<uint64_t>(
            contiguousBytes,
            std::min<uint64_t>(BUFFER_SIZE - bufferFilled, m_maxSize - currentPos)
        ));

        auto loc = m_fragments.TranslateOffset(currentPos);
        if (!loc.valid) {
            break;
        }

        uint64_t bytesPerCluster = m_fragments.BytesPerCluster();
        uint64_t sectorsPerCluster = bytesPerCluster / m_sectorSize;
        uint64_t diskOffset = m_volumeStartOffset + (loc.cluster * sectorsPerCluster * m_sectorSize) + loc.offsetInCluster;

        // FIX: Calculate alignment BEFORE reading
        uint64_t offsetInSector = diskOffset % m_sectorSize;
        uint64_t startSector = diskOffset / m_sectorSize;
        uint64_t sectorsNeeded = (offsetInSector + toRead + m_sectorSize - 1) / m_sectorSize;

        auto data = m_disk.ReadSectors(startSector, sectorsNeeded, m_sectorSize);

        if (data.empty()) {
            break;
        }

        size_t available = data.size() > offsetInSector ? data.size() - static_cast<size_t>(offsetInSector) : 0;
        size_t toCopy = std::min<size_t>(available, toRead);

        std::memcpy(m_buffer.data() + bufferFilled, data.data() + offsetInSector, toCopy);
        bufferFilled += toCopy;
        currentPos += toCopy;
    }

    m_bufferValid = bufferFilled;
    m_bufferPos = 0;
    m_bufferFileOffset = m_position;
}

bool SequentialReader::ReadByte(uint8_t& byte) {
    if (m_position >= m_maxSize) {
        return false;
    }

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

bool SequentialReader::Peek(uint8_t& byte) {
    if (m_position >= m_maxSize) {
        return false;
    }

    if (m_bufferPos >= m_bufferValid) {
        FillBuffer();
        if (m_bufferValid == 0) {
            return false;
        }
    }

    byte = m_buffer[m_bufferPos];
    return true;
}

size_t SequentialReader::Read(uint8_t* buffer, size_t count) {
    size_t totalRead = 0;

    while (totalRead < count && m_position < m_maxSize) {
        if (m_bufferPos >= m_bufferValid) {
            FillBuffer();
            if (m_bufferValid == 0) {
                break;
            }
        }

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

    uint64_t bufferRemaining = m_bufferValid - m_bufferPos;
    if (count <= bufferRemaining) {
        m_bufferPos += static_cast<size_t>(count);
        m_position += count;
        return true;
    }

    m_position += count;
    m_bufferValid = 0;
    m_bufferPos = 0;
    return true;
}

bool SequentialReader::Seek(uint64_t position) {
    if (position > m_maxSize) {
        return false;
    }

    if (m_bufferValid > 0 &&
        position >= m_bufferFileOffset &&
        position < m_bufferFileOffset + m_bufferValid) {
        m_bufferPos = static_cast<size_t>(position - m_bufferFileOffset);
        m_position = position;
        return true;
    }

    m_position = position;
    m_bufferValid = 0;
    m_bufferPos = 0;
    return true;
}

// ============================================================================
// FileCarver Implementation
// ============================================================================

FileCarver::FileCarver() = default;
FileCarver::~FileCarver() = default;

// Method to create fresh diagnostics
CarvingStatistics CreateCarvingDiagnostics() {
    CarvingStatistics stats{};
    stats.totalSignaturesFound = 0;
    stats.filesWithKnownSize = 0;
    stats.filesWithValidatedSize = 0;
    stats.potentiallyFragmented = 0;
    stats.severelyFragmented = 0;
    stats.unknownSize = 0;
    stats.clustersScanned = 0;
    return stats;
}

CarvingResult FileCarver::CarveVolume(
    VolumeReader& reader,
    const CarvingOptions& options,
    FileCallback onFileFound,
    ProgressCallback onProgress,
    std::atomic<bool>& shouldStop)
{
    CarvingResult result;
    const auto& geom = reader.Geometry();

    uint64_t startLCN = options.startLCN;
    uint64_t maxLCN = options.clusterLimit > 0
        ? std::min<uint64_t>(options.clusterLimit, geom.totalClusters)
        : geom.totalClusters;

    if (startLCN >= maxLCN) {
        return result;
    }

    std::unordered_set<uint64_t> seenStartLCNs;

    wchar_t startMsg[256];
    swprintf_s(startMsg, L"File carving: Scanning %llu clusters (%.2f GB)...",
              maxLCN - startLCN, ((maxLCN - startLCN) * geom.bytesPerCluster) / 1000000000.0);
    onProgress(startMsg, 0.0f);

    const uint64_t batchSize = options.batchClusters;

    for (uint64_t batchStart = startLCN;
         batchStart < maxLCN && result.files.size() < options.maxFiles;
         batchStart += batchSize) {

        if (shouldStop) {
            wchar_t stopMsg[256];
            swprintf_s(stopMsg, L"Carving stopped: %zu files found", result.files.size());
            onProgress(stopMsg, 1.0f);
            break;
        }

        uint64_t batchCount = std::min<uint64_t>(batchSize, maxLCN - batchStart);

        const uint8_t* batchData = nullptr;
        uint64_t batchDataSize = 0;
        std::vector<uint8_t> fallbackBuffer;
        bool usedMapping = false;

        auto view = reader.MapClusters(batchStart, batchCount);

        if (view.IsValid()) {
            batchData = view.data;
            batchDataSize = view.size;
            usedMapping = true;
        } else {
            try {
                fallbackBuffer = reader.ReadClusters(batchStart, batchCount);
                batchData = fallbackBuffer.data();
                batchDataSize = fallbackBuffer.size();
            } catch (const DiskReadError&) {
                continue;
            }
        }

        if (batchDataSize == 0) {
            if (usedMapping) reader.UnmapView(view);
            continue;
        }

        uint64_t clusterInBatch = 0;
        while (clusterInBatch < batchCount && result.files.size() < options.maxFiles) {
            bool advancedBySkip = false;

            uint64_t currentLCN = batchStart + clusterInBatch;
            uint64_t offsetInBatch = clusterInBatch * geom.bytesPerCluster;

            if (offsetInBatch + 16 > batchDataSize) {
                break;
            }

            const uint8_t* clusterPtr = batchData + offsetInBatch;

            for (const auto& sig : options.signatures) {
                bool signatureMatches = false;

                if (std::strcmp(sig.extension, "mp4") == 0) {
                    if (offsetInBatch + 8 <= batchDataSize) {
                        if (std::memcmp(clusterPtr + 4, sig.signature, sig.signatureSize) == 0) {
                            uint32_t atomSize = (static_cast<uint32_t>(clusterPtr[0]) << 24) |
                                              (static_cast<uint32_t>(clusterPtr[1]) << 16) |
                                              (static_cast<uint32_t>(clusterPtr[2]) << 8) |
                                              static_cast<uint32_t>(clusterPtr[3]);

                            if (atomSize >= 8 && atomSize < 100 * 1024 * 1024) {
                                signatureMatches = true;
                            }
                        }
                    }
                } else if (std::strcmp(sig.extension, "avi") == 0) {
                    if (offsetInBatch + 12 <= batchDataSize) {
                        if (std::memcmp(clusterPtr, sig.signature, sig.signatureSize) == 0 &&
                            std::memcmp(clusterPtr + 8, "AVI ", 4) == 0) {
                            signatureMatches = true;
                        }
                    }
                } else if (std::strcmp(sig.extension, "wav") == 0) {
                    if (offsetInBatch + 12 <= batchDataSize) {
                        if (std::memcmp(clusterPtr, sig.signature, sig.signatureSize) == 0 &&
                            std::memcmp(clusterPtr + 8, "WAVE", 4) == 0) {
                            signatureMatches = true;
                        }
                    }
                } else {
                    if (offsetInBatch + sig.signatureSize <= batchDataSize) {
                        if (std::memcmp(clusterPtr, sig.signature, sig.signatureSize) == 0) {
                            signatureMatches = true;
                        }
                    }
                }

                if (signatureMatches) {
                    if (seenStartLCNs.find(currentLCN) != seenStartLCNs.end()) {
                        continue;
                    }

                    result.stats.totalSignaturesFound++;

                    auto fileSize = ParseFileEnd(reader, currentLCN, sig);

                    if (fileSize.has_value() && fileSize.value() > 0) {
                        seenStartLCNs.insert(currentLCN);

                        CarvedFile carved;
                        carved.signature = sig;
                        carved.startLCN = currentLCN;
                        carved.fileSize = fileSize.value();

                        carved.fragments = FragmentMap(geom.bytesPerCluster);
                        uint64_t clustersNeeded = (fileSize.value() + geom.bytesPerCluster - 1) / geom.bytesPerCluster;
                        carved.fragments.AddRun(currentLCN, clustersNeeded);
                        carved.fragments.SetTotalSize(fileSize.value());

                        result.stats.filesWithKnownSize++;
                        result.stats.byFormat[sig.extension]++;

                        onFileFound(carved);
                        result.files.push_back(carved);

                        if (options.dedupMode == DedupMode::FastDedup) {
                            for (uint64_t i = 1; i < clustersNeeded && (currentLCN + i) < maxLCN; i++) {
                                seenStartLCNs.insert(currentLCN + i);
                            }
                            clusterInBatch += clustersNeeded;
                            advancedBySkip = true;
                        }
                    }

                    break;
                }
            }

            if (!advancedBySkip) {
                clusterInBatch++;
            }
        }

        if (usedMapping) {
            reader.UnmapView(view);
        }

        if ((batchStart % Constants::Progress::CARVING_INTERVAL) == 0 || result.files.size() >= options.maxFiles) {
            float progress = static_cast<float>(batchStart - startLCN) / (maxLCN - startLCN);
            float percentDone = progress * 100.0f;
            float gbProcessed = ((batchStart - startLCN) * geom.bytesPerCluster) / 1000000000.0f;
            float gbTotal = ((maxLCN - startLCN) * geom.bytesPerCluster) / 1000000000.0f;

            wchar_t statusMsg[256];
            swprintf_s(statusMsg, L"Carving: %.1f%% (%.2f / %.2f GB) - %zu files found",
                      percentDone, gbProcessed, gbTotal, result.files.size());
            onProgress(statusMsg, progress);
        }
    }

    result.stats.clustersScanned = maxLCN - startLCN;

    wchar_t completeMsg[256];
    float percentScanned = (static_cast<float>(maxLCN - startLCN) / geom.totalClusters) * 100.0f;
    swprintf_s(completeMsg, L"Carving complete: %zu files found (%.1f%% scanned)",
               result.files.size(), percentScanned);
    onProgress(completeMsg, 1.0f);

    return result;
}

std::optional<uint64_t> FileCarver::ParseFileEnd(
    VolumeReader& reader,
    uint64_t startLCN,
    const FileSignature& sig)
{
    const auto& geom = reader.Geometry();

    uint64_t maxScanSize = std::min<uint64_t>(
        Constants::MAX_FILE_SCAN_SIZE,
        (geom.totalClusters - startLCN) * geom.bytesPerCluster
    );

    FragmentMap fragments(geom.bytesPerCluster);
    uint64_t estimatedClusters = maxScanSize / geom.bytesPerCluster;
    fragments.AddRun(startLCN, estimatedClusters);
    fragments.SetTotalSize(maxScanSize);

    SequentialReader seqReader(reader.GetDiskHandle(), std::move(fragments), geom.sectorSize, geom.volumeStartOffset);

    if (std::strcmp(sig.extension, "jpg") == 0) {
        return ParseJpegEnd(seqReader);
    } else if (std::strcmp(sig.extension, "png") == 0) {
        return ParsePngEnd(seqReader);
    } else if (std::strcmp(sig.extension, "pdf") == 0) {
        return ParsePdfEnd(seqReader);
    } else if (std::strcmp(sig.extension, "zip") == 0 ||
               std::strcmp(sig.extension, "docx") == 0 ||
               std::strcmp(sig.extension, "xlsx") == 0 ||
               std::strcmp(sig.extension, "pptx") == 0) {
        return ParseZipEnd(seqReader);
    } else if (std::strcmp(sig.extension, "mp4") == 0) {
        return ParseMp4End(seqReader);
    } else if (std::strcmp(sig.extension, "gif") == 0) {
        return ParseGifEnd(seqReader);
    } else if (std::strcmp(sig.extension, "bmp") == 0) {
        return ParseBmpEnd(seqReader);
    } else if (std::strcmp(sig.extension, "avi") == 0) {
        return ParseAviEnd(seqReader);
    } else if (std::strcmp(sig.extension, "wav") == 0) {
        return ParseWavEnd(seqReader);
    }

    return std::nullopt;
}

std::optional<uint64_t> FileCarver::ParseJpegEnd(SequentialReader& reader) {
    uint8_t tmp[2];

    if (reader.Read(tmp, 2) != 2) {
        return std::nullopt;
    }

    if (tmp[0] != 0xFF || tmp[1] != 0xD8) {
        return std::nullopt;
    }

    constexpr uint8_t EOI_MARKER = 0xD9;
    constexpr uint8_t SOS_MARKER = 0xDA;
    constexpr uint8_t RST0_MARKER = 0xD0;
    constexpr uint8_t RST7_MARKER = 0xD7;

    while (!reader.AtEOF()) {
        if (reader.Read(tmp, 2) != 2) {
            return std::nullopt;
        }

        while (tmp[0] != 0xFF) {
            tmp[0] = tmp[1];
            if (!reader.ReadByte(tmp[1])) {
                return std::nullopt;
            }
        }

        uint8_t marker = tmp[1];

        if (marker == 0x00) {
            continue;
        }

        while (marker == 0xFF) {
            if (!reader.ReadByte(marker)) {
                return std::nullopt;
            }
        }

        if (marker == EOI_MARKER) {
            return reader.Position();
        }

        if (marker >= RST0_MARKER && marker <= RST7_MARKER) {
            continue;
        }

        if (reader.Read(tmp, 2) != 2) {
            return std::nullopt;
        }

        int segmentLen = (static_cast<int>(tmp[0]) << 8) + static_cast<int>(tmp[1]) - 2;
        if (segmentLen < 0) {
            return std::nullopt;
        }

        if (!reader.Skip(static_cast<uint64_t>(segmentLen))) {
            return std::nullopt;
        }

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

                    if (nextByte == 0x00) {
                        continue;
                    }

                    if (nextByte >= RST0_MARKER && nextByte <= RST7_MARKER) {
                        continue;
                    }

                    if (nextByte == 0xFF) {
                        continue;
                    }

                    if (nextByte == EOI_MARKER) {
                        return reader.Position();
                    }

                    break;
                }
            }
        }
    }

    return std::nullopt;
}

std::optional<uint64_t> FileCarver::ParsePngEnd(SequentialReader& reader) {
    uint8_t header[8];

    if (reader.Read(header, 8) != 8) {
        return std::nullopt;
    }

    const uint8_t pngSig[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (std::memcmp(header, pngSig, 8) != 0) {
        return std::nullopt;
    }

    while (!reader.AtEOF()) {
        uint8_t chunkHeader[8];
        if (reader.Read(chunkHeader, 8) != 8) {
            return std::nullopt;
        }

        uint32_t chunkLen = (static_cast<uint32_t>(chunkHeader[0]) << 24) |
                           (static_cast<uint32_t>(chunkHeader[1]) << 16) |
                           (static_cast<uint32_t>(chunkHeader[2]) << 8) |
                           static_cast<uint32_t>(chunkHeader[3]);

        if (chunkLen > 100 * 1024 * 1024) {
            return std::nullopt;
        }

        if (std::memcmp(chunkHeader + 4, "IEND", 4) == 0) {
            if (!reader.Skip(chunkLen + 4)) {
                return std::nullopt;
            }
            return reader.Position();
        }

        if (!reader.Skip(chunkLen + 4)) {
            return std::nullopt;
        }
    }

    return std::nullopt;
}

std::optional<uint64_t> FileCarver::ParsePdfEnd(SequentialReader& reader) {
    uint8_t header[5];

    if (reader.Read(header, 5) != 5) {
        return std::nullopt;
    }

    if (std::memcmp(header, "%PDF-", 5) != 0) {
        return std::nullopt;
    }

    constexpr uint64_t MAX_PDF_SIZE = 64 * 1024 * 1024;

    uint64_t lastEofPos = 0;
    uint8_t searchBuf[5] = {0};

    while (!reader.AtEOF() && reader.Position() < MAX_PDF_SIZE) {
        std::memmove(searchBuf, searchBuf + 1, 4);

        if (!reader.ReadByte(searchBuf[4])) {
            break;
        }

        if (std::memcmp(searchBuf, "%%EOF", 5) == 0) {
            lastEofPos = reader.Position();
        }
    }

    if (lastEofPos > 0) {
        return lastEofPos;
    }

    return std::nullopt;
}

std::optional<uint64_t> FileCarver::ParseZipEnd(SequentialReader& reader) {
    uint8_t header[4];

    if (reader.Read(header, 4) != 4) {
        return std::nullopt;
    }

    const uint8_t zipSig[] = {0x50, 0x4B, 0x03, 0x04};
    if (std::memcmp(header, zipSig, 4) != 0) {
        return std::nullopt;
    }

    constexpr uint64_t MAX_ZIP_SIZE = 100 * 1024 * 1024;

    uint8_t searchBuf[4] = {0};
    uint64_t eocdPos = 0;

    while (!reader.AtEOF() && reader.Position() < MAX_ZIP_SIZE) {
        std::memmove(searchBuf, searchBuf + 1, 3);

        if (!reader.ReadByte(searchBuf[3])) {
            break;
        }

        if (searchBuf[0] == 0x50 && searchBuf[1] == 0x4B &&
            searchBuf[2] == 0x05 && searchBuf[3] == 0x06) {
            eocdPos = reader.Position() - 4;
        }
    }

    if (eocdPos > 0) {
        return eocdPos + 22;
    }

    return std::nullopt;
}

std::optional<uint64_t> FileCarver::ParseMp4End(SequentialReader& reader) {
    uint8_t header[8];

    if (reader.Read(header, 8) != 8) {
        return std::nullopt;
    }

    if (std::memcmp(header + 4, "ftyp", 4) != 0) {
        return std::nullopt;
    }

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

    while (!reader.AtEOF()) {
        if (reader.Read(header, 8) != 8) {
            break;
        }

        uint64_t atomSize = (static_cast<uint32_t>(header[0]) << 24) |
                            (static_cast<uint32_t>(header[1]) << 16) |
                            (static_cast<uint32_t>(header[2]) << 8) |
                            static_cast<uint32_t>(header[3]);

        if (atomSize == 0) {
            return reader.Position();
        }

        if (atomSize == 1) {
            uint8_t extSize[8];
            if (reader.Read(extSize, 8) != 8) {
                break;
            }

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
                return totalSize;
            }
        } else {
            if (atomSize < 8) {
                break;
            }

            totalSize += atomSize;
            if (!reader.Skip(atomSize - 8)) {
                return totalSize;
            }
        }
    }

    if (totalSize > 0) {
        return totalSize;
    }

    return std::nullopt;
}

std::optional<uint64_t> FileCarver::ParseGifEnd(SequentialReader& reader) {
    uint8_t header[6];

    if (reader.Read(header, 6) != 6) {
        return std::nullopt;
    }

    if (std::memcmp(header, "GIF8", 4) != 0) {
        return std::nullopt;
    }

    constexpr uint64_t MAX_GIF_SIZE = 50 * 1024 * 1024;

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

std::optional<uint64_t> FileCarver::ParseBmpEnd(SequentialReader& reader) {
    uint8_t header[54];

    if (reader.Read(header, 54) != 54) {
        return std::nullopt;
    }

    if (header[0] != 0x42 || header[1] != 0x4D) {
        return std::nullopt;
    }

    uint32_t fileSize = static_cast<uint32_t>(header[2]) |
                       (static_cast<uint32_t>(header[3]) << 8) |
                       (static_cast<uint32_t>(header[4]) << 16) |
                       (static_cast<uint32_t>(header[5]) << 24);

    uint32_t reserved1 = static_cast<uint32_t>(header[6]) |
                        (static_cast<uint32_t>(header[7]) << 8);
    uint32_t reserved2 = static_cast<uint32_t>(header[8]) |
                        (static_cast<uint32_t>(header[9]) << 8);

    uint32_t bfOffBits = static_cast<uint32_t>(header[10]) |
                        (static_cast<uint32_t>(header[11]) << 8) |
                        (static_cast<uint32_t>(header[12]) << 16) |
                        (static_cast<uint32_t>(header[13]) << 24);

    uint32_t dibSize = static_cast<uint32_t>(header[14]) |
                      (static_cast<uint32_t>(header[15]) << 8) |
                      (static_cast<uint32_t>(header[16]) << 16) |
                      (static_cast<uint32_t>(header[17]) << 24);

    int32_t width = static_cast<int32_t>(
        static_cast<uint32_t>(header[18]) |
        (static_cast<uint32_t>(header[19]) << 8) |
        (static_cast<uint32_t>(header[20]) << 16) |
        (static_cast<uint32_t>(header[21]) << 24));

    int32_t height = static_cast<int32_t>(
        static_cast<uint32_t>(header[22]) |
        (static_cast<uint32_t>(header[23]) << 8) |
        (static_cast<uint32_t>(header[24]) << 16) |
        (static_cast<uint32_t>(header[25]) << 24));

    uint16_t planes = static_cast<uint16_t>(header[26]) |
                     (static_cast<uint16_t>(header[27]) << 8);

    uint16_t bitsPerPixel = static_cast<uint16_t>(header[28]) |
                           (static_cast<uint16_t>(header[29]) << 8);

    uint32_t compression = static_cast<uint32_t>(header[30]) |
                          (static_cast<uint32_t>(header[31]) << 8) |
                          (static_cast<uint32_t>(header[32]) << 16) |
                          (static_cast<uint32_t>(header[33]) << 24);

    if (reserved1 != 0 || reserved2 != 0) {
        return std::nullopt;
    }

    if (fileSize < 54 || fileSize > 100 * 1024 * 1024) {
        return std::nullopt;
    }

    if (bfOffBits < 54 || bfOffBits >= fileSize || bfOffBits > 10000) {
        return std::nullopt;
    }

    if (dibSize != 40 && dibSize != 108 && dibSize != 124) {
        return std::nullopt;
    }

    if (width <= 0 || width > 30000 || height == 0 || std::abs(height) > 30000) {
        return std::nullopt;
    }

    if (planes != 1) {
        return std::nullopt;
    }

    if (bitsPerPixel != 1 && bitsPerPixel != 4 && bitsPerPixel != 8 &&
        bitsPerPixel != 16 && bitsPerPixel != 24 && bitsPerPixel != 32) {
        return std::nullopt;
    }

    if (compression > 6) {
        return std::nullopt;
    }

    uint64_t expectedMinSize = static_cast<uint64_t>(bfOffBits) +
                               (static_cast<uint64_t>(std::abs(width)) * std::abs(height) * bitsPerPixel) / 8;

    if (expectedMinSize > 0 && fileSize < expectedMinSize / 2) {
        return std::nullopt;
    }

    return fileSize;
}

std::optional<uint64_t> FileCarver::ParseAviEnd(SequentialReader& reader) {
    uint8_t header[12];

    if (reader.Read(header, 12) != 12) {
        return std::nullopt;
    }

    if (std::memcmp(header, "RIFF", 4) != 0) {
        return std::nullopt;
    }

    if (std::memcmp(header + 8, "AVI ", 4) != 0) {
        return std::nullopt;
    }

    uint32_t fileSize = static_cast<uint32_t>(header[4]) |
                       (static_cast<uint32_t>(header[5]) << 8) |
                       (static_cast<uint32_t>(header[6]) << 16) |
                       (static_cast<uint32_t>(header[7]) << 24);

    fileSize += 8;

    if (fileSize < 12 || fileSize > 2000ULL * 1024 * 1024) {
        return std::nullopt;
    }

    return fileSize;
}

std::optional<uint64_t> FileCarver::ParseWavEnd(SequentialReader& reader) {
    uint8_t header[12];

    if (reader.Read(header, 12) != 12) {
        return std::nullopt;
    }

    if (std::memcmp(header, "RIFF", 4) != 0) {
        return std::nullopt;
    }

    if (std::memcmp(header + 8, "WAVE", 4) != 0) {
        return std::nullopt;
    }

    uint32_t fileSize = static_cast<uint32_t>(header[4]) |
                       (static_cast<uint32_t>(header[5]) << 8) |
                       (static_cast<uint32_t>(header[6]) << 16) |
                       (static_cast<uint32_t>(header[7]) << 24);

    fileSize += 8;

    if (fileSize < 12 || fileSize > 500ULL * 1024 * 1024) {
        return std::nullopt;
    }

    return fileSize;
}

} // namespace KVC
