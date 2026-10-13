// ============================================================================
// FileCarver.cpp - Complete Rewrite with VolumeReader Integration
// ============================================================================


#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "carving/FileCarver.h"
#include "support/Constants.h"
#include "support/StringUtils.h"

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

SequentialReader::SequentialReader(DiskHandle& disk, FragmentMap&& fragments, uint64_t sectorSize, uint64_t volumeStartOffset,
                                   const std::atomic<bool>* shouldStop)
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
    m_shouldStop = shouldStop;
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
    return m_volumeStartOffset + loc.cluster * bytesPerCluster + loc.offsetInCluster;
}

void SequentialReader::FillBuffer() {
    if (m_shouldStop && m_shouldStop->load(std::memory_order_relaxed)) {
        m_bufferValid = 0;
        return;
    }
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
        uint64_t diskOffset = m_volumeStartOffset + loc.cluster * bytesPerCluster + loc.offsetInCluster;

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
    if (count > m_maxSize - m_position) {
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
    CarvingResult result{};
    const auto& geom = reader.Geometry();
    const uint64_t bpc = geom.bytesPerCluster;
    if (bpc == 0 || geom.sectorSize == 0) throw std::invalid_argument("Invalid carving geometry");
    const uint64_t maxLCN = options.clusterLimit > 0 ? std::min<uint64_t>(options.clusterLimit, geom.totalClusters)
                                                     : geom.totalClusters;

    // where to look: the free runs the file system reported, or everything
    std::vector<std::pair<uint64_t, uint64_t>> regions = options.freeRuns;
    if (regions.empty() && !options.freeRunsGiven) {
        regions.push_back({ options.startLCN, maxLCN > options.startLCN ? maxLCN - options.startLCN : 0 });
    }
    uint64_t total = 0;
    for (const auto& r : regions) total += r.second;
    if (total == 0) {
        onProgress(L"Carving: no free space to scan", 1.0f);
        return result;
    }

    // signatures by their first byte; ftyp (MP4) lies 4 bytes in
    std::vector<size_t> byFirstByte[256];
    std::vector<size_t> atOffsetFour;
    for (size_t i = 0; i < options.signatures.size(); ++i) {
        const auto& sig = options.signatures[i];
        if (std::strcmp(sig.extension, "mp4") == 0) atOffsetFour.push_back(i);
        else if (sig.signatureSize) byFirstByte[sig.signature[0]].push_back(i);
    }

    wchar_t startMsg[256];
    swprintf_s(startMsg, L"Carving: scanning %llu %s (%.2f GB)...", total, bpc == 1 ? L"source bytes" : L"free clusters", (total * bpc) / 1000000000.0);
    onProgress(startMsg, 0.0f);

    // a batch is bounded by bytes, whatever the cluster size
    constexpr uint64_t BATCH_BYTES = 64ull * 1024 * 1024;
    const uint64_t batchClusters = std::max<uint64_t>(1, std::min(options.batchClusters, BATCH_BYTES / bpc));
    uint64_t scanned = 0;
    uint64_t nextLCN = 0;                       // a carved file covers up to here

    for (const auto& [regionStart, regionCount] : regions) {
        const uint64_t regionEnd = std::min(regionStart + regionCount, maxLCN);
        for (uint64_t batchStart = regionStart; batchStart < regionEnd && result.files.size() < options.maxFiles; ) {
            if (shouldStop) {
                wchar_t stopMsg[256];
                swprintf_s(stopMsg, L"Carving stopped: %zu files found", result.files.size());
                onProgress(stopMsg, 1.0f);
                result.complete = false;
                result.stats.clustersScanned = scanned;
                return result;
            }
            const uint64_t batchCount = std::min(batchClusters, regionEnd - batchStart);
            std::vector<uint8_t> batch;
            // Signatures can straddle a RAW batch boundary. Read enough
            // lookahead to identify them, but visit each start exactly once.
            uint64_t headerBytes = 12;
            for (const auto& sig : options.signatures) headerBytes = std::max<uint64_t>(headerBytes, sig.signatureSize + 4ull);
            const uint64_t lookahead = (headerBytes - 1) / bpc + ((headerBytes - 1) % bpc != 0);
            const uint64_t readCount = batchCount + std::min(lookahead, regionEnd - batchStart - batchCount);
            try {
                batch = reader.ReadClusters(batchStart, readCount);
            } catch (const ForensicsException&) {
                batch.clear();
            }
            if (batch.size() < readCount * bpc) {
                result.complete = false;
                ++result.stats.readErrorBatches;
            }

            for (uint64_t k = 0; k < batchCount && k * bpc < batch.size() && result.files.size() < options.maxFiles; ++k) {
                if ((k & 1023) == 0 && shouldStop) {
                    result.complete = false;
                    result.stats.clustersScanned = scanned + k;
                    return result;
                }
                const uint64_t lcn = batchStart + k;
                if (lcn < nextLCN) continue;
                const uint8_t* p = batch.data() + k * bpc;
                const uint64_t available = batch.size() - k * bpc;
                if (byFirstByte[p[0]].empty() && (atOffsetFour.empty() || available < 8 || p[4] != 'f')) continue;

                const FileSignature* found = nullptr;
                for (size_t i : byFirstByte[p[0]]) {
                    const auto& sig = options.signatures[i];
                    if (available < sig.signatureSize || std::memcmp(p, sig.signature, sig.signatureSize) != 0) continue;
                    if (std::strcmp(sig.extension, "avi") == 0 && (available < 12 || std::memcmp(p + 8, "AVI ", 4) != 0)) continue;
                    if (std::strcmp(sig.extension, "wav") == 0 && (available < 12 || std::memcmp(p + 8, "WAVE", 4) != 0)) continue;
                    found = &sig;
                    break;
                }
                if (!found) {
                    for (size_t i : atOffsetFour) {
                        const auto& sig = options.signatures[i];
                        if (available < 4ull + sig.signatureSize) continue;
                        const uint32_t atom = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
                        if (std::memcmp(p + 4, sig.signature, sig.signatureSize) == 0 && atom >= 8 && atom < 100u * 1024 * 1024) {
                            found = &sig;
                            break;
                        }
                    }
                }
                if (!found) continue;

                result.stats.totalSignaturesFound++;
                const auto hint = options.fragmentHints.find(lcn);
                const FragmentMap* map = hint == options.fragmentHints.end() ? nullptr : &hint->second;
                FileSignature resolved = *found; bool incompleteRevision = false;
                const auto fileSize = ParseFileEnd(reader, lcn, resolved, shouldStop, map, &incompleteRevision);
                if (shouldStop) { result.complete = false; result.stats.clustersScanned = scanned + k; return result; }
                const uint64_t availableFileBytes = std::min(Constants::MAX_FILE_SCAN_SIZE,
                    map ? map->TotalSize() : (geom.totalClusters - lcn) * bpc);
                if (!fileSize || *fileSize == 0 || *fileSize > availableFileBytes) {
                    result.stats.unknownSize++;
                    continue;
                }

                CarvedFile carved;
                carved.signature = resolved;
                carved.incompleteRevision = incompleteRevision;
                carved.startLCN = lcn;
                carved.fileSize = *fileSize;
                const uint64_t clusters = (*fileSize + bpc - 1) / bpc;
                carved.fragments = FragmentMap(bpc);
                if (map) {
                    for (const auto& run : map->GetRuns()) {
                        if (run.fileOffset >= *fileSize) break;
                        const uint64_t count = std::min(run.clusterCount, (*fileSize - run.fileOffset + bpc - 1) / bpc);
                        carved.fragments.AddRun(ClusterRun(run.startCluster, count, run.fileOffset));
                    }
                } else carved.fragments.AddRun(lcn, clusters);
                carved.fragments.SetTotalSize(*fileSize);
                // past its free run the clusters belong to live files: the
                // carved file was fragmented, or its end guessed wrong
                carved.spillsIntoUsed = !map && lcn + clusters > regionEnd;

                result.stats.filesWithKnownSize++;
                result.stats.filesWithValidatedSize++;
                result.stats.byFormat[resolved.extension]++;
                if (carved.spillsIntoUsed) {
                    result.stats.potentiallyFragmented++;
                    result.stats.fragmentedByFormat[resolved.extension]++;
                }
                onFileFound(carved);
                result.files.push_back(carved);
                if (options.dedupMode == DedupMode::FastDedup) {
                    nextLCN = lcn + (map ? carved.fragments.GetRuns().front().clusterCount : clusters);
                }
            }

            scanned += batchCount;
            batchStart += batchCount;
            wchar_t statusMsg[256];
            swprintf_s(statusMsg, L"Carving: %.1f%% (%.2f / %.2f GB) - %zu files found",
                       100.0 * scanned / total, (scanned * bpc) / 1000000000.0, (total * bpc) / 1000000000.0,
                       result.files.size());
            onProgress(statusMsg, static_cast<float>(scanned) / static_cast<float>(total));
        }
    }

    result.stats.clustersScanned = scanned;
    wchar_t completeMsg[256];
    swprintf_s(completeMsg, L"Carving complete: %zu files found in %llu %s", result.files.size(), scanned, bpc == 1 ? L"source bytes" : L"free clusters");
    onProgress(completeMsg, 1.0f);
    return result;
}
std::optional<uint64_t> FileCarver::ParseFileEnd(
    VolumeReader& reader,
    uint64_t startLCN,
    FileSignature& sig,
    std::atomic<bool>& shouldStop,
    const FragmentMap* hint,
    bool* incompleteRevision)
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
    if (hint) {
        fragments = *hint;
        fragments.SetTotalSize(std::min(Constants::MAX_FILE_SCAN_SIZE, hint->TotalSize()));
    }

    SequentialReader seqReader(reader.GetDiskHandle(), std::move(fragments), geom.sectorSize, geom.volumeStartOffset, &shouldStop);

    if (std::strcmp(sig.extension, "jpg") == 0) {
        return ParseJpegEnd(seqReader);
    } else if (std::strcmp(sig.extension, "png") == 0) {
        return ParsePngEnd(seqReader);
    } else if (std::strcmp(sig.extension, "pdf") == 0) {
        return ParsePdfEnd(seqReader, incompleteRevision);
    } else if (std::strcmp(sig.extension, "zip") == 0 ||
               std::strcmp(sig.extension, "docx") == 0 ||
               std::strcmp(sig.extension, "xlsx") == 0 ||
               std::strcmp(sig.extension, "pptx") == 0) {
        return ParseZipEnd(seqReader, &sig);
    } else if (std::strcmp(sig.extension, "7z") == 0) {
        return ParseSevenZipEnd(seqReader);
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
    uint8_t start[2];
    if (reader.Read(start, 2) != 2 || start[0] != 0xFF || start[1] != 0xD8) return std::nullopt;
    bool frame = false, scan = false, entropy = false;
    bool componentIds[256]{};
    unsigned components = 0;
    std::optional<uint8_t> pending;
    while (pending || !reader.AtEOF()) {
        uint8_t marker;
        if (pending) { marker = *pending; pending.reset(); }
        else {
            uint8_t prefix;
            if (!reader.ReadByte(prefix) || prefix != 0xFF) return std::nullopt;
            do { if (!reader.ReadByte(marker)) return std::nullopt; } while (marker == 0xFF);
        }
        if (marker == 0xD9) return frame && scan && entropy ? std::optional<uint64_t>(reader.Position()) : std::nullopt;
        if (marker == 0x01) continue; // TEM has no length field.
        const bool isFrame = marker == 0xC0 || marker == 0xC1 || marker == 0xC2 || marker == 0xC3 ||
                             marker == 0xC9 || marker == 0xCA || marker == 0xCB;
        const bool variable = isFrame || marker == 0xDA || marker == 0xC4 || marker == 0xCC ||
                              marker == 0xDB || marker == 0xDC || marker == 0xDD || marker == 0xFE ||
                              (marker >= 0xE0 && marker <= 0xEF);
        if (!variable) return std::nullopt;
        uint8_t lengthBytes[2];
        if (reader.Read(lengthBytes, 2) != 2) return std::nullopt;
        const unsigned length = (unsigned(lengthBytes[0]) << 8) | lengthBytes[1];
        if (length < 2 || length - 2 > reader.MaxSize() - reader.Position()) return std::nullopt;
        if (isFrame || marker == 0xDA) {
            std::vector<uint8_t> header(length - 2);
            if (reader.Read(header.data(), header.size()) != header.size()) return std::nullopt;
            if (isFrame) {
                if (frame || header.size() < 6) return std::nullopt;
                components = header[5];
                if (!components || header.size() != 6 + 3 * components ||
                    (header[0] != 8 && header[0] != 12 && header[0] != 16) ||
                    (header[1] == 0 && header[2] == 0) || (header[3] == 0 && header[4] == 0)) return std::nullopt;
                for (unsigned i = 0; i < components; ++i) {
                    const uint8_t id = header[6 + 3 * i], sampling = header[7 + 3 * i];
                    if (componentIds[id] || (sampling >> 4) == 0 || (sampling >> 4) > 4 ||
                        (sampling & 15) == 0 || (sampling & 15) > 4) return std::nullopt;
                    componentIds[id] = true;
                }
                frame = true;
            } else {
                if (!frame || header.empty() || header[0] == 0 || header[0] > 4 || header[0] > components ||
                    header.size() != 4ull + 2ull * header[0]) return std::nullopt;
                bool used[256]{};
                for (unsigned i = 0; i < header[0]; ++i) {
                    const uint8_t id = header[1 + 2 * i];
                    if (!componentIds[id] || used[id]) return std::nullopt;
                    used[id] = true;
                }
                scan = true;
                // Retain the next marker after entropy data. Progressive
                // images have multiple scans separated by ordinary segments.
                while (!reader.AtEOF()) {
                    uint8_t byte;
                    if (!reader.ReadByte(byte)) return std::nullopt;
                    if (byte != 0xFF) { entropy = true; continue; }
                    do { if (!reader.ReadByte(byte)) return std::nullopt; } while (byte == 0xFF);
                    if (byte == 0x00) { entropy = true; continue; }
                    if (byte >= 0xD0 && byte <= 0xD7) continue;
                    pending = byte;
                    break;
                }
            }
        } else if (!reader.Skip(length - 2)) return std::nullopt;
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

std::optional<uint64_t> FileCarver::ParseMp4End(SequentialReader& reader) {
    // Walk complete top-level boxes. Padding after the final box belongs
    // to the cluster, not the movie. Never return the size of a box whose
    // declared payload extends beyond the source.
    const auto be32 = [](const uint8_t* p) {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
    };
    uint64_t end = 0;
    bool movie = false, media = false;
    for (;;) {
        uint8_t box[8];
        if (reader.Read(box, sizeof(box)) != sizeof(box)) break;
        const uint8_t* type = box + 4;
        const bool ftyp = std::memcmp(type, "ftyp", 4) == 0;
        if (end == 0 && !ftyp) return std::nullopt;
        if (end != 0 && ftyp) break; // another file, not another box of this one
        static constexpr const char* types[] = {
            "ftyp", "moov", "mdat", "free", "skip", "wide", "uuid", "moof", "mfra",
            "sidx", "ssix", "styp", "pdin", "prft", "emsg", "meta", "meco", "bloc"
        };
        const bool known = std::any_of(std::begin(types), std::end(types),
            [&](const char* t) { return std::memcmp(type, t, 4) == 0; });
        if (!known) break;
        uint64_t size = be32(box), headerSize = 8;
        if (size == 1) {
            uint8_t extended[8];
            if (reader.Read(extended, sizeof(extended)) != sizeof(extended)) return std::nullopt;
            size = (uint64_t(be32(extended)) << 32) | be32(extended + 4);
            headerSize = 16;
        }
        // Size zero means "to EOF". Raw free space has no known file EOF,
        // so its boundary cannot be established by this carving parser.
        if (size < headerSize || size - headerSize > reader.MaxSize() - reader.Position()) return std::nullopt;
        if (ftyp && size < headerSize + 8) return std::nullopt;
        if (!reader.Skip(size - headerSize)) return std::nullopt;
        movie |= std::memcmp(type, "moov", 4) == 0;
        media |= std::memcmp(type, "mdat", 4) == 0;
        end = reader.Position();
    }
    return movie && media ? std::optional<uint64_t>(end) : std::nullopt;
}

std::optional<uint64_t> FileCarver::ParseGifEnd(SequentialReader& reader) {
    // GIF87a/89a: 0x3B is a trailer only between blocks. It may occur in
    // a palette, extension or compressed image without ending the file.
    uint8_t header[13];
    if (reader.Read(header, sizeof(header)) != sizeof(header) ||
        (std::memcmp(header, "GIF87a", 6) != 0 && std::memcmp(header, "GIF89a", 6) != 0) ||
        (header[6] | header[7]) == 0 || (header[8] | header[9]) == 0) return std::nullopt;
    auto palette = [&](uint8_t packed) {
        return (packed & 0x80) == 0 || reader.Skip(3ull * (2ull << (packed & 7)));
    };
    auto subblocks = [&]() {
        uint8_t length;
        while (reader.ReadByte(length)) {
            if (length == 0) return true;
            // Read every sub-block so a short source read cannot be hidden
            // by a seek past bytes which are missing.
            uint8_t data[255];
            if (reader.Read(data, length) != length) return false;
        }
        return false;
    };
    if (!palette(header[10])) return std::nullopt;
    bool hasGraphic = false;
    uint8_t block;
    while (reader.ReadByte(block)) {
        if (block == 0x3B) return hasGraphic ? std::optional<uint64_t>(reader.Position()) : std::nullopt;
        if (block == 0x21) {
            uint8_t label;
            if (!reader.ReadByte(label) || !subblocks()) return std::nullopt;
            if (label == 0x01) hasGraphic = true; // plain text is also a graphic
        } else if (block == 0x2C) {
            uint8_t image[9], codeSize;
            if (reader.Read(image, sizeof(image)) != sizeof(image) ||
                (image[4] | image[5]) == 0 || (image[6] | image[7]) == 0 ||
                !palette(image[8]) || !reader.ReadByte(codeSize) || codeSize < 2 || codeSize > 8 ||
                !subblocks()) return std::nullopt;
            hasGraphic = true;
        } else return std::nullopt;
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
