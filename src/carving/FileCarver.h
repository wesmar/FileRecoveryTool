// ============================================================================
// FileCarver.h - File Carving Engine
// ============================================================================
// Signature-based file recovery from raw disk data.
// ============================================================================

#pragma once

#include "io/VolumeReader.h"
#include "carving/FileSignatures.h"
#include "core/FragmentedFile.h"
#include <vector>
#include <functional>
#include <atomic>
#include <map>
#include <string>
#include <unordered_map>

namespace KVC {

// ============================================================================
// SequentialReader
// ============================================================================
class SequentialReader {
public:
    SequentialReader(DiskHandle& disk, uint64_t startOffset, uint64_t maxSize, uint64_t sectorSize);
    SequentialReader(DiskHandle& disk, const FragmentMap& fragments, uint64_t sectorSize, uint64_t volumeStartOffset = 0);
    SequentialReader(DiskHandle& disk, FragmentMap&& fragments, uint64_t sectorSize, uint64_t volumeStartOffset = 0,
                     const std::atomic<bool>* shouldStop = nullptr);
    
    bool ReadByte(uint8_t& byte);
    bool Peek(uint8_t& byte);
    size_t Read(uint8_t* buffer, size_t count);
    bool Skip(uint64_t count);
    bool Seek(uint64_t position);
    
    uint64_t Position() const { return m_position; }
    uint64_t MaxSize() const { return m_maxSize; }
    bool AtEOF() const { return m_position >= m_maxSize; }
    std::optional<uint64_t> TranslatePositionToDisk() const;

private:
    void FillBuffer();
    void FillBufferLinear();
    void FillBufferFragmented();
    
    static constexpr size_t BUFFER_SIZE = 65536;
    
    DiskHandle& m_disk;
    uint64_t m_startOffset;
    uint64_t m_maxSize;
    uint64_t m_position;
    uint64_t m_sectorSize;
    uint64_t m_volumeStartOffset;
    bool m_fragmentMode;
    FragmentMap m_fragments;
    std::vector<uint8_t> m_buffer;
    size_t m_bufferPos;
    size_t m_bufferValid;
    uint64_t m_bufferFileOffset;
    const std::atomic<bool>* m_shouldStop = nullptr;
};

// ============================================================================
// Carving Configuration
// ============================================================================

enum class DedupMode {
    FastDedup,
    ForensicFull
};

struct CarvingOptions {
    uint64_t maxFiles;
    uint64_t startLCN;
    uint64_t clusterLimit;
    uint64_t batchClusters;     // Clusters per batch for scanning
    DedupMode dedupMode;
    std::vector<FileSignature> signatures;
    // the free space to scan, (first cluster, count); freeRunsGiven with no
    // runs means there is none, without it the whole volume is scanned
    std::vector<std::pair<uint64_t, uint64_t>> freeRuns;
    bool freeRunsGiven = false;
    // Complete block maps recovered from ext inodes/journal metadata.
    // They identify data blocks; indirect blocks must never enter the stream.
    std::unordered_map<uint64_t, FragmentMap> fragmentHints;

    CarvingOptions()
        : maxFiles(10000000)
        , startLCN(0)
        , clusterLimit(0)
        , batchClusters(65536)  // ~256MB at 4KB clusters
        , dedupMode(DedupMode::FastDedup)
    {}
};

struct CarvedFile {
    FileSignature signature;
    uint64_t startLCN;
    uint64_t fileSize;
    FragmentMap fragments;
    bool incompleteRevision = false; // recovered earlier PDF revision after a truncated update
    bool spillsIntoUsed = false;    // runs past its free run into allocated clusters
};

struct CarvingStatistics {
    uint64_t totalSignaturesFound;
    uint64_t filesWithKnownSize;
    uint64_t filesWithValidatedSize;
    uint64_t potentiallyFragmented;
    uint64_t severelyFragmented;
    uint64_t unknownSize;
    uint64_t clustersScanned;
    uint64_t readErrorBatches = 0;
    std::map<std::string, uint64_t> byFormat;
    std::map<std::string, uint64_t> fragmentedByFormat;
};

struct CarvingResult {
    std::vector<CarvedFile> files;
    CarvingStatistics stats;
    bool complete = true;
};

// ============================================================================
// Helper Function
// ============================================================================

CarvingStatistics CreateCarvingDiagnostics();

// ============================================================================
// FileCarver
// ============================================================================

class FileCarver {
public:
    FileCarver();
    ~FileCarver();
    
    using ProgressCallback = std::function<void(const std::wstring&, float)>;
    using FileCallback = std::function<void(const CarvedFile&)>;
    
    CarvingResult CarveVolume(
        VolumeReader& reader,
        const CarvingOptions& options,
        FileCallback onFileFound,
        ProgressCallback onProgress,
        std::atomic<bool>& shouldStop
    );

private:
    std::optional<uint64_t> ParseFileEnd(
        VolumeReader& reader,
        uint64_t startLCN,
        FileSignature& sig,
        std::atomic<bool>& shouldStop,
        const FragmentMap* hint,
        bool* incompleteRevision
    );
    
    // FIXED: Made static for internal use
    static std::optional<uint64_t> ParseJpegEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParsePngEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParsePdfEnd(SequentialReader& reader, bool* incompleteRevision);
    static std::optional<uint64_t> ParseZipEnd(SequentialReader& reader, FileSignature* detected);
    static std::optional<uint64_t> ParseSevenZipEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseMp4End(SequentialReader& reader);
    static std::optional<uint64_t> ParseGifEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseBmpEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseAviEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseWavEnd(SequentialReader& reader);
};

} // namespace KVC
