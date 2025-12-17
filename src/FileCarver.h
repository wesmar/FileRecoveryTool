// ============================================================================
// FileCarver.h - Raw File Recovery
// ============================================================================
// Implements signature-based file recovery (carving) from raw disk sectors.
// Detects file types by magic numbers and reconstructs files without metadata.
// ============================================================================
#pragma once

#include "DiskForensicsCore.h"
#include "FileSignatures.h"
#include <vector>
#include <optional>

namespace KVC {

class FileCarver {
public:
    FileCarver();
    ~FileCarver();

    // Original method - single cluster scan
    std::optional<FileSignature> ScanClusterForSignature(
        DiskHandle& disk,
        uint64_t cluster,
        uint64_t sectorsPerCluster,
        uint64_t clusterHeapOffset,
        uint64_t sectorSize,
        const std::vector<FileSignature>& signatures
    );

    // Optimized method - batch scan using memory-mapped I/O
    struct CarvedFile {
        FileSignature signature;
        uint64_t startCluster;
        uint64_t fileSize;
    };
    
    std::vector<CarvedFile> ScanRegionMemoryMapped(
        DiskHandle& disk,
        uint64_t startCluster,
        uint64_t clusterCount,
        uint64_t sectorsPerCluster,
        uint64_t clusterHeapOffset,
        uint64_t sectorSize,
        const std::vector<FileSignature>& signatures,
        uint64_t maxFiles
    );

    // Parse file size from header
    std::optional<uint64_t> ParseFileSize(
        DiskHandle& disk,
        uint64_t cluster,
        uint64_t sectorsPerCluster,
        uint64_t clusterHeapOffset,
        uint64_t sectorSize,
        const FileSignature& signature
    );
    
    // Parse file size from memory buffer
    std::optional<uint64_t> ParseFileSizeFromMemory(
        const uint8_t* data,
        size_t dataSize,
        const FileSignature& signature
    );

private:
    // File format parsers
    static std::optional<uint64_t> ParsePngSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseJpegSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseGifSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseBmpSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParsePdfSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseZipSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseMp4Size(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseAviSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseWavSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseOle2Size(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> ParseRarSize(const std::vector<uint8_t>& data);
    static std::optional<uint64_t> Parse7zSize(const std::vector<uint8_t>& data);
};

} // namespace KVC
