// ============================================================================
// FileCarver.h - Raw File Recovery
// ============================================================================
// Implements signature-based file recovery (carving) from raw disk sectors.
// Detects file types by magic numbers and reconstructs files without metadata.
// ============================================================================
#pragma once

#include "DiskForensicsCore.h"
#include "FileSignatures.h"
#include "Constants.h"
#include <vector>
#include <optional>
#include <map>
#include <string>

namespace KVC {

// ============================================================================
// SequentialReader - Stream-based disk reader (Digler-style)
// ============================================================================
// Wraps DiskHandle to provide sequential byte-by-byte reading for format parsers.
// This eliminates the need to pre-determine file sizes from corrupted headers.
class SequentialReader {
public:
    SequentialReader(DiskHandle& disk, uint64_t startOffset, uint64_t maxSize, uint64_t sectorSize);
    
    // Read single byte (returns false on EOF/error)
    bool ReadByte(uint8_t& byte);
    
    // Read multiple bytes (returns bytes actually read)
    size_t Read(uint8_t* buffer, size_t count);
    
    // Skip bytes without reading
    bool Skip(uint64_t count);
    
    // Get current position relative to start
    uint64_t Position() const { return m_position; }
    
    // Check if we hit EOF
    bool AtEOF() const { return m_position >= m_maxSize; }

private:
    void FillBuffer();
    
    DiskHandle& m_disk;
    uint64_t m_startOffset;     // Starting offset on disk
    uint64_t m_maxSize;          // Maximum bytes to read
    uint64_t m_position;         // Current position (relative to start)
    uint64_t m_sectorSize;
    
    std::vector<uint8_t> m_buffer;  // Internal read buffer (64KB)
    size_t m_bufferPos;             // Position in buffer
    size_t m_bufferValid;           // Valid bytes in buffer
    
    static constexpr size_t BUFFER_SIZE = 65536; // 64KB buffer
};

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
        const std::vector<FileSignature>& signatures,
        bool useNTFSAddressing = false
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
        uint64_t maxFiles,
        bool useNTFSAddressing = false
    );

    // Diagnostic structures for measuring carving effectiveness
    struct CarvingDiagnostics {
        uint64_t totalSignaturesFound;
        uint64_t filesWithKnownSize;
        uint64_t filesWithValidatedSize;
        uint64_t potentiallyFragmented;
        uint64_t severelyFragmented;
        uint64_t unknownSize;
        
        std::map<std::string, uint64_t> byFormat;
        std::map<std::string, uint64_t> fragmentedByFormat;
        
        CarvingDiagnostics() 
            : totalSignaturesFound(0)
            , filesWithKnownSize(0)
            , filesWithValidatedSize(0)
            , potentiallyFragmented(0)
            , severelyFragmented(0)
            , unknownSize(0) 
        {}
        
        void Merge(const CarvingDiagnostics& other) {
            totalSignaturesFound += other.totalSignaturesFound;
            filesWithKnownSize += other.filesWithKnownSize;
            filesWithValidatedSize += other.filesWithValidatedSize;
            potentiallyFragmented += other.potentiallyFragmented;
            severelyFragmented += other.severelyFragmented;
            unknownSize += other.unknownSize;
            
            for (const auto& pair : other.byFormat) {
                byFormat[pair.first] += pair.second;
            }
            for (const auto& pair : other.fragmentedByFormat) {
                fragmentedByFormat[pair.first] += pair.second;
            }
        }
    };
    
    struct DiagnosticResult {
        std::vector<CarvedFile> files;
        CarvingDiagnostics stats;
    };
    
    // Enhanced scanning with fragmentation diagnostics
    DiagnosticResult ScanRegionWithDiagnostics(
        DiskHandle& disk,
        uint64_t startCluster,
        uint64_t clusterCount,
        uint64_t sectorsPerCluster,
        uint64_t clusterHeapOffset,
        uint64_t sectorSize,
        const std::vector<FileSignature>& signatures,
        uint64_t maxFiles,
        bool useNTFSAddressing = false
    );

    // Parse file size from header
    std::optional<uint64_t> ParseFileSize(
        DiskHandle& disk,
        uint64_t cluster,
        uint64_t sectorsPerCluster,
        uint64_t clusterHeapOffset,
        uint64_t sectorSize,
        const FileSignature& signature,
        bool useNTFSAddressing = false
    );
    
    // Parse file size from memory buffer
    std::optional<uint64_t> ParseFileSizeFromMemory(
        const uint8_t* data,
        size_t dataSize,
        const FileSignature& signature
    );
    
    // NEW: Sequential parsing - reads until file end marker (Digler-style)
    std::optional<uint64_t> ParseFileEnd(
        SequentialReader& reader,
        const FileSignature& signature
    );

private:
    // Sequential format parsers (Digler-style) - read byte-by-byte to find end
    static std::optional<uint64_t> ParseJpegEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParsePngEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParsePdfEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseZipEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseMp4End(SequentialReader& reader);
    static std::optional<uint64_t> ParseGifEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseBmpEnd(SequentialReader& reader);
    
    // File format parsers (OLD - header-based, kept for compatibility)
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
    
    // Size validation helper for diagnostics
    struct SizeValidation {
        bool hasSize;
        uint64_t expectedSize;
        uint64_t actualSize;
        bool isValid;
    };
    
    SizeValidation ValidateFileSize(
        const uint8_t* data,
        size_t dataSize,
        uint64_t offsetInData,
        const FileSignature& sig,
        uint64_t bytesPerCluster
    );
};

} // namespace KVC
