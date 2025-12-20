// ============================================================================
// FileCarver.h - Raw File Recovery
// ============================================================================
// Implements signature-based file recovery (carving) from raw disk sectors.
// Detects file types by magic numbers and reconstructs files without metadata.
// Supports fragmented file reading through FragmentMap abstraction.
// ============================================================================
#pragma once

#include "DiskForensicsCore.h"
#include "FileSignatures.h"
#include "FragmentedFile.h"
#include "Constants.h"
#include <vector>
#include <optional>
#include <map>
#include <string>

namespace KVC {

// ============================================================================
// SequentialReader - Fragment-aware stream-based disk reader
// ============================================================================
// Wraps DiskHandle to provide sequential byte-by-byte reading for format parsers.
// Transparently handles fragmented files - presents a continuous stream regardless
// of physical fragmentation on disk.
//
// Two modes of operation:
// 1. Linear mode: Simple start offset + max size (legacy, for contiguous files)
// 2. Fragment mode: Uses FragmentMap for non-contiguous files

class SequentialReader {
public:
    // Linear mode constructor (for contiguous files or simple scanning)
    SequentialReader(DiskHandle& disk, uint64_t startOffset, uint64_t maxSize, uint64_t sectorSize);
    
    // Fragment mode constructor (for fragmented files)
    SequentialReader(DiskHandle& disk, const FragmentMap& fragments, uint64_t sectorSize);
    SequentialReader(DiskHandle& disk, FragmentMap&& fragments, uint64_t sectorSize);
    
    // Read single byte (returns false on EOF/error)
    bool ReadByte(uint8_t& byte);
    
    // Read multiple bytes (returns bytes actually read)
    size_t Read(uint8_t* buffer, size_t count);
    
    // Peek at next byte without consuming it
    bool Peek(uint8_t& byte);
    
    // Skip bytes without reading
    bool Skip(uint64_t count);
    
    // Seek to absolute position (within file)
    bool Seek(uint64_t position);
    
    // Get current position relative to start
    uint64_t Position() const { return m_position; }
    
    // Check if we hit EOF
    bool AtEOF() const { return m_position >= m_maxSize; }
    
    // Get total readable size
    uint64_t TotalSize() const { return m_maxSize; }
    
    // Get remaining bytes
    uint64_t Remaining() const { 
        return m_position < m_maxSize ? m_maxSize - m_position : 0; 
    }
    
    // Check if operating in fragment mode
    bool IsFragmented() const { return m_fragmentMode; }
    
    // Get fragment map (only valid in fragment mode)
    const FragmentMap& Fragments() const { return m_fragments; }

private:
    void FillBuffer();
    void FillBufferLinear();
    void FillBufferFragmented();
    
    // Translate current file position to disk offset (for fragmented mode)
    std::optional<uint64_t> TranslatePositionToDisk() const;
    
    DiskHandle& m_disk;
    uint64_t m_startOffset;      // Starting offset on disk (linear mode only)
    uint64_t m_maxSize;          // Maximum bytes to read
    uint64_t m_position;         // Current position (relative to start)
    uint64_t m_sectorSize;
    
    bool m_fragmentMode;         // True if using FragmentMap
    FragmentMap m_fragments;     // Fragment map (fragment mode)
    
    std::vector<uint8_t> m_buffer;  // Internal read buffer
    size_t m_bufferPos;             // Position in buffer
    size_t m_bufferValid;           // Valid bytes in buffer
    uint64_t m_bufferFileOffset;    // File offset corresponding to buffer start
    
    static constexpr size_t BUFFER_SIZE = 65536; // 64KB buffer
};

// ============================================================================
// FileCarver - Main carving engine
// ============================================================================

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
        FragmentMap fragments;      // NEW: Fragment information
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

    // Parse file size from header (linear mode)
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
    
    // Sequential parsing - reads until file end marker (Digler-style)
    // Works with both linear and fragmented SequentialReader
    std::optional<uint64_t> ParseFileEnd(
        SequentialReader& reader,
        const FileSignature& signature
    );
    
    // NEW: Parse file end using fragment map
    std::optional<uint64_t> ParseFileEndFragmented(
        DiskHandle& disk,
        const FragmentMap& fragments,
        uint64_t sectorSize,
        const FileSignature& signature
    );

private:
    // Sequential format parsers (Digler-style) - read byte-by-byte to find end
    // These are UNCHANGED - they work on the abstract SequentialReader stream
    static std::optional<uint64_t> ParseJpegEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParsePngEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParsePdfEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseZipEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseMp4End(SequentialReader& reader);
    static std::optional<uint64_t> ParseGifEnd(SequentialReader& reader);
    static std::optional<uint64_t> ParseBmpEnd(SequentialReader& reader);
    
    // File format parsers (header-based, kept for compatibility)
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
