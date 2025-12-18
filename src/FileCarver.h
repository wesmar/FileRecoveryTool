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
