// ============================================================================
// Constants.h - Global Configuration Constants
// ============================================================================
// Hierarchical constant definitions for disk forensics operations.
// Separates hardware/format constants from tunable performance parameters.
// ============================================================================

#pragma once

#include <cstdint>

namespace KVC {
namespace Constants {

// ============================================================================
// Size Unit Multipliers
// ============================================================================
constexpr uint64_t KILOBYTE = 1024ULL;
constexpr uint64_t MEGABYTE = 1024ULL * 1024;
constexpr uint64_t GIGABYTE = 1024ULL * 1024 * 1024;

// ============================================================================
// Disk Geometry & Hardware Defaults
// ============================================================================
constexpr uint64_t SECTOR_SIZE_DEFAULT = 512;
constexpr uint64_t CLUSTER_SIZE_DEFAULT = 4096;
constexpr uint8_t  SECTORS_PER_CLUSTER_DEFAULT = 8;

// ============================================================================
// Memory I/O Configuration
// ============================================================================
constexpr uint64_t MAX_MAPPING_SIZE = 256 * MEGABYTE;
constexpr uint64_t ALLOCATION_GRANULARITY = 64 * KILOBYTE;

// Maximum single ReadFile call size (must fit in DWORD for Windows API)
constexpr uint64_t MAX_READ_CHUNK = 16 * MEGABYTE;

// Maximum file size to scan during carving (prevents runaway parsing)
constexpr uint64_t MAX_FILE_SCAN_SIZE = 2ULL * GIGABYTE;

// ============================================================================
// Batch Processing Sizes
// ============================================================================
constexpr uint64_t CLUSTERS_PER_BATCH = 65536;
constexpr uint64_t DIRECTORY_READ_LIMIT = 2 * MEGABYTE;

// Carving batch size in clusters (default ~256MB per batch at 4KB clusters)
constexpr uint64_t CARVING_BATCH_CLUSTERS = 65536;

// ============================================================================
// NTFS-Specific Constants
// ============================================================================
namespace NTFS {
    constexpr uint64_t USNJRNL_RECORD_NUMBER = 38;
    constexpr uint64_t RECORDS_PER_BATCH = 1024;
    constexpr uint64_t MAX_FRAGMENTS = 1000000;
    constexpr uint64_t MAX_CLUSTERS_TOTAL = (100ULL * GIGABYTE) / CLUSTER_SIZE_DEFAULT;
    constexpr uint64_t MAX_CLUSTER_CHAIN_READ = 100000;
    constexpr uint64_t PATH_CACHE_DEPTH_LIMIT = 50;
    constexpr uint64_t PATH_CACHE_SIZE_LIMIT = 100;
    
    // Data run parsing limits
    constexpr size_t MAX_DATA_RUN_SIZE = 8;          // Max bytes per length/offset field
    constexpr size_t MAX_DATA_RUNS_PER_ATTRIBUTE = 65536;
}

// ============================================================================
// ExFAT-Specific Constants
// ============================================================================
namespace ExFAT {
    constexpr uint64_t MAX_DELETED_FILE_SIZE = 10ULL * GIGABYTE;
    constexpr uint64_t MAX_SEQUENTIAL_SIZE = 10ULL * GIGABYTE;
}

// ============================================================================
// FAT32-Specific Constants
// ============================================================================
namespace FAT32 {
    constexpr int MAX_CHAIN_CLUSTERS = 2048;
}

// ============================================================================
// File Carving Constants
// ============================================================================
namespace Carving {
    constexpr uint64_t HEADER_READ_CLUSTERS = 256;  // Increased from 64 for large files
    constexpr uint64_t HEADER_READ_SIZE = 1 * MEGABYTE;  // Increased from 256KB for modern media
    constexpr uint64_t MAX_SAFE_SKIP = 64 * MEGABYTE;
    constexpr uint64_t MAX_REASONABLE_GAP = 50;
    constexpr uint64_t SIZE_PARSE_TOLERANCE = 10;
}

// ============================================================================
// Fragmentation Support
// ============================================================================
namespace Fragmentation {
    constexpr size_t SEQUENTIAL_READER_BUFFER_SIZE = 65536;  // 64KB read buffer
    constexpr size_t MAX_FRAGMENTS_PER_FILE = 1000000;       // Safety limit
    constexpr size_t PARALLEL_VALIDATION_THRESHOLD = 10;     // Min fragments for parallel validation
    constexpr size_t DEFAULT_PARALLEL_THREADS = 4;
    constexpr uint64_t MAX_CONTIGUOUS_READ = 16 * MEGABYTE;  // Max single contiguous read
}

// ============================================================================
// Progress Reporting Intervals
// ============================================================================
namespace Progress {
    constexpr uint64_t MFT_SCAN_INTERVAL = 10240;
    constexpr uint64_t USN_JOURNAL_INTERVAL = 1000;
    constexpr uint64_t CARVING_INTERVAL = 10000;
    constexpr uint64_t CARVING_BATCH_INTERVAL = 1000;
}

} // namespace Constants
} // namespace KVC
