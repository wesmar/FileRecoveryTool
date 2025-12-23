// ============================================================================
// SafetyLimits.h - Hard Safety Limits
// ============================================================================
#pragma once

#include <climits>
#include <cstdint>


namespace KVC {
namespace Limits {

// Hard safety limits (compile-time)
constexpr uint64_t MAX_FILE_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10GB
constexpr uint64_t MAX_FRAGMENTS_PER_FILE = 1000000;
constexpr uint64_t MAX_CLUSTER_NUMBER = 0x0FFFFFFFFFFFF;
constexpr size_t MAX_DATA_RUN_SIZE = 8;

// Memory constraints
constexpr uint64_t MAX_SINGLE_READ = 256 * 1024 * 1024;  // 256MB
constexpr uint64_t MAX_MAPPING_SIZE = 256 * 1024 * 1024;

// Hardware defaults
constexpr uint64_t DEFAULT_SECTOR_SIZE = 512;
constexpr uint64_t DEFAULT_CLUSTER_SIZE = 4096;

} // namespace Limits
} // namespace KVC