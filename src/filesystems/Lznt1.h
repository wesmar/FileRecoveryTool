// ============================================================================
// Lznt1.h - NTFS compressed files: LZNT1 and compression units
// ============================================================================
// An NTFS compressed file is cut into compression units (16 clusters as a
// rule). A unit whose clusters are all allocated is stored as it is, one with
// none is zeros, and one with fewer holds LZNT1 data: chunks that each expand
// to at most 4096 bytes.
// ============================================================================

#pragma once

#include "core/RecoveryCandidate.h"
#include "io/VolumeReader.h"
#include <cstddef>
#include <cstdint>
#include <functional>

namespace KVC {

// Expands LZNT1 data into out. Returns the bytes produced, or SIZE_MAX when
// the data is not valid LZNT1 (an overwritten unit, a wrong guess).
size_t Lznt1Decompress(const uint8_t* in, size_t inLength, uint8_t* out, size_t outCapacity);

// Writes a compressed file through write/zeros, unit by unit. Returns the
// bytes that could not be read or expanded (written as zeros).
uint64_t WriteLznt1(VolumeReader& reader, const RecoveryCandidate& file,
                    const std::function<void(const uint8_t*, uint64_t)>& write,
                    const std::function<void(uint64_t)>& zeros);

} // namespace KVC
