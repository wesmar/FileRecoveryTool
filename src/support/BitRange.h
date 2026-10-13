// ============================================================================
// BitRange.h - questions about runs of bits in an allocation bitmap
// ============================================================================
// Bit n of byte n / 8, least significant first - the layout of NTFS
// $Bitmap, ext block and inode bitmaps and the exFAT allocation bitmap.
// Whole 64-bit words are looked at where the range covers them.
// ============================================================================

#pragma once

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace KVC {

// any bit set in [first, first + count)? Bits past the bitmap count as clear.
inline bool AnyBitSet(const std::vector<uint8_t>& bits, uint64_t first, uint64_t count) {
    const uint64_t limit = static_cast<uint64_t>(bits.size()) * 8;
    if (first >= limit || count == 0) return false;
    uint64_t end = first + count < first || first + count > limit ? limit : first + count;
    uint64_t i = first;
    while (i < end && (i % 64) != 0) {
        if ((bits[static_cast<size_t>(i / 8)] >> (i % 8)) & 1) return true;
        ++i;
    }
    while (i + 64 <= end) {
        uint64_t word;
        std::memcpy(&word, bits.data() + i / 8, sizeof(word));
        if (word) return true;
        i += 64;
    }
    for (; i < end; ++i) {
        if ((bits[static_cast<size_t>(i / 8)] >> (i % 8)) & 1) return true;
    }
    return false;
}

// the first clear bit in [first, limit), or limit when there is none; bits
// past the bitmap count as clear. Never less than first.
inline uint64_t NextClearBit(const std::vector<uint8_t>& bits, uint64_t first, uint64_t limit) {
    if (first >= limit) return limit;
    const uint64_t known = std::min<uint64_t>(limit, static_cast<uint64_t>(bits.size()) * 8);
    uint64_t i = first;
    while (i < known && (i % 64) != 0) {
        if (!((bits[static_cast<size_t>(i / 8)] >> (i % 8)) & 1)) return i;
        ++i;
    }
    while (i + 64 <= known) {
        uint64_t word;
        std::memcpy(&word, bits.data() + i / 8, sizeof(word));
        if (word != ~0ull) return i + static_cast<uint64_t>(std::countr_one(word));
        i += 64;
    }
    for (; i < known; ++i) {
        if (!((bits[static_cast<size_t>(i / 8)] >> (i % 8)) & 1)) return i;
    }
    return i;                               // known == limit, or the first bit past the bitmap
}

// the first set bit in [first, limit), or limit when there is none
inline uint64_t NextSetBit(const std::vector<uint8_t>& bits, uint64_t first, uint64_t limit) {
    const uint64_t known = std::min<uint64_t>(limit, static_cast<uint64_t>(bits.size()) * 8);
    uint64_t i = first;
    while (i < known && (i % 64) != 0) {
        if ((bits[static_cast<size_t>(i / 8)] >> (i % 8)) & 1) return i;
        ++i;
    }
    while (i + 64 <= known) {
        uint64_t word;
        std::memcpy(&word, bits.data() + i / 8, sizeof(word));
        if (word) return i + static_cast<uint64_t>(std::countr_zero(word));
        i += 64;
    }
    for (; i < known; ++i) {
        if ((bits[static_cast<size_t>(i / 8)] >> (i % 8)) & 1) return i;
    }
    return limit;                           // bits past the bitmap are clear
}

// the runs of clear bits in [0, limit) as (start, count): the free space of
// an allocation bitmap. Bits past the bitmap count as clear.
inline std::vector<std::pair<uint64_t, uint64_t>> ClearRuns(const std::vector<uint8_t>& bits, uint64_t limit) {
    std::vector<std::pair<uint64_t, uint64_t>> runs;
    for (uint64_t start = NextClearBit(bits, 0, limit); start < limit; ) {
        const uint64_t end = NextSetBit(bits, start, limit);
        runs.push_back({ start, end - start });
        start = NextClearBit(bits, end, limit);
    }
    return runs;
}

} // namespace KVC
