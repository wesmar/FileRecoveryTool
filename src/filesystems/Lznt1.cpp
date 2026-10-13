// ============================================================================
// Lznt1.cpp - NTFS compressed files: LZNT1 and compression units
// ============================================================================

#include "filesystems/Lznt1.h"
#include "support/ForensicsExceptions.h"

#include <algorithm>
#include <vector>

namespace KVC {

namespace {

constexpr size_t CHUNK_BYTES = 4096;            // a chunk expands to at most this
constexpr uint16_t CHUNK_SIZE_MASK = 0x0FFF;    // stored size - 3
constexpr uint16_t CHUNK_COMPRESSED = 0x8000;

} // namespace

size_t Lznt1Decompress(const uint8_t* in, size_t inLength, uint8_t* out, size_t outCapacity) {
    size_t ip = 0;
    size_t op = 0;

    while (ip + 2 <= inLength && op < outCapacity) {
        const uint16_t header = static_cast<uint16_t>(in[ip] | (in[ip + 1] << 8));
        if (header == 0) {
            break;                                  // end of the unit's data
        }
        const size_t chunkEnd = ip + (header & CHUNK_SIZE_MASK) + 3;
        if (chunkEnd > inLength) {
            return SIZE_MAX;
        }
        ip += 2;
        const size_t chunkStart = op;
        const size_t chunkLimit = std::min(outCapacity, chunkStart + CHUNK_BYTES);

        if (!(header & CHUNK_COMPRESSED)) {
            const size_t n = std::min(chunkEnd - ip, chunkLimit - op);
            std::copy(in + ip, in + ip + n, out + op);
            op += n;
            ip = chunkEnd;
            continue;
        }

        while (ip < chunkEnd && op < chunkLimit) {
            const uint8_t flags = in[ip++];
            for (int bit = 0; bit < 8 && ip < chunkEnd && op < chunkLimit; ++bit) {
                if (!(flags & (1 << bit))) {
                    out[op++] = in[ip++];           // a literal
                    continue;
                }
                if (ip + 2 > chunkEnd) {
                    return SIZE_MAX;
                }
                const uint16_t token = static_cast<uint16_t>(in[ip] | (in[ip + 1] << 8));
                ip += 2;
                // the further into the chunk, the more bits the offset takes
                unsigned lengthBits = 12;
                for (size_t p = op - chunkStart - 1; op > chunkStart && p >= 0x10; p >>= 1) {
                    --lengthBits;
                }
                if (op == chunkStart) {
                    return SIZE_MAX;                // a reference before any byte
                }
                const size_t offset = static_cast<size_t>(token >> lengthBits) + 1;
                size_t length = static_cast<size_t>(token & ((1u << lengthBits) - 1)) + 3;
                if (offset > op - chunkStart) {
                    return SIZE_MAX;
                }
                length = std::min(length, chunkLimit - op);
                for (size_t k = 0; k < length; ++k, ++op) {
                    out[op] = out[op - offset];     // may overlap: byte by byte
                }
            }
        }
        ip = chunkEnd;
    }
    return op;
}

uint64_t WriteLznt1(VolumeReader& reader, const RecoveryCandidate& file,
                    const std::function<void(const uint8_t*, uint64_t)>& write,
                    const std::function<void(uint64_t)>& zeros)
{
    const VolumeGeometry& geom = reader.Geometry();
    const uint64_t bpc = geom.bytesPerCluster;
    const uint64_t unitClusters = file.compressionUnitClusters ? file.compressionUnitClusters : 16;
    const uint64_t unitBytes = unitClusters * bpc;
    const uint64_t size = file.fileSize;
    const uint64_t valid = std::min(size, file.validLength.value_or(size));

    std::vector<ClusterRun> runs = file.file.GetFragments().GetRuns();
    std::sort(runs.begin(), runs.end(), [](const ClusterRun& a, const ClusterRun& b) {
        return a.fileOffset < b.fileOffset;
    });

    std::vector<uint8_t> packed;
    std::vector<uint8_t> unit(static_cast<size_t>(unitBytes));
    uint64_t unreadable = 0;

    for (uint64_t start = 0; start < size; start += unitBytes) {
        const uint64_t want = std::min(unitBytes, size - start);
        const uint64_t firstVcn = start / bpc;

        // the unit's allocated clusters, in file order
        packed.clear();
        uint64_t allocated = 0;
        bool readError = false;
        for (const auto& run : runs) {
            const uint64_t runVcn = run.fileOffset / bpc;
            const uint64_t from = std::max(runVcn, firstVcn);
            const uint64_t to = std::min(runVcn + run.clusterCount, firstVcn + unitClusters);
            if (from >= to) continue;
            allocated += to - from;
            try {
                auto data = reader.ReadClusters(run.startCluster + (from - runVcn), to - from);
                if (data.size() < (to - from) * bpc) readError = true;
                packed.insert(packed.end(), data.begin(), data.end());
            } catch (const ForensicsException&) {
                readError = true;
            }
        }

        size_t produced = 0;
        if (allocated == 0) {
            produced = 0;                           // the whole unit is a hole
        } else if (allocated >= unitClusters) {
            produced = std::min<size_t>(packed.size(), unit.size());
            std::copy(packed.begin(), packed.begin() + static_cast<ptrdiff_t>(produced), unit.begin());
        } else {
            produced = Lznt1Decompress(packed.data(), packed.size(), unit.data(), unit.size());
            if (produced == SIZE_MAX) {
                produced = 0;
                readError = true;
            }
        }
        // a unit that ends early is zero-filled, as NTFS fills it
        std::fill(unit.begin() + static_cast<ptrdiff_t>(std::min<uint64_t>(produced, unit.size())), unit.end(), uint8_t{ 0 });

        // zeros past the valid length
        if (start + want > valid) {
            const uint64_t from = valid > start ? valid - start : 0;
            std::fill(unit.begin() + static_cast<ptrdiff_t>(from), unit.begin() + static_cast<ptrdiff_t>(want), uint8_t{ 0 });
        }
        if (readError) {
            unreadable += want;
        }
        if (allocated == 0) {
            zeros(want);
        } else {
            write(unit.data(), want);
        }
    }
    return unreadable;
}

} // namespace KVC
