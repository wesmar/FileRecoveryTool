// ============================================================================
// ExtJournal.cpp - the jbd2 journal of an ext3/ext4 volume as a block archive
// ============================================================================

#include "filesystems/ExtJournal.h"

#include <algorithm>

namespace KVC {

namespace {

constexpr uint32_t JBD2_MAGIC = 0xC03B3998;
constexpr uint32_t BLOCK_DESCRIPTOR = 1;
constexpr uint32_t BLOCK_SUPERBLOCK_V1 = 3;
constexpr uint32_t BLOCK_SUPERBLOCK_V2 = 4;
constexpr uint32_t INCOMPAT_64BIT = 0x02;
constexpr uint32_t INCOMPAT_CSUM_V2 = 0x08;
constexpr uint32_t INCOMPAT_CSUM_V3 = 0x10;
constexpr uint32_t TAG_ESCAPE = 0x1;
constexpr uint32_t TAG_SAME_UUID = 0x2;
constexpr uint32_t TAG_LAST = 0x8;
constexpr size_t UUID_BYTES = 16;
constexpr size_t HEADER_BYTES = 12;
constexpr uint64_t READ_CHUNK = 4 * 1024 * 1024;

uint32_t Be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
uint16_t Be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

} // namespace

ExtJournal::ExtJournal(ExtVolume& volume) : m_volume(volume) {}

std::vector<uint8_t> ExtJournal::ReadLogBlock(uint64_t logBlock) {
    const uint64_t bs = m_volume.BlockSize();
    const uint64_t offset = logBlock * bs;
    for (const auto& run : m_runs) {
        if (offset >= run.fileOffset && offset < run.fileOffset + run.clusterCount * bs) {
            return m_volume.ReadBlock(run.startCluster + (offset - run.fileOffset) / bs);
        }
    }
    return {};
}

bool ExtJournal::Load(std::atomic<bool>& shouldStop) {
    m_loaded = false;
    m_copies.clear();
    if (m_volume.JournalInode() == 0) return false;
    auto inode = m_volume.ReadInode(m_volume.JournalInode());
    if (!inode || inode->size == 0) return false;
    bool complete = true;
    m_runs = m_volume.MapBlocks(*inode, m_volume.DiskSource(), complete);
    if (m_runs.empty()) return false;

    const auto sb = ReadLogBlock(0);
    if (sb.size() < 64 || Be32(sb.data()) != JBD2_MAGIC) return false;
    const uint32_t type = Be32(sb.data() + 4);
    if (type != BLOCK_SUPERBLOCK_V1 && type != BLOCK_SUPERBLOCK_V2) return false;
    if (Be32(sb.data() + 12) != m_volume.BlockSize()) return false;
    m_maxLen = Be32(sb.data() + 16);
    m_first = Be32(sb.data() + 20);
    m_incompat = type == BLOCK_SUPERBLOCK_V2 ? Be32(sb.data() + 40) : 0;
    if (m_first == 0 || m_first >= m_maxLen) return false;

    const bool csum3 = (m_incompat & INCOMPAT_CSUM_V3) != 0;
    const bool csum2 = (m_incompat & INCOMPAT_CSUM_V2) != 0;
    const bool wide = (m_incompat & INCOMPAT_64BIT) != 0;
    const size_t tagBytes = csum3 ? 16 : (8 + (wide ? 4 : 0) + (csum2 ? 2 : 0));
    const size_t tail = (csum2 || csum3) ? 4 : 0;          // the descriptor's checksum tail
    const uint64_t bs = m_volume.BlockSize();
    auto position = [&](uint64_t p) { return p >= m_maxLen ? m_first + (p - m_maxLen) % (m_maxLen - m_first) : p; };

    // every block of the log, whatever the superblock says is live: a
    // checkpointed transaction is still there until the log wraps over it.
    // Read in large pieces, each within one run of the journal inode.
    const uint64_t chunkBlocks = std::max<uint64_t>(1, READ_CHUNK / bs);
    std::vector<uint8_t> chunk;
    for (uint64_t j = m_first; j < m_maxLen && !shouldStop; ) {
        uint64_t count = std::min(chunkBlocks, m_maxLen - j);
        chunk.clear();
        for (const auto& run : m_runs) {
            const uint64_t first = run.fileOffset / bs;
            if (j >= first && j < first + run.clusterCount) {
                count = std::min(count, first + run.clusterCount - j);
                chunk = m_volume.ReadBlocks(run.startCluster + (j - first), count);
                break;
            }
        }
        if (chunk.size() < count * bs) {
            j += std::max<uint64_t>(1, chunk.size() / bs + 1);      // a hole or a read error: step past it
            continue;
        }
        for (uint64_t k = 0; k < count; ++k) {
            const uint8_t* block = chunk.data() + k * bs;
            if (Be32(block) != JBD2_MAGIC || Be32(block + 4) != BLOCK_DESCRIPTOR) {
                continue;
            }
            const uint32_t sequence = Be32(block + 8);
            size_t off = HEADER_BYTES;
            uint64_t data = j + k + 1;
            while (off + tagBytes <= bs - tail) {
                const uint8_t* t = block + off;
                uint64_t fsBlock = Be32(t);
                uint32_t flags;
                if (csum3) {
                    flags = Be32(t + 4);
                    if (wide) fsBlock |= static_cast<uint64_t>(Be32(t + 8)) << 32;
                } else {
                    flags = Be16(t + 6);
                    if (wide) fsBlock |= static_cast<uint64_t>(Be32(t + 8)) << 32;
                }
                if (fsBlock < m_volume.BlockCount()) {
                    m_copies[fsBlock].push_back({ sequence, position(data), (flags & TAG_ESCAPE) != 0 });
                }
                ++data;
                off += tagBytes + ((flags & TAG_SAME_UUID) ? 0 : UUID_BYTES);
                if (flags & TAG_LAST) break;
            }
        }
        j += count;
    }

    for (auto& [block, copies] : m_copies) {
        std::sort(copies.begin(), copies.end(),
                  [](const ExtJournalCopy& a, const ExtJournalCopy& b) { return a.sequence > b.sequence; });
    }
    m_loaded = true;
    return true;
}

const std::vector<ExtJournalCopy>* ExtJournal::Copies(uint64_t fsBlock) const {
    auto it = m_copies.find(fsBlock);
    return it == m_copies.end() ? nullptr : &it->second;
}

std::vector<uint8_t> ExtJournal::ReadCopy(const ExtJournalCopy& copy) {
    auto data = ReadLogBlock(copy.journalBlock);
    if (copy.escaped && data.size() >= 4) {         // the log cleared the magic it began with
        data[0] = 0xC0; data[1] = 0x3B; data[2] = 0x39; data[3] = 0x98;
    }
    return data;
}

std::vector<uint8_t> ExtJournal::NewestValid(uint64_t fsBlock, bool (*valid)(const std::vector<uint8_t>&)) {
    if (const auto* copies = Copies(fsBlock)) {
        for (const auto& c : *copies) {
            auto data = ReadCopy(c);
            if (!data.empty() && valid(data)) return data;
        }
    }
    return m_volume.ReadBlock(fsBlock);
}

} // namespace KVC
