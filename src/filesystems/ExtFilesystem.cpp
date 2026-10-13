// ============================================================================
// ExtFilesystem.cpp - ext2/ext3/ext4 on-disk structures, read-only
// ============================================================================

#include "filesystems/ExtFilesystem.h"
#include "support/BitRange.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>

namespace KVC {

namespace {

constexpr uint64_t SUPERBLOCK_OFFSET = 1024;
constexpr uint16_t EXT_MAGIC = 0xEF53;
constexpr uint16_t EXTENT_MAGIC = 0xF30A;
constexpr uint32_t INCOMPAT_FILETYPE = 0x0002;
constexpr uint32_t INCOMPAT_64BIT = 0x0080;
constexpr uint16_t BG_INODE_UNINIT = 0x0001;
constexpr uint16_t BG_BLOCK_UNINIT = 0x0002;
constexpr uint16_t UNWRITTEN_LENGTH = 32768;    // ee_len above this: an unwritten extent
constexpr int MAX_EXTENT_DEPTH = 5;
constexpr size_t DIRECT_BLOCKS = 12;
constexpr uint8_t MAX_FILE_TYPE = 7;

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) { return static_cast<uint32_t>(Le16(p)) | (static_cast<uint32_t>(Le16(p + 2)) << 16); }

void AddRun(std::vector<ClusterRun>& runs, uint64_t logical, uint64_t physical, uint64_t count, uint64_t blockSize) {
    if (count == 0) return;
    if (!runs.empty()) {
        ClusterRun& last = runs.back();
        if (last.startCluster + last.clusterCount == physical &&
            last.fileOffset + last.clusterCount * blockSize == logical * blockSize) {
            last.clusterCount += count;
            return;
        }
    }
    runs.emplace_back(physical, count, logical * blockSize);
}

} // namespace

ExtVolume::ExtVolume(DiskHandle& disk) : m_disk(disk) {}

bool ExtVolume::Open() {
    const auto sb = m_disk.ReadBytes(SUPERBLOCK_OFFSET, 1024);
    if (sb.size() < 1024 || Le16(sb.data() + 56) != EXT_MAGIC) return false;
    const uint32_t logBlock = Le32(sb.data() + 24);
    if (logBlock > 6) return false;
    m_blockSize = 1024ull << logBlock;
    const uint32_t incompat = Le32(sb.data() + 96);
    m_fileType = (incompat & INCOMPAT_FILETYPE) != 0;
    const bool is64 = (incompat & INCOMPAT_64BIT) != 0;
    m_blockCount = Le32(sb.data() + 4) | (is64 ? static_cast<uint64_t>(Le32(sb.data() + 336)) << 32 : 0);
    m_firstDataBlock = Le32(sb.data() + 20);
    m_blocksPerGroup = Le32(sb.data() + 32);
    m_inodesPerGroup = Le32(sb.data() + 40);
    m_inodeCount = Le32(sb.data() + 0);
    m_inodeSize = Le32(sb.data() + 76) >= 1 ? Le16(sb.data() + 88) : 128;
    m_journalInode = Le32(sb.data() + 224);
    const uint32_t descSize = is64 && Le16(sb.data() + 254) >= 64 ? Le16(sb.data() + 254) : 32;
    if (m_blocksPerGroup == 0 || m_inodesPerGroup == 0 || m_inodeSize < 128 || m_inodeSize > m_blockSize) return false;

    const uint64_t groups = (m_blockCount - m_firstDataBlock + m_blocksPerGroup - 1) / m_blocksPerGroup;
    const auto gdt = m_disk.ReadBytes((m_firstDataBlock + 1) * m_blockSize, groups * descSize);
    if (gdt.size() < groups * descSize) return false;
    m_groups.resize(static_cast<size_t>(groups));
    for (size_t g = 0; g < m_groups.size(); ++g) {
        const uint8_t* d = gdt.data() + g * descSize;
        Group& G = m_groups[g];
        G.blockBitmap = Le32(d + 0);
        G.inodeBitmap = Le32(d + 4);
        G.inodeTable = Le32(d + 8);
        G.flags = Le16(d + 18);
        if (descSize >= 64) {
            G.blockBitmap |= static_cast<uint64_t>(Le32(d + 32)) << 32;
            G.inodeBitmap |= static_cast<uint64_t>(Le32(d + 36)) << 32;
            G.inodeTable |= static_cast<uint64_t>(Le32(d + 40)) << 32;
        }
        m_tables.push_back({ G.inodeTable, static_cast<uint32_t>(g) });
    }
    std::sort(m_tables.begin(), m_tables.end());
    return true;
}

std::vector<uint8_t> ExtVolume::ReadBlocks(uint64_t first, uint64_t count) {
    if (first >= m_blockCount || count == 0) return {};
    count = std::min(count, m_blockCount - first);
    return m_disk.ReadBytes(first * m_blockSize, count * m_blockSize);
}

std::vector<uint8_t> ExtVolume::ReadBlock(uint64_t block) {
    if (block >= m_blockCount) return {};
    auto data = m_disk.ReadBytes(block * m_blockSize, m_blockSize);
    if (data.size() != m_blockSize) return {};
    return data;
}

bool ExtVolume::InodeLocation(uint32_t inode, uint64_t& block, uint32_t& offset) const {
    if (inode == 0 || inode > m_inodeCount) return false;
    const uint32_t group = (inode - 1) / m_inodesPerGroup;
    if (group >= m_groups.size()) return false;
    const uint64_t byteOffset = static_cast<uint64_t>((inode - 1) % m_inodesPerGroup) * m_inodeSize;
    block = m_groups[group].inodeTable + byteOffset / m_blockSize;
    offset = static_cast<uint32_t>(byteOffset % m_blockSize);
    return true;
}

bool ExtVolume::IsInodeTableBlock(uint64_t block, uint32_t& firstInode) const {
    const uint64_t perGroupBlocks = (static_cast<uint64_t>(m_inodesPerGroup) * m_inodeSize + m_blockSize - 1) / m_blockSize;
    const uint32_t perBlock = static_cast<uint32_t>(m_blockSize / m_inodeSize);
    // the last table starting at or before the block (tables never overlap)
    auto it = std::upper_bound(m_tables.begin(), m_tables.end(), std::make_pair(block, UINT32_MAX));
    if (it == m_tables.begin()) return false;
    --it;
    if (block >= it->first + perGroupBlocks) return false;
    firstInode = static_cast<uint32_t>(static_cast<uint64_t>(it->second) * m_inodesPerGroup + (block - it->first) * perBlock + 1);
    return true;
}

ExtInode ExtVolume::DecodeInode(uint32_t number, const uint8_t* raw) const {
    ExtInode i;
    i.number = number;
    i.mode = Le16(raw + 0);
    i.size = Le32(raw + 4) | (static_cast<uint64_t>(Le32(raw + 108)) << 32);
    i.mtime = Le32(raw + 16);
    i.dtime = Le32(raw + 20);
    i.linksCount = Le16(raw + 26);
    i.flags = Le32(raw + 32);
    std::memcpy(i.block, raw + 40, sizeof(i.block));
    i.generation = Le32(raw + 100);
    return i;
}

std::optional<ExtInode> ExtVolume::ReadInode(uint32_t inode) {
    uint64_t block = 0;
    uint32_t offset = 0;
    if (!InodeLocation(inode, block, offset)) return std::nullopt;
    const auto data = ReadBlock(block);
    if (data.size() < offset + m_inodeSize) return std::nullopt;
    return DecodeInode(inode, data.data() + offset);
}

std::vector<uint8_t>& ExtVolume::Bitmap(std::unordered_map<uint32_t, std::vector<uint8_t>>& cache, uint32_t group, bool blocks) {
    auto it = cache.find(group);
    if (it == cache.end()) {
        const Group& g = m_groups[group];
        std::vector<uint8_t> bits;
        if (!(g.flags & (blocks ? BG_BLOCK_UNINIT : BG_INODE_UNINIT))) {
            bits = ReadBlock(blocks ? g.blockBitmap : g.inodeBitmap);
        }
        it = cache.emplace(group, std::move(bits)).first;
    }
    return it->second;
}

bool ExtVolume::BlockInUse(uint64_t block) {
    if (block < m_firstDataBlock || block >= m_blockCount) return true;
    const uint32_t group = static_cast<uint32_t>((block - m_firstDataBlock) / m_blocksPerGroup);
    const uint64_t bit = (block - m_firstDataBlock) % m_blocksPerGroup;
    const auto& bits = Bitmap(m_blockBitmaps, group, true);
    if (bit / 8 >= bits.size()) return false;           // uninitialised: free
    return (bits[static_cast<size_t>(bit / 8)] >> (bit % 8)) & 1;
}

bool ExtVolume::AnyBlockInUse(uint64_t first, uint64_t count) {
    if (first < m_firstDataBlock || first + count > m_blockCount) return true;
    uint64_t block = first;
    const uint64_t end = first + count;
    while (block < end) {
        const uint32_t group = static_cast<uint32_t>((block - m_firstDataBlock) / m_blocksPerGroup);
        const uint64_t groupStart = m_firstDataBlock + static_cast<uint64_t>(group) * m_blocksPerGroup;
        const uint64_t stop = std::min(end, groupStart + m_blocksPerGroup);
        if (AnyBitSet(Bitmap(m_blockBitmaps, group, true), block - groupStart, stop - block)) return true;
        block = stop;
    }
    return false;
}

std::vector<std::pair<uint64_t, uint64_t>> ExtVolume::FreeRuns() {
    std::vector<std::pair<uint64_t, uint64_t>> runs;
    for (uint32_t g = 0; g < m_groups.size(); ++g) {
        const uint64_t start = m_firstDataBlock + static_cast<uint64_t>(g) * m_blocksPerGroup;
        if (start >= m_blockCount) break;
        const uint64_t count = std::min<uint64_t>(m_blocksPerGroup, m_blockCount - start);
        for (const auto& [first, length] : ClearRuns(Bitmap(m_blockBitmaps, g, true), count)) {
            if (!runs.empty() && runs.back().first + runs.back().second == start + first) {
                runs.back().second += length;
            } else {
                runs.push_back({ start + first, length });
            }
        }
        m_blockBitmaps.erase(g);                // a whole volume's bitmaps need not stay
    }
    return runs;
}

bool ExtVolume::InodeInUse(uint32_t inode) {
    if (inode == 0 || inode > m_inodeCount) return true;
    const uint32_t group = (inode - 1) / m_inodesPerGroup;
    const uint32_t bit = (inode - 1) % m_inodesPerGroup;
    const auto& bits = Bitmap(m_inodeBitmaps, group, false);
    if (bit / 8 >= bits.size()) return false;
    return (bits[bit / 8] >> (bit % 8)) & 1;
}

std::vector<ClusterRun> ExtVolume::MapBlocks(const ExtInode& inode, const ExtBlockSource& source, bool& complete) {
    std::vector<ClusterRun> runs;
    complete = true;
    if (inode.HasInlineData()) {
        return runs;
    }
    if (inode.UsesExtents()) {
        MapExtents(inode.block, sizeof(inode.block), MAX_EXTENT_DEPTH, source, runs, complete);
    } else {
        const uint64_t limit = (inode.size + m_blockSize - 1) / m_blockSize;
        uint64_t logical = 0;
        for (size_t i = 0; i < DIRECT_BLOCKS && logical < limit; ++i, ++logical) {
            const uint32_t b = Le32(inode.block + i * 4);
            if (b) AddRun(runs, logical, b, 1, m_blockSize);
        }
        for (int level = 1; level <= 3 && logical < limit; ++level) {
            MapIndirect(Le32(inode.block + (DIRECT_BLOCKS + level - 1) * 4), level, logical, limit, source, runs, complete);
        }
    }
    return runs;
}

void ExtVolume::MapExtents(const uint8_t* node, size_t size, int depthLimit, const ExtBlockSource& source,
                           std::vector<ClusterRun>& runs, bool& complete) {
    if (size < 12 || Le16(node) != EXTENT_MAGIC) {
        complete = false;
        return;
    }
    const uint16_t entries = Le16(node + 2);
    const uint16_t depth = Le16(node + 6);
    if (depth > depthLimit || 12 + static_cast<size_t>(entries) * 12 > size) {
        complete = false;
        return;
    }
    for (uint16_t e = 0; e < entries; ++e) {
        const uint8_t* x = node + 12 + e * 12;
        if (depth == 0) {
            const uint32_t logical = Le32(x);
            uint16_t length = Le16(x + 4);
            const uint64_t start = (static_cast<uint64_t>(Le16(x + 6)) << 32) | Le32(x + 8);
            if (length > UNWRITTEN_LENGTH) {
                continue;                           // unwritten: reads as zeros, a hole
            }
            if (start + length > m_blockCount) {
                complete = false;
                continue;
            }
            AddRun(runs, logical, start, length, m_blockSize);
        } else {
            const uint64_t child = Le32(x + 4) | (static_cast<uint64_t>(Le16(x + 8)) << 32);
            const auto block = source(child);
            if (block.size() < 12 || Le16(block.data() + 6) != depth - 1) {
                complete = false;
                continue;
            }
            MapExtents(block.data(), block.size(), depth - 1, source, runs, complete);
        }
    }
}

void ExtVolume::MapIndirect(uint64_t block, int level, uint64_t& logical, uint64_t limit, const ExtBlockSource& source,
                            std::vector<ClusterRun>& runs, bool& complete) {
    const uint64_t perBlock = m_blockSize / 4;
    uint64_t span = 1;
    for (int k = 1; k < level; ++k) span *= perBlock;      // data blocks under one pointer of this level
    if (block == 0) {
        logical += span * perBlock;                         // a hole
        return;
    }
    if (block >= m_blockCount) {
        complete = false;
        logical += span * perBlock;
        return;
    }
    const auto data = source(block);
    if (data.size() != m_blockSize) {
        complete = false;
        logical += span * perBlock;
        return;
    }
    for (uint64_t i = 0; i < perBlock && logical < limit; ++i) {
        const uint32_t pointer = Le32(data.data() + i * 4);
        if (level == 1) {
            if (pointer) AddRun(runs, logical, pointer, 1, m_blockSize);
            ++logical;
        } else {
            MapIndirect(pointer, level - 1, logical, limit, source, runs, complete);
        }
    }
}

std::wstring ExtVolume::DecodeName(const uint8_t* p, size_t length) const {
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(p),
                                      static_cast<int>(length), nullptr, 0);
    if (n > 0) {
        std::wstring s(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, reinterpret_cast<const char*>(p), static_cast<int>(length), s.data(), n);
        return s;
    }
    std::wstring s(length, L'\0');                         // not UTF-8: byte for byte
    for (size_t i = 0; i < length; ++i) s[i] = static_cast<wchar_t>(p[i]);
    return s;
}

bool ExtVolume::ValidEntry(const uint8_t* p, size_t room) const {
    if (room < 12) return false;
    const uint32_t inode = Le32(p);
    const uint32_t recLen = Le16(p + 4);
    const uint8_t nameLen = p[6];
    const uint8_t type = p[7];
    if (inode == 0 || inode > m_inodeCount || nameLen == 0 || 8u + nameLen > room) return false;
    if (recLen % 4 != 0 || recLen < ((8u + nameLen + 3) & ~3u)) return false;
    if (m_fileType && (type == 0 || type > MAX_FILE_TYPE)) return false;
    for (uint8_t i = 0; i < nameLen; ++i) {
        if (p[8 + i] == 0 || p[8 + i] == '/') return false;
    }
    if ((nameLen == 1 && p[8] == '.') || (nameLen == 2 && p[8] == '.' && p[9] == '.')) return false;
    return true;
}

void ExtVolume::ParseDirectoryBlock(const std::vector<uint8_t>& block, std::vector<ExtDirEntry>& live,
                                    std::vector<ExtDirEntry>* slack) const {
    const size_t size = block.size();
    if (size < 12) return;
    // an htree node: one empty entry over the whole block, index entries inside
    if (Le32(block.data()) == 0 && Le16(block.data() + 4) == size && block[6] == 0) return;

    size_t off = 0;
    while (off + 8 <= size) {
        const uint8_t* p = block.data() + off;
        const uint32_t inode = Le32(p);
        uint32_t recLen = Le16(p + 4);
        if (recLen == 0 || recLen == 65535) recLen = static_cast<uint32_t>(m_blockSize);
        const uint8_t nameLen = p[6];
        if (recLen < 8 || off + recLen > size) break;

        const bool dot = (nameLen == 1 && p[8] == '.') || (nameLen == 2 && p[8] == '.' && p[9] == '.');
        if (inode != 0 && nameLen > 0 && !dot) {
            live.push_back({ inode, p[7], DecodeName(p + 8, nameLen) });
        }

        // the room after this entry: entries a delete only skipped
        bool htreeRoot = false;
        if (off == 12 && nameLen == 2 && p[8] == '.' && p[9] == '.' && size >= 32) {
            htreeRoot = Le32(block.data() + 24) == 0 && block[29] == 8;     // dx_root_info
        }
        if (slack && !htreeRoot) {
            size_t q = off + ((8u + nameLen + 3) & ~3u);
            const size_t end = off + recLen;
            while (q + 12 <= end) {
                if (ValidEntry(block.data() + q, end - q)) {
                    const uint8_t n = block[q + 6];
                    slack->push_back({ Le32(block.data() + q), block[q + 7], DecodeName(block.data() + q + 8, n) });
                    q += (8u + n + 3) & ~3u;
                } else {
                    q += 4;
                }
            }
        }
        off += recLen;
    }
}

} // namespace KVC
