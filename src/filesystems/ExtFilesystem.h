// ============================================================================
// ExtFilesystem.h - ext2/ext3/ext4 on-disk structures, read-only
// ============================================================================
// Superblock, group descriptors (32 and 64 byte), inodes, block maps (extent
// trees and ext2/3 indirect blocks), directory entries and the allocation
// bitmaps - what a recovery needs, from any source of blocks: the volume as
// it is now, or older copies of metadata blocks kept in the journal.
// ============================================================================

#pragma once

#include "io/DiskHandle.h"
#include "core/FragmentedFile.h"
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace KVC {

// a block as one source holds it; empty when the source has no such block
using ExtBlockSource = std::function<std::vector<uint8_t>(uint64_t block)>;

struct ExtInode {
    uint32_t number = 0;
    uint16_t mode = 0;
    uint16_t linksCount = 0;
    uint32_t flags = 0;
    uint32_t generation = 0;
    uint32_t dtime = 0;
    uint32_t mtime = 0;
    uint64_t size = 0;
    uint32_t journalSequence = 0;       // the transaction a journal copy came from; 0: the volume
    uint8_t block[60] = {};             // i_block: extent tree root, block map or inline data

    bool IsDirectory() const { return (mode & 0xF000) == 0x4000; }
    bool IsRegular() const { return (mode & 0xF000) == 0x8000; }
    bool UsesExtents() const { return (flags & 0x00080000) != 0; }
    bool HasInlineData() const { return (flags & 0x10000000) != 0; }
};

struct ExtDirEntry {
    uint32_t inode = 0;
    uint8_t type = 0;                   // 1 file, 2 directory, 7 symlink ...
    std::wstring name;
};

class ExtVolume {
public:
    explicit ExtVolume(DiskHandle& disk);

    bool Open();

    uint64_t BlockSize() const { return m_blockSize; }
    uint64_t BlockCount() const { return m_blockCount; }
    uint32_t InodeCount() const { return m_inodeCount; }
    uint32_t JournalInode() const { return m_journalInode; }
    bool HasFileType() const { return m_fileType; }

    std::vector<uint8_t> ReadBlock(uint64_t block);
    std::vector<uint8_t> ReadBlocks(uint64_t first, uint64_t count);
    ExtBlockSource DiskSource() { return [this](uint64_t b) { return ReadBlock(b); }; }

    // where an inode lies: its inode table block and the offset in it
    bool InodeLocation(uint32_t inode, uint64_t& block, uint32_t& offset) const;
    std::optional<ExtInode> ReadInode(uint32_t inode);
    ExtInode DecodeInode(uint32_t number, const uint8_t* raw) const;
    uint32_t InodeSize() const { return m_inodeSize; }
    bool IsInodeTableBlock(uint64_t block, uint32_t& firstInode) const;

    bool BlockInUse(uint64_t block);
    bool AnyBlockInUse(uint64_t first, uint64_t count);

    // the free blocks of the whole volume, (first block, count), adjacent groups joined
    std::vector<std::pair<uint64_t, uint64_t>> FreeRuns();
    bool InodeInUse(uint32_t inode);

    // the file's blocks as runs (fileOffset = logical block * block size);
    // holes and unwritten extents are left out. Metadata blocks of the map
    // (extent tree nodes, indirect blocks) come from source. complete is
    // false when a part of the map could not be read.
    std::vector<ClusterRun> MapBlocks(const ExtInode& inode, const ExtBlockSource& source, bool& complete);

    // the entries of a directory block; with slack, also those found in the
    // unused room after live entries (older entries a delete only skipped)
    void ParseDirectoryBlock(const std::vector<uint8_t>& block, std::vector<ExtDirEntry>& live,
                             std::vector<ExtDirEntry>* slack) const;

private:
    struct Group {
        uint64_t blockBitmap = 0;
        uint64_t inodeBitmap = 0;
        uint64_t inodeTable = 0;
        uint16_t flags = 0;
    };

    void MapExtents(const uint8_t* node, size_t size, int depthLimit, const ExtBlockSource& source,
                    std::vector<ClusterRun>& runs, bool& complete);
    void MapIndirect(uint64_t block, int level, uint64_t& logical, uint64_t limit, const ExtBlockSource& source,
                     std::vector<ClusterRun>& runs, bool& complete);
    bool ValidEntry(const uint8_t* p, size_t room) const;
    std::wstring DecodeName(const uint8_t* p, size_t length) const;
    std::vector<uint8_t>& Bitmap(std::unordered_map<uint32_t, std::vector<uint8_t>>& cache, uint32_t group, bool blocks);

    DiskHandle& m_disk;
    uint64_t m_blockSize = 0;
    uint64_t m_blockCount = 0;
    uint64_t m_firstDataBlock = 0;
    uint32_t m_inodeCount = 0;
    uint32_t m_inodesPerGroup = 0;
    uint32_t m_blocksPerGroup = 0;
    uint32_t m_inodeSize = 0;
    uint32_t m_journalInode = 0;
    bool m_fileType = false;
    std::vector<Group> m_groups;
    std::vector<std::pair<uint64_t, uint32_t>> m_tables;    // (inode table block, group), sorted
    std::unordered_map<uint32_t, std::vector<uint8_t>> m_blockBitmaps;
    std::unordered_map<uint32_t, std::vector<uint8_t>> m_inodeBitmaps;
};

} // namespace KVC
