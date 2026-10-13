// ============================================================================
// FatScanner.h - FAT12/FAT16/FAT32 deleted file scanner
// ============================================================================
// Walks the directory tree - live directories along their FAT chains, deleted
// ones from their first cluster - and reports deleted entries. A deleted
// file's FAT chain is zeroed, so its clusters are taken from its first one
// onwards, the free ones only: clusters still allocated belong to files that
// survived, and a file written next to one of them continues past it.
// ============================================================================

#pragma once

#include "core/DiskForensicsCore.h"
#include "filesystems/FilesystemDetector.h"
#include "io/VolumeReader.h"
#include <atomic>
#include <deque>
#include <optional>
#include <set>
#include <unordered_map>

namespace KVC {

// The first FAT, read a page at a time as entries are asked for
class FatTable {
public:
    FatTable(DiskHandle& disk, const FatLayout& layout);

    // the entry of a cluster, masked to its width (12, 16 or 28 bits)
    uint32_t Entry(uint32_t cluster);
    bool IsFree(uint32_t cluster) { return Entry(cluster) == 0; }
    bool IsChainEnd(uint32_t value) const;      // end of chain, bad cluster or out of range
    bool IsCluster(uint32_t value) const { return value >= 2 && value < m_layout.clusterCount + 2; }

    // the first cluster at or after rom that no file holds, or 0; the
    // whole FAT is read once, on the first question
    uint32_t NextFree(uint32_t from);
    const std::vector<uint8_t>& Used() { NextFree(2); return m_used; }

private:
    uint8_t ByteAt(uint64_t offset);

    static constexpr uint64_t PAGE_BYTES = 64 * 1024;
    DiskHandle& m_disk;
    FatLayout m_layout;
    uint64_t m_fatBytes;
    std::unordered_map<uint64_t, std::vector<uint8_t>> m_pages;
    std::vector<uint8_t> m_used;                // bit n: cluster n + 2 is held
};

class FatScanner {
public:
    FatScanner();
    ~FatScanner();

    // the clusters the FAT shows free, for carving
    FreeSpace FreeSpaceOf(DiskHandle& disk);

    bool ScanVolume(
        DiskHandle& disk,
        DiskForensicsCore::FileFoundCallback onFileFound,
        DiskForensicsCore::ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        const ScanConfiguration& config
    );

private:
    struct DirectoryWork {
        uint32_t firstCluster;      // 0: the FAT12/16 root region
        std::wstring path;          // relative to the root, '\' separated
        bool deleted;               // the directory itself was deleted
    };

    struct Context {
        DiskHandle* disk = nullptr;
        FatLayout layout;
        FatTable* fat = nullptr;
        VolumeReader* reader = nullptr;
        DiskForensicsCore::FileFoundCallback onFileFound;
        std::deque<DirectoryWork> queue;
        std::set<uint32_t> visited;
        uint64_t filesFound = 0;
    };

    std::vector<uint8_t> ReadDirectory(Context& ctx, const DirectoryWork& dir);
    void ParseDirectory(Context& ctx, const DirectoryWork& dir, const std::vector<uint8_t>& data);
    void ReportDeletedFile(Context& ctx, const DirectoryWork& dir, const std::wstring& name,
                           uint32_t firstCluster, uint32_t size, uint64_t created);

    // clusters of a deleted file or directory: the free ones from the first
    std::vector<uint32_t> GuessDeletedClusters(Context& ctx, uint32_t firstCluster, uint64_t count);
};

} // namespace KVC
