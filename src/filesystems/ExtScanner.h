// ============================================================================
// ExtScanner.h - ext2/ext3/ext4 deleted file scanner
// ============================================================================
// A delete on Linux leaves little on the volume: the inode keeps its mode
// and times but loses its size and block map, and since Linux 5.14 the
// directory entry is wiped as well. What the delete did not reach is the
// journal (ext3, ext4): its older copies of directory blocks name the files,
// its older copies of inode table blocks give their size and blocks, and
// the blocks themselves stay until another file takes them - which the
// block bitmap tells. Directory entries a delete only skipped (older Linux,
// other drivers) are read from the room after live entries as well.
// ============================================================================

#pragma once

#include "core/DiskForensicsCore.h"
#include "filesystems/ExtFilesystem.h"
#include "filesystems/ExtJournal.h"
#include <atomic>
#include <map>
#include <set>
#include <unordered_map>

namespace KVC {

class ExtScanner {
public:
    ExtScanner();
    ~ExtScanner();

    // the blocks the block bitmaps show free, for carving
    FreeSpace FreeSpaceOf(DiskHandle& disk);

    bool ScanVolume(
        DiskHandle& disk,
        DiskForensicsCore::FileFoundCallback onFileFound,
        DiskForensicsCore::ProgressCallback onProgress,
        std::atomic<bool>& shouldStop,
        const ScanConfiguration& config
    );

private:
    struct Found {                      // a name seen for an inode in a directory
        uint32_t directory;
        ExtDirEntry entry;
        uint32_t goneAt = UINT32_MAX;   // first transaction whose copy no longer shows it; MAX: unknown
    };

    struct Scan {
        ExtVolume* volume = nullptr;
        ExtJournal* journal = nullptr;
        std::wstring fsName;
        DiskForensicsCore::FileFoundCallback onFileFound;
        // inode -> its versions in the journal while it was alive, newest first
        std::unordered_map<uint32_t, std::vector<ExtInode>> versions;
        std::unordered_map<uint32_t, std::wstring> dirPath;         // directory inode -> path
        std::unordered_map<uint32_t, std::set<std::pair<std::wstring, uint32_t>>> liveNames;
        std::set<uint32_t> liveInodes;                               // reachable from the root now
        std::vector<Found> found;
        std::set<std::pair<uint32_t, uint32_t>> reported;           // (inode, version)
        uint64_t files = 0;
    };

    void CollectInodeVersions(Scan& s, std::atomic<bool>& shouldStop);
    void WalkLiveTree(Scan& s, std::atomic<bool>& shouldStop);
    void CollectDirectoryHistory(Scan& s, uint32_t directory, const std::vector<ClusterRun>& runs,
                                 bool deletedDirectory);
    void ResolveDeletedDirectories(Scan& s);
    void Report(Scan& s, uint32_t inode, const std::wstring& name, const std::wstring& directory, uint32_t goneAt);
    std::optional<ExtInode> AliveVersion(Scan& s, uint32_t inode, uint32_t goneAt);
    ExtBlockSource MetadataSource(Scan& s);
};

} // namespace KVC
