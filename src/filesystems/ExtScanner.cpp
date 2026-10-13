// ============================================================================
// ExtScanner.cpp - ext2/ext3/ext4 deleted file scanner
// ============================================================================

#include "filesystems/ExtScanner.h"
#include "filesystems/FilesystemDetector.h"
#include "support/StringUtils.h"
#include "support/BitRange.h"

#include <algorithm>
#include <deque>

namespace KVC {

namespace {

constexpr uint32_t ROOT_INODE = 2;
constexpr uint8_t TYPE_REGULAR = 1;
constexpr uint8_t TYPE_DIRECTORY = 2;
constexpr uint8_t TYPE_UNKNOWN = 0;
constexpr uint16_t EXTENT_MAGIC = 0xF30A;
constexpr size_t MAX_DIRECTORY_BLOCKS = 65536;

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }

// a metadata block worth taking from the journal: an extent node that still
// has entries, or an indirect block that still points somewhere
bool LooksUsed(const std::vector<uint8_t>& b) {
    if (b.size() >= 12 && Le16(b.data()) == EXTENT_MAGIC) {
        return Le16(b.data() + 2) > 0;
    }
    for (size_t i = 0; i + 4 <= b.size() && i < 64; i += 4) {
        if (b[i] | b[i + 1] | b[i + 2] | b[i + 3]) return true;
    }
    return false;
}

std::wstring Join(const std::wstring& dir, const std::wstring& name) {
    return dir.empty() ? name : dir + L"\\" + name;
}

} // namespace

ExtScanner::ExtScanner() = default;
ExtScanner::~ExtScanner() = default;

ExtBlockSource ExtScanner::MetadataSource(Scan& s) {
    return [&s](uint64_t block) {
        return s.journal && s.journal->Loaded() ? s.journal->NewestValid(block, &LooksUsed)
                                                : s.volume->ReadBlock(block);
    };
}

// every version of every inode the journal logged while it was alive
void ExtScanner::CollectInodeVersions(Scan& s, std::atomic<bool>& shouldStop) {
    if (!s.journal || !s.journal->Loaded()) return;
    const uint32_t inodeSize = s.volume->InodeSize();
    for (const auto& [block, copies] : s.journal->All()) {
        if (shouldStop) return;
        uint32_t firstInode = 0;
        if (!s.volume->IsInodeTableBlock(block, firstInode)) continue;
        for (const auto& copy : copies) {               // newest first
            const auto data = s.journal->ReadCopy(copy);
            for (uint32_t k = 0; (k + 1) * inodeSize <= data.size(); ++k) {
                ExtInode i = s.volume->DecodeInode(firstInode + k, data.data() + k * inodeSize);
                if (i.mode == 0 || i.linksCount == 0 || i.dtime != 0) continue;
                i.journalSequence = copy.sequence;
                s.versions[i.number].push_back(i);
            }
        }
    }
}

std::optional<ExtInode> ExtScanner::AliveVersion(Scan& s, uint32_t inode, uint32_t goneAt) {
    auto current = s.volume->ReadInode(inode);
    auto it = s.versions.find(inode);
    if (it != s.versions.end()) {
        // the version the name lived with: the newest before the name was
        // gone - an inode reused by a later file has later versions
        if (goneAt != UINT32_MAX) {
            for (const auto& v : it->second) {
                if (v.journalSequence < goneAt) return v;
            }
            return std::nullopt;
        }
        // otherwise the newest version of the same file (same generation)
        for (const auto& v : it->second) {
            if (!current || v.generation == current->generation) return v;
        }
        return it->second.front();
    }
    // no journal copy: a driver that does not clear the inode may have left it whole
    if (current && current->size > 0 && (current->UsesExtents() ? Le16(current->block) == EXTENT_MAGIC
                                                                 : current->block[0] | current->block[1])) {
        return current;
    }
    return std::nullopt;
}

void ExtScanner::WalkLiveTree(Scan& s, std::atomic<bool>& shouldStop) {
    std::deque<uint32_t> queue{ ROOT_INODE };
    s.dirPath[ROOT_INODE] = L"";
    std::set<uint32_t> visited{ ROOT_INODE };
    while (!queue.empty() && !shouldStop) {
        const uint32_t dir = queue.front();
        queue.pop_front();
        auto inode = s.volume->ReadInode(dir);
        if (!inode || !inode->IsDirectory() || inode->linksCount == 0) continue;
        s.liveInodes.insert(dir);
        bool complete = true;
        const auto runs = s.volume->MapBlocks(*inode, s.volume->DiskSource(), complete);
        for (const auto& run : runs) {
            for (uint64_t b = 0; b < run.clusterCount && b < MAX_DIRECTORY_BLOCKS; ++b) {
                std::vector<ExtDirEntry> live;
                s.volume->ParseDirectoryBlock(s.volume->ReadBlock(run.startCluster + b), live, nullptr);
                for (const auto& e : live) {
                    s.liveNames[dir].insert({ e.name, e.inode });
                    s.liveInodes.insert(e.inode);
                    if (e.type == TYPE_DIRECTORY && visited.insert(e.inode).second) {
                        s.dirPath[e.inode] = Join(s.dirPath[dir], e.name);
                        queue.push_back(e.inode);
                    }
                }
            }
        }
        CollectDirectoryHistory(s, dir, runs, false);
    }
}

// names a directory held: its blocks as they are now (the room a delete
// left) and as the journal saw them before
void ExtScanner::CollectDirectoryHistory(Scan& s, uint32_t directory, const std::vector<ClusterRun>& runs,
                                         bool deletedDirectory) {
    for (const auto& run : runs) {
        for (uint64_t b = 0; b < run.clusterCount && b < MAX_DIRECTORY_BLOCKS; ++b) {
            const uint64_t block = run.startCluster + b;
            std::vector<ExtDirEntry> live, slack;
            s.volume->ParseDirectoryBlock(s.volume->ReadBlock(block), live, &slack);
            if (deletedDirectory) {
                for (const auto& e : live) s.found.push_back({ directory, e });
            }
            for (const auto& e : slack) s.found.push_back({ directory, e });

            const auto* copies = s.journal && s.journal->Loaded() ? s.journal->Copies(block) : nullptr;
            if (!copies) continue;
            // the block's history, oldest first: which names each copy shows
            std::vector<std::pair<uint32_t, std::set<std::pair<std::wstring, uint32_t>>>> history;
            std::map<std::pair<std::wstring, uint32_t>, ExtDirEntry> seen;
            for (auto it = copies->rbegin(); it != copies->rend(); ++it) {
                std::vector<ExtDirEntry> old, oldSlack;
                s.volume->ParseDirectoryBlock(s.journal->ReadCopy(*it), old, &oldSlack);
                std::set<std::pair<std::wstring, uint32_t>> names;
                for (const auto& e : old) { names.insert({ e.name, e.inode }); seen[{ e.name, e.inode }] = e; }
                history.push_back({ it->sequence, std::move(names) });
                for (const auto& e : oldSlack) s.found.push_back({ directory, e });
            }
            // a name is gone from the first copy after its last appearance
            for (const auto& [key, entry] : seen) {
                uint32_t gone = UINT32_MAX;
                bool present = false;
                for (const auto& [sequence, names] : history) {
                    if (names.count(key)) { present = true; gone = UINT32_MAX; }
                    else if (present && gone == UINT32_MAX) gone = sequence;
                }
                s.found.push_back({ directory, entry, gone });
            }
        }
    }
}

// directories that are gone: their old versions in the journal give their
// blocks, the names found so far give their place in the tree
void ExtScanner::ResolveDeletedDirectories(Scan& s) {
    std::set<uint32_t> done;
    for (bool progress = true; progress; ) {
        progress = false;
        for (size_t i = 0; i < s.found.size(); ++i) {
            const Found f = s.found[i];
            if (f.entry.type != TYPE_DIRECTORY || s.liveInodes.count(f.entry.inode) || done.count(f.entry.inode)) continue;
            auto parent = s.dirPath.find(f.directory);
            if (parent == s.dirPath.end()) continue;    // its parent is not placed yet
            auto version = AliveVersion(s, f.entry.inode, f.goneAt);
            if (!version || !version->IsDirectory()) continue;
            done.insert(f.entry.inode);
            s.dirPath[f.entry.inode] = Join(parent->second, f.entry.name);
            bool complete = true;
            const auto runs = s.volume->MapBlocks(*version, MetadataSource(s), complete);
            CollectDirectoryHistory(s, f.entry.inode, runs, true);
            progress = true;
        }
    }
}

void ExtScanner::Report(Scan& s, uint32_t inode, const std::wstring& name, const std::wstring& directory, uint32_t goneAt) {
    auto version = AliveVersion(s, inode, goneAt);
    if (!s.reported.insert({ inode, version ? version->journalSequence : 0 }).second) return;
    if (version && !version->IsRegular()) return;       // a symlink, a device: nothing to recover

    RecoveryCandidate c;
    c.name = name;
    c.directory = directory;
    c.path = L"\\" + Join(directory, name);
    c.mftRecord = inode;                                // tells candidates apart
    c.source = RecoverySource::Ext;
    c.filesystemType = s.fsName;
    c.volumeStartOffset = 0;
    c.file = FragmentedFile(0, s.volume->BlockSize());

    if (!version) {
        c.quality = RecoveryQuality::MetadataOnly;
        c.isRecoverable = false;
        c.sizeFormatted = L"Unknown (inode cleared)";
    } else {
        c.fileSize = c.size = version->size;
        c.writeOrder = version->journalSequence;
        c.sizeFormatted = StringUtils::FormatFileSize(version->size);
        if (version->size == 0) {
            c.quality = RecoveryQuality::Full;
        } else if (version->HasInlineData() && version->size <= sizeof(version->block)) {
            c.file.SetResidentData(std::vector<uint8_t>(version->block, version->block + version->size));
            c.quality = RecoveryQuality::Full;
        } else {
            bool complete = true;
            const auto runs = s.volume->MapBlocks(*version, MetadataSource(s), complete);
            bool overwritten = false;
            FragmentMap map(s.volume->BlockSize(), s.volume->BlockCount());
            for (const auto& run : runs) {
                map.AddRun(run);
                overwritten = overwritten || s.volume->AnyBlockInUse(run.startCluster, run.clusterCount);
            }
            map.SetTotalSize(version->size);
            c.file = FragmentedFile(version->size, s.volume->BlockSize());
            c.file.SetFragmentMap(std::move(map));
            if (runs.empty()) {
                c.quality = RecoveryQuality::MetadataOnly;
                c.isRecoverable = false;
            } else {
                c.quality = complete && !overwritten ? RecoveryQuality::Full : RecoveryQuality::Partial;
                if (overwritten) c.sizeFormatted += L" (overwritten)";
                else if (!complete) c.sizeFormatted += L" (incomplete)";
            }
        }
    }
    ++s.files;
    s.onFileFound(c);
}

FreeSpace ExtScanner::FreeSpaceOf(DiskHandle& disk) {
    FreeSpace free;
    ExtVolume volume(disk);
    if (!volume.Open()) return free;
    free.geometry.sectorSize = disk.GetSectorSize();
    free.geometry.bytesPerCluster = volume.BlockSize();
    free.geometry.totalClusters = volume.BlockCount();
    free.geometry.volumeStartOffset = 0;
    free.geometry.fsType = FilesystemType::Ext;
    free.runs = volume.FreeRuns();
    free.valid = true;
    return free;
}

bool ExtScanner::ScanVolume(
    DiskHandle& disk,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    const ScanConfiguration& config)
{
    (void)config;
    ExtVolume volume(disk);
    if (!volume.Open()) {
        onProgress(L"Cannot read the ext superblock or group descriptors", 1.0f);
        return false;
    }
    ExtJournal journal(volume);
    Scan s;
    s.volume = &volume;
    s.journal = &journal;
    s.fsName = DetectFilesystem(disk).name;
    s.onFileFound = onFileFound;

    onProgress(L"Reading the journal...", 0.05f);
    if (journal.Load(shouldStop)) {
        wchar_t msg[160];
        swprintf_s(msg, L"Journal: %zu blocks with older copies", journal.All().size());
        onProgress(msg, 0.2f);
    } else {
        onProgress(L"No journal: deleted files keep only what their inodes still hold", 0.2f);
    }
    CollectInodeVersions(s, shouldStop);

    onProgress(L"Walking the directory tree...", 0.3f);
    WalkLiveTree(s, shouldStop);
    ResolveDeletedDirectories(s);

    onProgress(L"Matching names with inodes...", 0.7f);
    // a name that is gone from its directory, for an inode nobody uses now
    for (const auto& f : s.found) {
        if (shouldStop) break;
        const auto& e = f.entry;
        if (e.type != TYPE_REGULAR && e.type != TYPE_UNKNOWN) continue;
        if (s.liveNames[f.directory].count({ e.name, e.inode })) continue;
        if (s.liveInodes.count(e.inode) || volume.InodeInUse(e.inode)) continue;     // renamed, or reused
        auto dir = s.dirPath.find(f.directory);
        Report(s, e.inode, e.name, dir == s.dirPath.end() ? L"$Orphans" : dir->second, f.goneAt);
    }

    // inodes the journal saw alive whose names were not found
    for (const auto& [inode, versions] : s.versions) {
        if (shouldStop) break;
        if (s.liveInodes.count(inode) || inode < 11 || volume.InodeInUse(inode)) continue;
        if (!versions.front().IsRegular()) continue;
        auto named = s.reported.lower_bound({ inode, 0 });
        if (named != s.reported.end() && named->first == inode) continue;
        Report(s, inode, L"inode_" + std::to_wstring(inode), L"$Orphans", UINT32_MAX);
    }

    wchar_t msg[160];
    swprintf_s(msg, L"%s scan complete: %llu deleted files found", s.fsName.c_str(), s.files);
    onProgress(msg, 1.0f);
    return true;
}

} // namespace KVC
