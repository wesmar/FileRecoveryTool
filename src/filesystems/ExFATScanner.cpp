// ============================================================================
// ExFATScanner.cpp - exFAT deleted file scanner
// ============================================================================

#include "filesystems/ExFATScanner.h"
#include "support/StringUtils.h"
#include "support/BitRange.h"

#include <algorithm>
#include <cstring>

namespace KVC {

namespace {

constexpr size_t ENTRY = 32;
constexpr uint8_t IN_USE = 0x80;
constexpr uint8_t TYPE_FILE = 0x05;             // with InUse: 0x85
constexpr uint8_t TYPE_STREAM = 0x40;           // 0xC0
constexpr uint8_t TYPE_NAME = 0x41;             // 0xC1
constexpr uint8_t TYPE_BITMAP = 0x81;           // only ever in use
constexpr uint8_t STREAM_NO_FAT_CHAIN = 0x02;
constexpr uint16_t ATTR_DIRECTORY = 0x10;
constexpr uint32_t FAT_BAD = 0xFFFFFFF7;
constexpr uint64_t FAT_PAGE = 64 * 1024;
constexpr uint64_t MAX_DIRECTORY_BYTES = 256ull * 1024 * 1024;  // spec limit
constexpr size_t NAME_CHARS_PER_ENTRY = 15;

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) { return static_cast<uint32_t>(Le16(p)) | (static_cast<uint32_t>(Le16(p + 2)) << 16); }
uint64_t Le64(const uint8_t* p) { return static_cast<uint64_t>(Le32(p)) | (static_cast<uint64_t>(Le32(p + 4)) << 32); }

// exFAT spec 6.3.3: over every byte of the set but the checksum itself
uint16_t EntrySetChecksum(const uint8_t* set, size_t bytes) {
    uint16_t sum = 0;
    for (size_t i = 0; i < bytes; ++i) {
        if (i == 2 || i == 3) continue;
        sum = static_cast<uint16_t>(((sum & 1) ? 0x8000 : 0) + (sum >> 1) + set[i]);
    }
    return sum;
}

} // namespace

ExFATScanner::ExFATScanner() = default;
ExFATScanner::~ExFATScanner() = default;

bool ExFATScanner::InUse(const Volume& v, uint32_t c) const {
    if (!IsCluster(v, c)) return true;
    const uint32_t bit = c - 2;
    if (bit / 8 >= v.bitmap.size()) return true;    // no bitmap: assume the worst
    return (v.bitmap[bit / 8] >> (bit % 8)) & 1;
}

uint32_t ExFATScanner::FatEntry(Volume& v, uint32_t cluster) {
    const uint64_t offset = static_cast<uint64_t>(cluster) * 4;
    const uint64_t page = offset / FAT_PAGE;
    auto it = v.fatPages.find(page);
    if (it == v.fatPages.end()) {
        it = v.fatPages.emplace(page, v.disk->ReadBytes(v.fatOffsetBytes + page * FAT_PAGE, FAT_PAGE)).first;
    }
    const size_t in = static_cast<size_t>(offset % FAT_PAGE);
    return in + 4 <= it->second.size() ? Le32(it->second.data() + in) : 0xFFFFFFFF;
}

std::vector<uint32_t> ExFATScanner::StreamClusters(Volume& v, const Stream& s, bool deleted, bool& intact) {
    intact = true;
    std::vector<uint32_t> clusters;
    if (!IsCluster(v, s.firstCluster) || s.dataLength == 0) {
        return clusters;
    }
    const uint64_t needed = (s.dataLength + v.clusterSize - 1) / v.clusterSize;
    const uint32_t end = v.clusterCount + 2;

    if (s.noFatChain) {
        const uint64_t count = std::min<uint64_t>(needed, end - s.firstCluster);
        clusters.resize(static_cast<size_t>(count));
        for (uint64_t k = 0; k < count; ++k) clusters[static_cast<size_t>(k)] = static_cast<uint32_t>(s.firstCluster + k);
        if (deleted && (v.bitmap.empty() || AnyBitSet(v.bitmap, s.firstCluster - 2, count))) intact = false;
        if (count < needed) intact = false;
        return clusters;
    }

    // along the FAT: still there after a delete, unless the clusters were
    // taken again (the bitmap tells)
    std::set<uint32_t> seen;
    for (uint32_t c = s.firstCluster; IsCluster(v, c) && clusters.size() < needed; ) {
        if (!seen.insert(c).second) break;
        if (deleted && InUse(v, c) && !clusters.empty()) {
            intact = false;
            break;
        }
        clusters.push_back(c);
        const uint32_t next = FatEntry(v, c);
        if (next >= FAT_BAD || !IsCluster(v, next)) break;
        c = next;
    }
    if (clusters.size() < needed && deleted && !clusters.empty()) {
        // the chain ends early (cleared, or cut by reuse): the rest is taken
        // from the free clusters that follow, as on FAT
        intact = false;
        for (uint64_t c = NextClearBit(v.bitmap, clusters.back() + 1 - 2, v.clusterCount);
             c < v.clusterCount && clusters.size() < needed; c = NextClearBit(v.bitmap, c + 1, v.clusterCount)) {
            clusters.push_back(static_cast<uint32_t>(c + 2));
        }
    }
    if (clusters.size() < needed) intact = false;
    if (deleted && InUse(v, s.firstCluster)) intact = false;
    return clusters;
}

std::vector<uint8_t> ExFATScanner::ReadStream(Volume& v, const std::vector<uint32_t>& clusters, uint64_t limit) {
    std::vector<uint8_t> data;
    for (size_t i = 0; i < clusters.size() && data.size() < limit; ) {
        // read runs of consecutive clusters at once
        size_t j = i + 1;
        while (j < clusters.size() && clusters[j] == clusters[j - 1] + 1 && (j - i) * v.clusterSize < 16 * 1024 * 1024) ++j;
        std::vector<uint8_t> block;
        try {
            block = v.reader->ReadClusters(clusters[i] - 2, j - i);
        } catch (const std::exception&) {
            break;
        }
        if (block.empty()) break;
        data.insert(data.end(), block.begin(), block.end());
        i = j;
    }
    if (data.size() > limit) data.resize(static_cast<size_t>(limit));
    return data;
}

bool ExFATScanner::LoadBitmap(Volume& v, const std::vector<uint8_t>& root) {
    for (size_t i = 0; i + ENTRY <= root.size(); i += ENTRY) {
        const uint8_t* e = root.data() + i;
        if (e[0] == 0x00) break;
        if (e[0] == TYPE_BITMAP && (e[1] & 1) == 0) {       // the first bitmap
            Stream s;
            s.firstCluster = Le32(e + 20);
            s.dataLength = Le64(e + 24);
            bool intact = true;
            auto clusters = StreamClusters(v, s, false, intact);
            v.bitmap = ReadStream(v, clusters, s.dataLength);
            return !v.bitmap.empty();
        }
    }
    return false;
}

bool ExFATScanner::OpenVolume(DiskHandle& disk, Volume& v, VolumeGeometry& geom, uint32_t& rootCluster) {
    const auto bootData = disk.ReadBytes(0, sizeof(ExFatBootSector));
    if (bootData.size() < sizeof(ExFatBootSector)) return false;
    ExFatBootSector boot;
    std::memcpy(&boot, bootData.data(), sizeof(boot));
    if (std::memcmp(boot.oemName, "EXFAT   ", 8) != 0 ||
        boot.bytesPerSectorShift < 9 || boot.bytesPerSectorShift > 12 ||
        boot.bytesPerSectorShift + boot.sectorsPerClusterShift > 25) {
        return false;
    }
    v.disk = &disk;
    v.sectorSize = 1ull << boot.bytesPerSectorShift;
    v.clusterSize = v.sectorSize << boot.sectorsPerClusterShift;
    v.heapOffsetBytes = static_cast<uint64_t>(boot.clusterHeapOffset) * v.sectorSize;
    v.fatOffsetBytes = static_cast<uint64_t>(boot.fatOffset) * v.sectorSize;
    v.clusterCount = boot.clusterCount;
    rootCluster = boot.rootDirectoryCluster;

    geom.sectorSize = v.sectorSize;
    geom.bytesPerCluster = v.clusterSize;
    geom.totalClusters = v.clusterCount;
    geom.volumeStartOffset = v.heapOffsetBytes;              // LCN 0 = cluster 2
    geom.fsType = FilesystemType::ExFAT;
    return true;
}

FreeSpace ExFATScanner::FreeSpaceOf(DiskHandle& disk) {
    FreeSpace free;
    Volume v;
    uint32_t rootCluster = 0;
    if (!OpenVolume(disk, v, free.geometry, rootCluster)) return free;
    VolumeReader reader(disk, free.geometry);
    v.reader = &reader;
    Stream root;
    root.firstCluster = rootCluster;
    root.dataLength = MAX_DIRECTORY_BYTES;
    bool intact = true;
    if (!LoadBitmap(v, ReadStream(v, StreamClusters(v, root, false, intact), MAX_DIRECTORY_BYTES))) return free;
    free.runs = ClearRuns(v.bitmap, v.clusterCount);       // bit n: cluster n + 2 = LCN n
    free.valid = true;
    return free;
}

bool ExFATScanner::ScanVolume(
    DiskHandle& disk,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    const ScanConfiguration& config)
{
    Volume v;
    VolumeGeometry geom;
    uint32_t rootCluster = 0;
    if (!OpenVolume(disk, v, geom, rootCluster)) {
        onProgress(L"Not a valid exFAT volume", 1.0f);
        return false;
    }
    v.onFileFound = onFileFound;
    VolumeReader reader(disk, geom);
    v.reader = &reader;

    // the root is a FAT chain of unrecorded length
    Stream root;
    root.firstCluster = rootCluster;
    root.dataLength = MAX_DIRECTORY_BYTES;
    bool intact = true;
    auto rootClusters = StreamClusters(v, root, false, intact);
    const auto rootData = ReadStream(v, rootClusters, MAX_DIRECTORY_BYTES);
    if (!LoadBitmap(v, rootData)) {
        onProgress(L"exFAT: allocation bitmap not found, overwritten clusters cannot be told apart", 0.0f);
    }

    v.visited.insert(root.firstCluster);
    DirectoryWork rootWork;
    rootWork.stream = root;
    ParseDirectory(v, rootWork, rootData);

    uint64_t directories = 1;
    while (!v.queue.empty() && !shouldStop) {
        const DirectoryWork dir = v.queue.front();
        v.queue.pop_front();
        // a deleted directory whose first cluster is taken holds someone else's data
        if (dir.deleted && InUse(v, dir.stream.firstCluster)) continue;
        bool dirIntact = true;
        auto clusters = StreamClusters(v, dir.stream, dir.deleted, dirIntact);
        ParseDirectory(v, dir, ReadStream(v, clusters, std::min(dir.stream.dataLength, MAX_DIRECTORY_BYTES)));

        if ((++directories % 16) == 0) {
            wchar_t msg[256];
            swprintf_s(msg, L"exFAT: %llu directories, %llu deleted files found", directories, v.filesFound);
            onProgress(msg, 0.5f);
        }
        if (directories > config.exfatDirectoryEntriesLimit) {
            onProgress(L"Directory limit reached", 0.9f);
            break;
        }
    }

    wchar_t msg[256];
    swprintf_s(msg, L"exFAT scan complete: %llu directories, %llu deleted files found", directories, v.filesFound);
    onProgress(msg, 1.0f);
    return true;
}

void ExFATScanner::ParseDirectory(Volume& v, const DirectoryWork& dir, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> set;
    for (size_t i = 0; i + ENTRY <= data.size(); ) {
        const uint8_t type = data[i];
        if (type == 0x00) break;                            // end of directory
        if ((type & 0x7F) != TYPE_FILE) {
            i += ENTRY;
            continue;
        }
        const size_t secondary = data[i + 1];
        const size_t bytes = (secondary + 1) * ENTRY;
        if (secondary < 2 || i + bytes > data.size()) {
            i += ENTRY;
            continue;
        }

        // a deleted set has every InUse bit cleared; the checksum was made
        // with them set
        set.assign(data.begin() + static_cast<ptrdiff_t>(i), data.begin() + static_cast<ptrdiff_t>(i + bytes));
        const bool setDeleted = !(type & IN_USE);
        for (size_t k = 0; k < bytes; k += ENTRY) set[k] |= IN_USE;
        if (EntrySetChecksum(set.data(), bytes) != Le16(set.data() + 2) ||
            set[ENTRY] != (TYPE_STREAM | IN_USE)) {
            i += ENTRY;                                     // not a whole set: overwritten in part
            continue;
        }

        const uint8_t* file = set.data();
        const uint8_t* stream = set.data() + ENTRY;
        const bool isDir = (Le16(file + 4) & ATTR_DIRECTORY) != 0;
        Stream s;
        s.noFatChain = (stream[1] & STREAM_NO_FAT_CHAIN) != 0;
        s.validDataLength = Le64(stream + 8);
        s.firstCluster = Le32(stream + 20);
        s.dataLength = Le64(stream + 24);
        const size_t nameLength = stream[3];

        std::wstring name;
        for (size_t k = 2; k <= secondary && name.size() < nameLength; ++k) {
            const uint8_t* e = set.data() + k * ENTRY;
            if (e[0] != (TYPE_NAME | IN_USE)) continue;
            for (size_t c = 0; c < NAME_CHARS_PER_ENTRY && name.size() < nameLength; ++c) {
                name += static_cast<wchar_t>(Le16(e + 2 + c * 2));
            }
        }
        i += bytes;
        if (name.empty()) continue;

        const bool deleted = setDeleted || dir.deleted;
        const std::wstring path = dir.path.empty() ? name : dir.path + L"\\" + name;

        if (isDir) {
            if (IsCluster(v, s.firstCluster) && v.visited.insert(s.firstCluster).second) {
                DirectoryWork work;
                work.stream = s;
                work.path = path;
                work.deleted = deleted;
                v.queue.push_back(work);
            }
            continue;
        }
        if (!deleted) continue;

        RecoveryCandidate candidate;
        candidate.name = name;
        candidate.directory = dir.path;
        candidate.path = L"\\" + path;
        candidate.fileSize = s.dataLength;
        candidate.size = s.dataLength;
        candidate.sizeFormatted = StringUtils::FormatFileSize(s.dataLength);
        candidate.source = RecoverySource::ExFAT;
        candidate.writeOrder = (static_cast<uint64_t>(Le32(file + 8)) << 8) | file[20];
        candidate.filesystemType = L"exFAT";
        candidate.volumeStartOffset = v.heapOffsetBytes;
        candidate.file = FragmentedFile(s.dataLength, v.clusterSize);
        if (s.validDataLength < s.dataLength) {
            candidate.validLength = s.validDataLength;
        }

        if (s.dataLength == 0) {
            candidate.quality = RecoveryQuality::Full;
        } else if (!IsCluster(v, s.firstCluster)) {
            candidate.quality = RecoveryQuality::MetadataOnly;
            candidate.isRecoverable = false;
        } else {
            bool intact = true;
            auto clusters = StreamClusters(v, s, true, intact);
            std::vector<uint64_t> lcns;
            lcns.reserve(clusters.size());
            for (uint32_t c : clusters) lcns.push_back(static_cast<uint64_t>(c) - 2);
            FragmentMap map(v.clusterSize);
            map.BuildFromClusterList(lcns);
            candidate.file.SetFragmentMap(std::move(map));
            candidate.quality = intact ? RecoveryQuality::Full : RecoveryQuality::Partial;
            if (InUse(v, s.firstCluster)) {
                candidate.sizeFormatted += L" (overwritten)";
            }
        }
        ++v.filesFound;
        v.onFileFound(candidate);
    }
}

} // namespace KVC
