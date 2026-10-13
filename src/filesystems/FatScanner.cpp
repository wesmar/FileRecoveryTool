// ============================================================================
// FatScanner.cpp - FAT12/FAT16/FAT32 deleted file scanner
// ============================================================================

#include "filesystems/FatScanner.h"
#include "support/StringUtils.h"
#include "support/BitRange.h"

#include <algorithm>
#include <cstring>

namespace KVC {

namespace {

constexpr size_t ENTRY = 32;
constexpr uint8_t ATTR_READ_ONLY = 0x01;
constexpr uint8_t ATTR_HIDDEN = 0x02;
constexpr uint8_t ATTR_SYSTEM = 0x04;
constexpr uint8_t ATTR_VOLUME_ID = 0x08;
constexpr uint8_t ATTR_DIRECTORY = 0x10;
constexpr uint8_t ATTR_LONG_NAME = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
constexpr uint8_t ENTRY_FREE = 0xE5;            // first byte of a deleted entry
constexpr uint8_t ENTRY_KANJI_E5 = 0x05;        // a name that really starts with 0xE5
constexpr uint8_t LFN_LAST = 0x40;
constexpr uint8_t NT_LOWER_BASE = 0x08;         // byte 12: Windows NT case flags
constexpr uint8_t NT_LOWER_EXT = 0x10;
constexpr uint64_t MAX_DIRECTORY_BYTES = 65536 * ENTRY;     // FAT spec: 65536 entries

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) { return static_cast<uint32_t>(Le16(p)) | (static_cast<uint32_t>(Le16(p + 2)) << 16); }

uint8_t ShortNameChecksum(const uint8_t* name11) {
    uint8_t sum = 0;
    for (int i = 0; i < 11; ++i) {
        sum = static_cast<uint8_t>(((sum & 1) << 7) + (sum >> 1) + name11[i]);
    }
    return sum;
}

// OEM bytes of a short name: the volume was written in some OEM code page;
// the current one is the best guess there is
std::wstring OemToWide(const uint8_t* bytes, size_t length) {
    if (length == 0) return {};
    wchar_t out[16] = {};
    const int n = MultiByteToWideChar(CP_OEMCP, 0, reinterpret_cast<const char*>(bytes), static_cast<int>(length), out, 16);
    return std::wstring(out, n > 0 ? static_cast<size_t>(n) : 0);
}

std::wstring ShortName(const uint8_t* raw, bool deleted) {
    uint8_t name[11];
    std::memcpy(name, raw, 11);
    if (name[0] == ENTRY_KANJI_E5) name[0] = 0xE5;
    if (deleted) name[0] = '_';                 // the first character is gone

    size_t baseLen = 8, extLen = 3;
    while (baseLen > 0 && name[baseLen - 1] == ' ') --baseLen;
    while (extLen > 0 && name[8 + extLen - 1] == ' ') --extLen;

    std::wstring base = OemToWide(name, baseLen);
    std::wstring ext = OemToWide(name + 8, extLen);
    if (raw[12] & NT_LOWER_BASE) std::transform(base.begin(), base.end(), base.begin(), ::towlower);
    if (raw[12] & NT_LOWER_EXT) std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    return ext.empty() ? base : base + L"." + ext;
}

// one LFN entry's 13 characters, up to the terminator
std::wstring LfnPart(const uint8_t* raw) {
    static const int offsets[] = { 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
    std::wstring part;
    for (int off : offsets) {
        const wchar_t c = static_cast<wchar_t>(Le16(raw + off));
        if (c == 0 || c == 0xFFFF) break;
        part += c;
    }
    return part;
}

} // namespace

// ============================================================================
// FatTable
// ============================================================================

FatTable::FatTable(DiskHandle& disk, const FatLayout& layout)
    : m_disk(disk), m_layout(layout), m_fatBytes(layout.fatSectors * layout.bytesPerSector)
{
}

uint8_t FatTable::ByteAt(uint64_t offset) {
    if (offset >= m_fatBytes) return 0xFF;
    const uint64_t page = offset / PAGE_BYTES;
    auto it = m_pages.find(page);
    if (it == m_pages.end()) {
        const uint64_t start = page * PAGE_BYTES;
        auto data = m_disk.ReadBytes(m_layout.fatStartSector * m_layout.bytesPerSector + start,
                                     std::min(PAGE_BYTES, m_fatBytes - start));
        it = m_pages.emplace(page, std::move(data)).first;
    }
    const uint64_t inPage = offset % PAGE_BYTES;
    return inPage < it->second.size() ? it->second[static_cast<size_t>(inPage)] : 0xFF;
}

uint32_t FatTable::Entry(uint32_t cluster) {
    switch (m_layout.type) {
    case FilesystemType::FAT12: {
        const uint64_t off = static_cast<uint64_t>(cluster) + cluster / 2;
        const uint32_t v = ByteAt(off) | (static_cast<uint32_t>(ByteAt(off + 1)) << 8);
        return (cluster & 1) ? (v >> 4) : (v & 0x0FFF);
    }
    case FilesystemType::FAT16: {
        const uint64_t off = static_cast<uint64_t>(cluster) * 2;
        return ByteAt(off) | (static_cast<uint32_t>(ByteAt(off + 1)) << 8);
    }
    default: {
        const uint64_t off = static_cast<uint64_t>(cluster) * 4;
        return (ByteAt(off) | (static_cast<uint32_t>(ByteAt(off + 1)) << 8) |
                (static_cast<uint32_t>(ByteAt(off + 2)) << 16) | (static_cast<uint32_t>(ByteAt(off + 3)) << 24)) & 0x0FFFFFFF;
    }
    }
}

uint32_t FatTable::NextFree(uint32_t from) {
    if (m_used.empty()) {
        m_used.assign((static_cast<size_t>(m_layout.clusterCount) + 7) / 8, 0);
        for (uint32_t c = 0; c < m_layout.clusterCount; ++c) {
            if (Entry(c + 2) != 0) m_used[c / 8] |= static_cast<uint8_t>(1u << (c % 8));
        }
    }
    if (from < 2) from = 2;
    const uint64_t index = NextClearBit(m_used, from - 2, m_layout.clusterCount);
    return index < m_layout.clusterCount ? static_cast<uint32_t>(index + 2) : 0;
}

bool FatTable::IsChainEnd(uint32_t value) const {
    const uint32_t bad = m_layout.type == FilesystemType::FAT12 ? 0xFF7 :
                         m_layout.type == FilesystemType::FAT16 ? 0xFFF7 : 0x0FFFFFF7;
    return value >= bad || !IsCluster(value);
}

// ============================================================================
// FatScanner
// ============================================================================

FatScanner::FatScanner() = default;
FatScanner::~FatScanner() = default;

bool FatScanner::ScanVolume(
    DiskHandle& disk,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    const ScanConfiguration& config)
{
    const auto boot = disk.ReadBytes(0, 512);
    const auto layout = ParseFatBootSector(boot.data(), boot.size());
    if (!layout) {
        onProgress(L"Not a FAT volume", 1.0f);
        return false;
    }

    FatTable fat(disk, *layout);
    VolumeGeometry geom;
    geom.sectorSize = layout->bytesPerSector;
    geom.bytesPerCluster = layout->clusterSize;
    geom.totalClusters = layout->clusterCount;
    geom.volumeStartOffset = layout->dataStartSector * layout->bytesPerSector;   // LCN 0 = cluster 2
    geom.fsType = layout->type;
    VolumeReader reader(disk, geom);

    Context ctx;
    ctx.disk = &disk;
    ctx.layout = *layout;
    ctx.fat = &fat;
    ctx.reader = &reader;
    ctx.onFileFound = onFileFound;
    if (layout->type == FilesystemType::FAT32) {
        ctx.queue.push_back({ layout->rootCluster, L"", false });
        ctx.visited.insert(layout->rootCluster);
    } else {
        ctx.queue.push_back({ 0, L"", false });
    }

    uint64_t directories = 0;
    while (!ctx.queue.empty() && !shouldStop) {
        const DirectoryWork dir = ctx.queue.front();
        ctx.queue.pop_front();
        ParseDirectory(ctx, dir, ReadDirectory(ctx, dir));

        if ((++directories % 16) == 0) {
            wchar_t msg[256];
            swprintf_s(msg, L"%s: %llu directories, %llu deleted files found",
                       FilesystemName(layout->type), directories, ctx.filesFound);
            onProgress(msg, 0.5f);
        }
        if (directories > config.exfatDirectoryEntriesLimit) {
            onProgress(L"Directory limit reached", 0.9f);
            break;
        }
    }

    wchar_t msg[256];
    swprintf_s(msg, L"%s scan complete: %llu directories, %llu deleted files found",
               FilesystemName(layout->type), directories, ctx.filesFound);
    onProgress(msg, 1.0f);
    return true;
}

FreeSpace FatScanner::FreeSpaceOf(DiskHandle& disk) {
    FreeSpace free;
    const auto boot = disk.ReadBytes(0, 512);
    const auto layout = ParseFatBootSector(boot.data(), boot.size());
    if (!layout) return free;
    FatTable fat(disk, *layout);
    free.geometry.sectorSize = layout->bytesPerSector;
    free.geometry.bytesPerCluster = layout->clusterSize;
    free.geometry.totalClusters = layout->clusterCount;
    free.geometry.volumeStartOffset = layout->dataStartSector * layout->bytesPerSector;
    free.geometry.fsType = layout->type;
    free.runs = ClearRuns(fat.Used(), layout->clusterCount);     // bit n: cluster n + 2 = LCN n
    free.valid = true;
    return free;
}

std::vector<uint8_t> FatScanner::ReadDirectory(Context& ctx, const DirectoryWork& dir) {
    const FatLayout& L = ctx.layout;
    if (dir.firstCluster == 0) {                // the fixed FAT12/16 root
        return ctx.disk->ReadBytes(L.rootDirStartSector * L.bytesPerSector, L.rootDirSectors * L.bytesPerSector);
    }

    const uint64_t maxClusters = std::max<uint64_t>(1, MAX_DIRECTORY_BYTES / L.clusterSize);
    std::vector<uint32_t> clusters;
    if (!dir.deleted) {
        std::set<uint32_t> chain;
        for (uint32_t c = dir.firstCluster; ctx.fat->IsCluster(c) && clusters.size() < maxClusters; ) {
            if (!chain.insert(c).second) break;                 // a loop in a damaged FAT
            clusters.push_back(c);
            const uint32_t next = ctx.fat->Entry(c);
            if (ctx.fat->IsChainEnd(next)) break;
            c = next;
        }
    } else {
        clusters = GuessDeletedClusters(ctx, dir.firstCluster, maxClusters);
    }

    std::vector<uint8_t> data;
    for (size_t i = 0; i < clusters.size(); ++i) {
        std::vector<uint8_t> block;
        try {
            block = ctx.reader->ReadClusters(clusters[i] - 2, 1);
        } catch (const std::exception&) {
            break;
        }
        if (block.empty()) break;
        if (dir.deleted && i == 0) {
            // still a directory only when it starts with its "." entry
            if (block.size() < ENTRY || std::memcmp(block.data(), ".          ", 11) != 0 ||
                !(block[11] & ATTR_DIRECTORY)) {
                return {};
            }
        }
        const size_t before = data.size();
        data.insert(data.end(), block.begin(), block.end());
        if (dir.deleted) {
            // a deleted directory's size is unknown: it ends at its end marker
            bool end = false;
            for (size_t k = before; k + ENTRY <= data.size(); k += ENTRY) {
                if (data[k] == 0x00) { end = true; break; }
            }
            if (end) break;
        }
    }
    return data;
}

void FatScanner::ParseDirectory(Context& ctx, const DirectoryWork& dir, const std::vector<uint8_t>& data) {
    struct LfnPiece { uint8_t checksum; std::wstring text; };
    std::vector<LfnPiece> lfn;          // in disk order: the name's last part first

    for (size_t off = 0; off + ENTRY <= data.size(); off += ENTRY) {
        const uint8_t* raw = data.data() + off;
        const uint8_t first = raw[0];
        const uint8_t attr = raw[11];
        if (first == 0x00) {
            break;                                  // nothing was ever written past this
        }
        const bool deleted = first == ENTRY_FREE || dir.deleted;

        if ((attr & 0x3F) == ATTR_LONG_NAME) {
            const uint8_t checksum = raw[13];
            if ((first != ENTRY_FREE && (first & LFN_LAST)) || (!lfn.empty() && lfn.back().checksum != checksum)) {
                lfn.clear();                        // a new name starts
            }
            lfn.push_back({ checksum, LfnPart(raw) });
            continue;
        }
        if ((attr & ATTR_VOLUME_ID) || raw[0] == '.') {
            lfn.clear();                            // the label, "." and ".."
            continue;
        }

        // the long name belongs to this entry when its checksum matches; for a
        // deleted entry the first byte is gone, so any first byte may match
        std::wstring name;
        if (!lfn.empty()) {
            uint8_t name11[11];
            std::memcpy(name11, raw, 11);
            if (name11[0] == ENTRY_KANJI_E5) name11[0] = 0xE5;
            bool match = ShortNameChecksum(name11) == lfn.front().checksum;
            for (int c = 0x20; !match && first == ENTRY_FREE && c < 0x100; ++c) {
                name11[0] = static_cast<uint8_t>(c);
                match = ShortNameChecksum(name11) == lfn.front().checksum;
            }
            if (match) {
                for (auto it = lfn.rbegin(); it != lfn.rend(); ++it) name += it->text;
            }
        }
        if (name.empty()) {
            name = ShortName(raw, first == ENTRY_FREE);
        }
        lfn.clear();

        const uint32_t cluster = ctx.layout.type == FilesystemType::FAT32
            ? (static_cast<uint32_t>(Le16(raw + 20)) << 16) | Le16(raw + 26)
            : Le16(raw + 26);
        const std::wstring path = dir.path.empty() ? name : dir.path + L"\\" + name;

        if (attr & ATTR_DIRECTORY) {
            if (ctx.fat->IsCluster(cluster) && ctx.visited.insert(cluster).second) {
                ctx.queue.push_back({ cluster, path, deleted });
            }
            continue;
        }
        if (deleted) {
            // creation date, time and 10 ms units: comparable as one number
            const uint64_t created = (static_cast<uint64_t>(Le16(raw + 16)) << 24) | (static_cast<uint64_t>(Le16(raw + 14)) << 8) | raw[13];
            ReportDeletedFile(ctx, dir, name, cluster, Le32(raw + 28), created);
        }
    }
}

std::vector<uint32_t> FatScanner::GuessDeletedClusters(Context& ctx, uint32_t firstCluster, uint64_t count) {
    std::vector<uint32_t> clusters;
    if (!ctx.fat->IsCluster(firstCluster) || count == 0) {
        return clusters;
    }
    clusters.push_back(firstCluster);               // where the data started, free or not
    for (uint32_t c = ctx.fat->NextFree(firstCluster + 1); c != 0 && clusters.size() < count; c = ctx.fat->NextFree(c + 1)) {
        clusters.push_back(c);
    }
    return clusters;
}

void FatScanner::ReportDeletedFile(Context& ctx, const DirectoryWork& dir, const std::wstring& name,
                                   uint32_t firstCluster, uint32_t size, uint64_t created) {
    const FatLayout& L = ctx.layout;
    RecoveryCandidate candidate;
    candidate.name = name;
    candidate.directory = dir.path;
    candidate.path = L"\\" + (dir.path.empty() ? name : dir.path + L"\\" + name);
    candidate.fileSize = size;
    candidate.size = size;
    candidate.sizeFormatted = StringUtils::FormatFileSize(size);
    candidate.source = RecoverySource::FAT32;
    candidate.writeOrder = created;
    candidate.filesystemType = FilesystemName(L.type);
    candidate.volumeStartOffset = L.dataStartSector * L.bytesPerSector;
    candidate.file = FragmentedFile(size, L.clusterSize);

    if (size == 0) {
        candidate.quality = RecoveryQuality::Full;  // nothing to lose
    } else if (!ctx.fat->IsCluster(firstCluster)) {
        candidate.quality = RecoveryQuality::MetadataOnly;
        candidate.isRecoverable = false;
    } else {
        const uint64_t needed = (static_cast<uint64_t>(size) + L.clusterSize - 1) / L.clusterSize;
        const bool startFree = ctx.fat->IsFree(firstCluster);
        auto clusters = GuessDeletedClusters(ctx, firstCluster, needed);
        std::vector<uint64_t> lcns;
        lcns.reserve(clusters.size());
        for (uint32_t c : clusters) lcns.push_back(static_cast<uint64_t>(c) - 2);

        FragmentMap map(L.clusterSize);
        map.BuildFromClusterList(lcns);
        map.SetTotalSize(size);
        candidate.file.SetFragmentMap(std::move(map));

        // a reused first cluster means another file wrote over the start
        candidate.quality = (startFree && clusters.size() == needed) ? RecoveryQuality::Full : RecoveryQuality::Partial;
        if (!startFree) {
            candidate.sizeFormatted += L" (overwritten)";
        }
    }
    ++ctx.filesFound;
    ctx.onFileFound(candidate);
}

} // namespace KVC
