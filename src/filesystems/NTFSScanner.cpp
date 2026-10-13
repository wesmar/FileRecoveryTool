// ============================================================================
// NTFSScanner.cpp - NTFS deleted file scanner
// ============================================================================

#include "filesystems/NTFSScanner.h"
#include "core/RecoveryCandidate.h"
#include "support/SafetyLimits.h"
#include "support/StringUtils.h"
#include "support/BitRange.h"

#include <algorithm>
#include <cstring>

namespace KVC {

namespace {

constexpr uint32_t ATTR_ATTRIBUTE_LIST = 0x20;
constexpr uint32_t ATTR_FILE_NAME = 0x30;
constexpr uint32_t ATTR_DATA = 0x80;
constexpr uint32_t ATTR_END = 0xFFFFFFFF;
constexpr uint16_t RECORD_IN_USE = 0x0001;
constexpr uint16_t RECORD_DIRECTORY = 0x0002;
constexpr uint16_t ATTR_FLAG_COMPRESSED = 0x0001;
constexpr uint16_t ATTR_FLAG_ENCRYPTED = 0x4000;
constexpr uint8_t NAMESPACE_DOS = 2;
constexpr uint64_t ROOT_RECORD = 5;
constexpr uint64_t BITMAP_RECORD = 6;
constexpr uint64_t EXTEND_RECORD = 11;
constexpr uint64_t FIRST_USER_RECORD = 16;
constexpr uint64_t REFERENCE_MASK = 0x0000FFFFFFFFFFFFull;
constexpr size_t FIXUP_STRIDE = 512;            // NTFS fixes up every 512 bytes, whatever the sector size
constexpr uint64_t MFT_CHUNK_BYTES = 4 * 1024 * 1024;
constexpr uint64_t MAX_BITMAP_BYTES = 512ull * 1024 * 1024;
constexpr size_t MAX_PATH_DEPTH = 256;

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) { return static_cast<uint32_t>(Le16(p)) | (static_cast<uint32_t>(Le16(p + 2)) << 16); }
uint64_t Le64(const uint8_t* p) { return static_cast<uint64_t>(Le32(p)) | (static_cast<uint64_t>(Le32(p + 4)) << 32); }

std::wstring Utf16(const uint8_t* p, size_t chars) {
    std::wstring s(chars, L'\0');
    for (size_t i = 0; i < chars; ++i) s[i] = static_cast<wchar_t>(Le16(p + 2 * i));
    return s;
}

const NtfsAttribute* FindAttribute(const NtfsRecord& r, uint32_t type, const std::wstring& name = L"") {
    for (const auto& a : r.attributes) {
        if (a.type == type && a.name == name) return &a;
    }
    return nullptr;
}

struct FileName {
    std::wstring name;
    uint64_t parent = 0;
    uint16_t parentSequence = 0;
    bool found = false;
};

// the record's name: Win32 or POSIX before the DOS 8.3 one
FileName BestFileName(const NtfsRecord& r) {
    FileName best;
    int bestRank = -1;
    for (const auto& a : r.attributes) {
        if (a.type != ATTR_FILE_NAME || a.nonResident || a.value.size() < 66) continue;
        const uint8_t* v = a.value.data();
        const size_t chars = v[64];
        const uint8_t space = v[65];
        if (66 + chars * 2 > a.value.size()) continue;
        const int rank = space == NAMESPACE_DOS ? 0 : 1;
        if (rank > bestRank) {
            bestRank = rank;
            best.name = Utf16(v + 66, chars);
            best.parent = Le64(v) & REFERENCE_MASK;
            best.parentSequence = static_cast<uint16_t>(Le64(v) >> 48);
            best.found = true;
        }
    }
    return best;
}

} // namespace

NTFSScanner::NTFSScanner() = default;
NTFSScanner::~NTFSScanner() = default;

NTFSBootSector NTFSScanner::ReadBootSector(DiskHandle& disk) {
    NTFSBootSector boot = {};
    const auto data = disk.ReadBytes(0, 512);
    if (data.size() >= sizeof(NTFSBootSector)) {
        std::memcpy(&boot, data.data(), sizeof(NTFSBootSector));
    }
    return boot;
}

bool NTFSScanner::ApplyFixups(std::vector<uint8_t>& rec) const {
    if (rec.size() < 48) return false;
    const uint16_t usaOffset = Le16(rec.data() + 4);
    const uint16_t usaCount = Le16(rec.data() + 6);
    if (usaCount == 0 || usaOffset + static_cast<size_t>(usaCount) * 2 > rec.size()) return false;
    const uint16_t usn = Le16(rec.data() + usaOffset);
    bool torn = false;
    for (size_t i = 1; i < usaCount; ++i) {
        const size_t end = i * FIXUP_STRIDE - 2;
        if (end + 2 > rec.size()) break;
        if (Le16(rec.data() + end) != usn) {
            torn = true;                            // a sector of a half-written record
            continue;
        }
        rec[end] = rec[usaOffset + 2 * i];
        rec[end + 1] = rec[usaOffset + 2 * i + 1];
    }
    return !torn;
}

std::vector<ClusterRun> NTFSScanner::DecodeRuns(const uint8_t* data, size_t size, uint64_t startVcn, bool& valid) const {
    std::vector<ClusterRun> runs;
    valid = false;
    uint64_t vcn = startVcn;
    int64_t lcn = 0;
    size_t i = 0;
    while (i < size) {
        const uint8_t header = data[i++];
        if (header == 0) {
            valid = true;
            break;
        }
        const uint8_t lenBytes = header & 0x0F;
        const uint8_t offBytes = header >> 4;
        if (lenBytes == 0 || lenBytes > 8 || offBytes > 8 || i + lenBytes + offBytes > size) {
            break;
        }
        uint64_t length = 0;
        for (uint8_t k = 0; k < lenBytes; ++k) length |= static_cast<uint64_t>(data[i + k]) << (8 * k);
        i += lenBytes;
        if (length == 0 || length > Limits::MAX_CLUSTER_NUMBER) break;
        if (offBytes == 0) {
            vcn += length;                          // sparse: a hole, no clusters
            continue;
        }
        int64_t delta = 0;
        for (uint8_t k = 0; k < offBytes; ++k) delta |= static_cast<int64_t>(data[i + k]) << (8 * k);
        if (data[i + offBytes - 1] & 0x80) {
            for (uint8_t k = offBytes; k < 8; ++k) delta |= static_cast<int64_t>(0xFF) << (8 * k);
        }
        i += offBytes;
        lcn += delta;
        if (lcn < 0 || (m_totalClusters && static_cast<uint64_t>(lcn) + length > m_totalClusters)) break;
        runs.emplace_back(static_cast<uint64_t>(lcn), length, vcn * m_clusterSize);
        vcn += length;
        if (runs.size() > Limits::MAX_FRAGMENTS_PER_FILE) break;
    }
    return runs;
}

bool NTFSScanner::DecodeRecord(const std::vector<uint8_t>& raw, NtfsRecord& out) const {
    if (raw.size() < 48 || std::memcmp(raw.data(), "FILE", 4) != 0) return false;
    out = NtfsRecord{};
    out.lsn = Le64(raw.data() + 8);
    out.sequence = Le16(raw.data() + 16);
    out.flags = Le16(raw.data() + 22);
    out.baseRecord = Le64(raw.data() + 32) & REFERENCE_MASK;
    out.baseSequence = static_cast<uint16_t>(Le64(raw.data() + 32) >> 48);
    size_t off = Le16(raw.data() + 20);
    const size_t used = std::min<size_t>(Le32(raw.data() + 24), raw.size());

    while (off + 16 <= used) {
        const uint8_t* a = raw.data() + off;
        const uint32_t type = Le32(a);
        if (type == ATTR_END) break;
        const uint32_t length = Le32(a + 4);
        if (length < 16 || off + length > used) break;

        NtfsAttribute attr;
        attr.type = type;
        attr.nonResident = a[8] != 0;
        const uint8_t nameLength = a[9];
        const uint16_t nameOffset = Le16(a + 10);
        attr.flags = Le16(a + 12);
        if (nameLength && nameOffset + nameLength * 2u <= length) {
            attr.name = Utf16(a + nameOffset, nameLength);
        }
        if (!attr.nonResident) {
            const uint32_t valueLength = Le32(a + 16);
            const uint16_t valueOffset = Le16(a + 20);
            if (valueOffset + static_cast<uint64_t>(valueLength) <= length) {
                attr.value.assign(a + valueOffset, a + valueOffset + valueLength);
            }
            attr.realSize = attr.initializedSize = attr.allocatedSize = valueLength;
        } else if (length >= 64) {
            attr.startVcn = Le64(a + 16);
            attr.endVcn = Le64(a + 24);
            const uint16_t runOffset = Le16(a + 32);
            attr.compressionUnit = Le16(a + 34);
            attr.allocatedSize = Le64(a + 40);
            attr.realSize = Le64(a + 48);
            attr.initializedSize = Le64(a + 56);
            if (runOffset < length) {
                attr.runs = DecodeRuns(a + runOffset, length - runOffset, attr.startVcn, attr.runsValid);
            } else {
                attr.runsValid = false;
            }
        }
        out.attributes.push_back(std::move(attr));
        off += length;
    }
    return true;
}

bool NTFSScanner::Open(DiskHandle& disk) {
    if (m_open && m_openPath == disk.Path()) return true;
    m_open = false;
    m_dirCache.clear();
    m_mftRuns.clear();
    m_bitmap.clear();

    m_boot = ReadBootSector(disk);
    if (std::memcmp(m_boot.oemID, "NTFS    ", 8) != 0 || m_boot.bytesPerSector == 0 || m_boot.sectorsPerCluster == 0) {
        return false;
    }
    // sectors per cluster above 128 are stored as a negative power of two
    const uint64_t spc = m_boot.sectorsPerCluster <= 128 ? m_boot.sectorsPerCluster
                                                         : 1ull << (256 - m_boot.sectorsPerCluster);
    m_clusterSize = m_boot.bytesPerSector * spc;
    m_recordSize = m_boot.clustersPerMFTRecord >= 0 ? m_boot.clustersPerMFTRecord * m_clusterSize
                                                    : 1ull << (-m_boot.clustersPerMFTRecord);
    m_totalClusters = (m_boot.totalSectors + 1) / spc;
    if (m_recordSize < 512 || m_recordSize > 65536) return false;

    // record 0 is $MFT itself; its $DATA says where every other record is
    auto raw = disk.ReadBytes(m_boot.mftCluster * m_clusterSize, m_recordSize);
    NtfsRecord mft;
    if (!ApplyFixups(raw) || !DecodeRecord(raw, mft)) return false;
    const NtfsAttribute* data = FindAttribute(mft, ATTR_DATA);
    if (!data || !data->nonResident || data->runs.empty()) return false;
    m_mftRuns = data->runs;
    m_recordCount = data->realSize / m_recordSize;
    m_open = true;
    m_openPath = disk.Path();

    // $MFT's own run list may continue in extension records
    bool complete = true;
    if (auto full = GatherData(disk, 0, mft, L"", complete)) {
        m_mftRuns = full->runs;
    }

    // $Bitmap: which clusters are in use now
    NtfsRecord bitmapRecord;
    if (DecodeRecord(ReadMFTRecord(disk, m_boot, BITMAP_RECORD), bitmapRecord)) {
        if (auto bitmap = GatherData(disk, BITMAP_RECORD, bitmapRecord, L"", complete)) {
            const uint64_t size = std::min(bitmap->realSize, MAX_BITMAP_BYTES);
            m_bitmap.reserve(static_cast<size_t>(size));
            for (const auto& run : bitmap->runs) {
                if (m_bitmap.size() >= size) break;
                auto bytes = disk.ReadBytes(run.startCluster * m_clusterSize,
                                            std::min(run.clusterCount * m_clusterSize, size - m_bitmap.size()));
                m_bitmap.insert(m_bitmap.end(), bytes.begin(), bytes.end());
            }
        }
    }
    return true;
}


std::vector<uint8_t> NTFSScanner::ReadMFTRecord(DiskHandle& disk, const NTFSBootSector& boot, uint64_t recordNum) {
    (void)boot;
    if (!Open(disk)) return {};
    const uint64_t offset = recordNum * m_recordSize;
    for (const auto& run : m_mftRuns) {
        const uint64_t runBytes = run.clusterCount * m_clusterSize;
        if (offset >= run.fileOffset && offset + m_recordSize <= run.fileOffset + runBytes) {
            auto raw = disk.ReadBytes(run.startCluster * m_clusterSize + (offset - run.fileOffset), m_recordSize);
            if (raw.size() != m_recordSize) return {};
            ApplyFixups(raw);                               // a torn record is still worth reading
            return raw;
        }
    }
    return {};
}

std::optional<NtfsAttribute> NTFSScanner::GatherData(DiskHandle& disk, uint64_t recordNum, const NtfsRecord& record,
                                                     const std::wstring& stream, bool& complete) {
    complete = true;
    std::optional<NtfsAttribute> result;
    for (const auto& a : record.attributes) {
        if (a.type == ATTR_DATA && a.name == stream) {
            if (!result) {
                result = a;
            } else if (a.nonResident) {
                result->runs.insert(result->runs.end(), a.runs.begin(), a.runs.end());
            }
            if (!a.runsValid) complete = false;
        }
    }

    // pieces of the stream that live in extension records
    const NtfsAttribute* list = FindAttribute(record, ATTR_ATTRIBUTE_LIST);
    if (list) {
        std::vector<uint8_t> value = list->value;
        if (list->nonResident) {
            value.clear();
            for (const auto& run : list->runs) {
                auto bytes = disk.ReadBytes(run.startCluster * m_clusterSize, run.clusterCount * m_clusterSize);
                value.insert(value.end(), bytes.begin(), bytes.end());
            }
            value.resize(std::min<size_t>(value.size(), static_cast<size_t>(list->realSize)));
        }
        std::map<uint64_t, uint16_t> extensions;
        for (size_t off = 0; off + 26 <= value.size(); ) {
            const uint8_t* e = value.data() + off;
            const uint16_t length = Le16(e + 4);
            if (length < 26 || off + length > value.size()) break;
            const uint32_t type = Le32(e);
            const uint8_t nameLength = e[6];
            const uint8_t nameOffset = e[7];
            const std::wstring name = nameLength && nameOffset + nameLength * 2u <= length
                                      ? Utf16(e + nameOffset, nameLength) : L"";
            const uint64_t holder = Le64(e + 16) & REFERENCE_MASK;
            if (type == ATTR_DATA && name == stream && holder != recordNum) {
                extensions.emplace(holder, static_cast<uint16_t>(Le64(e + 16) >> 48));
            }
            off += length;
        }
        for (const auto& [ext, expectedSequence] : extensions) {
            NtfsRecord extension;
            if (!DecodeRecord(ReadMFTRecord(disk, m_boot, ext), extension) || extension.baseRecord != recordNum ||
                (extension.sequence != expectedSequence &&
                 ((extension.flags & RECORD_IN_USE) || extension.sequence != static_cast<uint16_t>(expectedSequence + 1))) ||
                (extension.baseSequence != record.sequence &&
                 ((record.flags & RECORD_IN_USE) || static_cast<uint16_t>(extension.baseSequence + 1) != record.sequence))) {
                complete = false;                   // taken by another file since
                continue;
            }
            for (const auto& a : extension.attributes) {
                if (a.type != ATTR_DATA || a.name != stream || !a.nonResident) continue;
                if (!result) {
                    result = a;
                } else {
                    result->runs.insert(result->runs.end(), a.runs.begin(), a.runs.end());
                }
                if (a.startVcn == 0) {              // the first piece holds the sizes
                    result->realSize = a.realSize;
                    result->initializedSize = a.initializedSize;
                    result->allocatedSize = a.allocatedSize;
                    result->compressionUnit = a.compressionUnit;
                    result->flags = a.flags;
                }
                if (!a.runsValid) complete = false;
            }
        }
    }
    if (result) {
        std::sort(result->runs.begin(), result->runs.end(),
                  [](const ClusterRun& x, const ClusterRun& y) { return x.fileOffset < y.fileOffset; });
    }
    return result;
}

std::wstring NTFSScanner::DirectoryPath(DiskHandle& disk, uint64_t parent, uint16_t parentSequence) {
    std::vector<std::wstring> parts;
    std::set<uint64_t> seen;
    while (parent != ROOT_RECORD) {
        if (parts.size() > MAX_PATH_DEPTH || !seen.insert(parent).second) {
            parts.push_back(L"$Orphan");
            break;
        }
        auto it = m_dirCache.find(parent);
        if (it == m_dirCache.end()) {
            DirInfo info;
            NtfsRecord r;
            if (DecodeRecord(ReadMFTRecord(disk, m_boot, parent), r) && (r.flags & RECORD_DIRECTORY)) {
                const FileName fn = BestFileName(r);
                info.valid = fn.found;
                info.name = fn.name;
                info.parent = fn.parent;
                info.parentSequence = fn.parentSequence;
                info.sequence = r.sequence;
                info.inUse = (r.flags & RECORD_IN_USE) != 0;
            }
            it = m_dirCache.emplace(parent, info).first;
        }
        const DirInfo& d = it->second;
        // the reference holds the sequence the parent had; a deleted parent
        // has one more, a reused record any other
        const bool same = d.valid && (d.sequence == parentSequence ||
                                      (!d.inUse && d.sequence == static_cast<uint16_t>(parentSequence + 1)));
        if (!same) {
            parts.push_back(L"$Orphan");
            break;
        }
        parts.push_back(d.name);
        parent = d.parent;
        parentSequence = d.parentSequence;
    }
    std::wstring path;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        path += path.empty() ? *it : L"\\" + *it;
    }
    return path;
}

bool NTFSScanner::ParseMFTRecord(const std::vector<uint8_t>& data, uint64_t recordNum,
                                 DiskForensicsCore::FileFoundCallback& callback, DiskHandle& disk,
                                 const NTFSBootSector& boot, const std::wstring& folderFilter,
                                 const std::wstring& filenameFilter) {
    (void)boot; (void)folderFilter; (void)filenameFilter;
    NtfsRecord record;
    if (!DecodeRecord(data, record)) return false;
    if ((record.flags & (RECORD_IN_USE | RECORD_DIRECTORY)) || record.baseRecord != 0) return false;

    const FileName fn = BestFileName(record);
    if (!fn.found) return false;

    RecoveryCandidate candidate;
    candidate.name = fn.name;
    candidate.mftRecord = recordNum;
    candidate.writeOrder = record.lsn;
    candidate.source = RecoverySource::MFT;
    candidate.filesystemType = L"NTFS";
    candidate.directory = DirectoryPath(disk, fn.parent, fn.parentSequence);
    candidate.path = L"\\" + (candidate.directory.empty() ? fn.name : candidate.directory + L"\\" + fn.name);
    candidate.file = FragmentedFile(0, m_clusterSize);
    candidate.quality = RecoveryQuality::Unrecoverable;

    bool complete = true;
    auto stream = GatherData(disk, recordNum, record, L"", complete);
    if (!stream) {
        candidate.sizeFormatted = L"Unknown";
        candidate.isRecoverable = false;
        callback(candidate);
        return true;
    }

    candidate.fileSize = stream->realSize;
    candidate.size = stream->realSize;
    candidate.sizeFormatted = StringUtils::FormatFileSize(stream->realSize);

    if (!stream->nonResident) {
        candidate.file.SetResidentData(stream->value);
        candidate.quality = RecoveryQuality::Full;
        callback(candidate);
        return true;
    }

    // Deleting a fragmented stream can truncate $DATA in its extension
    // record to size zero and erase the other extension attributes. That
    // is lost allocation metadata, not evidence of an originally empty file.
    // An actual empty resident stream takes the branch above.
    const bool externalData = std::none_of(record.attributes.begin(), record.attributes.end(),
        [](const NtfsAttribute& a) { return a.type == ATTR_DATA && a.name.empty(); });
    if (stream->realSize == 0 && (externalData || !complete || stream->startVcn != 0)) {
        candidate.quality = RecoveryQuality::MetadataOnly;
        candidate.isRecoverable = false;
        candidate.sizeFormatted = L"Unknown (data layout cleared)";
        callback(candidate);
        return true;
    }

    FragmentMap map(m_clusterSize, m_totalClusters);
    bool overwritten = false;
    for (const auto& run : stream->runs) {
        map.AddRun(run);
        overwritten = overwritten || AnyBitSet(m_bitmap, run.startCluster, run.clusterCount);
    }
    map.SetTotalSize(stream->realSize);
    candidate.file = FragmentedFile(stream->realSize, m_clusterSize);
    candidate.file.SetFragmentMap(std::move(map));
    if (stream->initializedSize < stream->realSize) {
        candidate.validLength = stream->initializedSize;
    }
    if ((stream->flags & ATTR_FLAG_COMPRESSED) && stream->compressionUnit) {
        candidate.encoding = DataEncoding::NtfsLznt1;
        candidate.compressionUnitClusters = 1u << stream->compressionUnit;
    }

    if (stream->realSize == 0) {
        candidate.quality = RecoveryQuality::Full;
    } else if (stream->runs.empty() && !(stream->flags & 0x8000)) {
        candidate.quality = RecoveryQuality::Unrecoverable;
    } else {
        candidate.quality = (complete && !overwritten) ? RecoveryQuality::Full : RecoveryQuality::Partial;
    }
    if (stream->flags & ATTR_FLAG_ENCRYPTED) {
        candidate.quality = RecoveryQuality::Partial;
        candidate.sizeFormatted += L" (EFS encrypted)";
    } else if (overwritten) {
        candidate.sizeFormatted += L" (overwritten)";
    } else if (!complete) {
        candidate.sizeFormatted += L" (incomplete)";
    }
    candidate.isRecoverable = candidate.quality != RecoveryQuality::Unrecoverable;
    callback(candidate);
    return true;
}

FreeSpace NTFSScanner::FreeSpaceOf(DiskHandle& disk) {
    FreeSpace free;
    if (!Open(disk) || m_bitmap.empty()) return free;
    free.geometry.sectorSize = m_boot.bytesPerSector;
    free.geometry.bytesPerCluster = m_clusterSize;
    free.geometry.totalClusters = m_totalClusters;
    free.geometry.volumeStartOffset = 0;
    free.geometry.fsType = FilesystemType::NTFS;
    free.runs = ClearRuns(m_bitmap, m_totalClusters);
    free.valid = true;
    return free;
}

std::optional<uint64_t> NTFSScanner::FindUsnJournal(DiskHandle& disk) {
    if (!Open(disk)) return std::nullopt;
    // a system file: early in the MFT, a child of $Extend
    const uint64_t limit = std::min<uint64_t>(m_recordCount, 1u << 20);
    for (uint64_t i = FIRST_USER_RECORD; i < limit; ++i) {
        NtfsRecord r;
        if (!DecodeRecord(ReadMFTRecord(disk, m_boot, i), r) || !(r.flags & RECORD_IN_USE)) continue;
        const FileName fn = BestFileName(r);
        if (fn.found && fn.parent == EXTEND_RECORD && fn.name == L"$UsnJrnl") {
            return i;
        }
    }
    return std::nullopt;
}

std::vector<ClusterRun> NTFSScanner::StreamRuns(DiskHandle& disk, uint64_t recordNum, const std::wstring& stream, uint64_t& realSize) {
    realSize = 0;
    NtfsRecord r;
    if (!Open(disk) || !DecodeRecord(ReadMFTRecord(disk, m_boot, recordNum), r)) return {};
    bool complete = true;
    auto data = GatherData(disk, recordNum, r, stream, complete);
    if (!data) return {};
    realSize = data->realSize;
    return data->runs;
}

bool NTFSScanner::ScanVolume(
    DiskHandle& disk,
    const std::wstring& folderFilter,
    const std::wstring& filenameFilter,
    DiskForensicsCore::FileFoundCallback onFileFound,
    DiskForensicsCore::ProgressCallback onProgress,
    std::atomic<bool>& shouldStop,
    const ScanConfiguration& config)
{
    if (!Open(disk)) {
        onProgress(L"Cannot read the MFT", 0.0f);
        return false;
    }
    const uint64_t records = std::min(m_recordCount, config.ntfsMftMaxRecords);
    uint64_t found = 0;

    // the MFT run by run, a few megabytes at a time
    for (const auto& run : m_mftRuns) {
        const uint64_t runBytes = run.clusterCount * m_clusterSize;
        for (uint64_t at = 0; at < runBytes && !shouldStop; at += MFT_CHUNK_BYTES) {
            const uint64_t firstRecord = (run.fileOffset + at) / m_recordSize;
            if (firstRecord >= records) break;
            const uint64_t bytes = std::min(MFT_CHUNK_BYTES, runBytes - at);
            const auto chunk = disk.ReadBytes(run.startCluster * m_clusterSize + at, bytes);

            for (uint64_t k = 0; (k + 1) * m_recordSize <= chunk.size(); ++k) {
                const uint64_t index = firstRecord + k;
                if (index >= records) break;
                if (index < FIRST_USER_RECORD) continue;
                std::vector<uint8_t> rec(chunk.begin() + static_cast<ptrdiff_t>(k * m_recordSize),
                                         chunk.begin() + static_cast<ptrdiff_t>((k + 1) * m_recordSize));
                if (std::memcmp(rec.data(), "FILE", 4) != 0) continue;
                ApplyFixups(rec);
                if (ParseMFTRecord(rec, index, onFileFound, disk, m_boot, folderFilter, filenameFilter)) {
                    ++found;
                }
            }
            const uint64_t done = std::min(records, firstRecord + chunk.size() / m_recordSize);
            wchar_t msg[256];
            swprintf_s(msg, L"Stage 1 (MFT): %llu of %llu records, %llu deleted files found", done, records, found);
            onProgress(msg, records ? 0.33f * static_cast<float>(done) / static_cast<float>(records) : 0.33f);
        }
    }

    wchar_t msg[256];
    swprintf_s(msg, L"MFT scan complete: %llu records, %llu deleted files found", records, found);
    onProgress(msg, 0.33f);
    return true;
}

} // namespace KVC
