// Archive structural boundaries; payload decoding is verified separately in tests.
#include "carving/FileCarver.h"
#include <array>
#include <cstring>
#include <algorithm>
namespace KVC {
namespace {
uint32_t Crc(const uint8_t* data, size_t size, uint32_t crc = UINT32_MAX) {
    static const auto table = [] {
        std::array<uint32_t, 256> result{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit) value = (value >> 1) ^ (0xEDB88320u & (0u - (value & 1)));
            result[i] = value;
        }
        return result;
    }();
    for (size_t i = 0; i < size; ++i) crc = table[(crc ^ data[i]) & 255] ^ (crc >> 8);
    return crc;
}
uint32_t Le32(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
uint64_t Le64(const uint8_t* p) { return uint64_t(Le32(p)) | (uint64_t(Le32(p + 4)) << 32); }
}
std::optional<uint64_t> FileCarver::ParseSevenZipEnd(SequentialReader& reader) {
    uint8_t header[32];
    static constexpr uint8_t signature[] = {0x37,0x7A,0xBC,0xAF,0x27,0x1C};
    if (reader.Read(header, sizeof(header)) != sizeof(header) || std::memcmp(header, signature, 6) ||
        header[6] != 0 || (Crc(header + 12, 20) ^ UINT32_MAX) != Le32(header + 8)) return std::nullopt;
    const uint64_t offset = Le64(header + 12), size = Le64(header + 20);
    if (offset > reader.MaxSize() - 32 || size > reader.MaxSize() - 32 - offset || !reader.Seek(32 + offset)) return std::nullopt;
    uint32_t crc = UINT32_MAX;
    std::array<uint8_t, 65536> buffer{};
    for (uint64_t left = size; left;) {
        const size_t count = static_cast<size_t>(std::min<uint64_t>(left, buffer.size()));
        if (reader.Read(buffer.data(), count) != count) return std::nullopt;
        crc = Crc(buffer.data(), count, crc); left -= count;
    }
    return (crc ^ UINT32_MAX) == Le32(header + 28) ? std::optional<uint64_t>(reader.Position()) : std::nullopt;
}
std::optional<uint64_t> FileCarver::ParseZipEnd(SequentialReader& reader, FileSignature* detected) {
    // APPNOTE 4.3.12 / 4.3.16: an EOCD belongs to this archive only when
    // its offset, size and count describe the central directory we read.
    // Scan forward once, including archives using data descriptors. Each
    // directory entry is checked against its local header in constant work
    // plus the filename length. Never search for the last EOCD on the disk.
    const auto le16 = [](const uint8_t* p) { return uint16_t(p[0] | (uint16_t(p[1]) << 8)); };
    const auto le32 = [](const uint8_t* p) {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    };
    const auto le64 = [&](const uint8_t* p) { return uint64_t(le32(p)) | (uint64_t(le32(p + 4)) << 32); };
    uint8_t first[4];
    if (reader.Read(first, sizeof(first)) != sizeof(first)) return std::nullopt;
    if (le32(first) == 0x06054B50) {
        uint8_t end[18];
        if (reader.Read(end, 18) != 18 || std::any_of(end, end + 16, [](uint8_t c) { return c != 0; })) return std::nullopt;
        std::vector<uint8_t> comment(le16(end + 16));
        if (reader.Read(comment.data(), comment.size()) != comment.size()) return std::nullopt;
        return reader.Position();
    }
    if (le32(first) != 0x04034B50) return std::nullopt;

    uint64_t centralStart = 0, centralEnd = 0;
    uint32_t entries = 0;
    unsigned package = 0;
    uint32_t window = 0;
    uint8_t byte;
    while (reader.ReadByte(byte)) {
        window = (window >> 8) | (uint32_t(byte) << 24);
        if (window == 0x02014B50) {
            const uint64_t pos = reader.Position() - 4;
            if (pos != centralEnd) { centralStart = pos; entries = 0; package = 0; }
            const auto validCentral = [&]() -> bool {
                uint8_t central[42];
                if (reader.Read(central, sizeof(central)) != sizeof(central)) return false;
                const uint16_t nameLength = le16(central + 24);
                const uint64_t packedSize = le32(central + 16);
                const uint64_t localOffset = le32(central + 38);
                // ZIP64 and split archives require their own record layouts.
                if (le16(central + 30) != 0 || packedSize == UINT32_MAX ||
                    le32(central + 20) == UINT32_MAX || localOffset == UINT32_MAX ||
                    localOffset >= centralStart || nameLength == 0) return false;
                std::vector<uint8_t> name(nameLength), localName(nameLength);
                if (reader.Read(name.data(), name.size()) != name.size() ||
                    !reader.Skip(uint64_t(le16(central + 26)) + le16(central + 28))) return false;
                const uint64_t resume = reader.Position();
                uint8_t local[30];
                if (!reader.Seek(localOffset) || reader.Read(local, sizeof(local)) != sizeof(local) ||
                    le32(local) != 0x04034B50 || le16(local + 6) != le16(central + 4) ||
                    le16(local + 8) != le16(central + 6) || le16(local + 26) != nameLength ||
                    reader.Read(localName.data(), localName.size()) != localName.size() || name != localName)
                    return false;
                const uint64_t payload = localOffset + sizeof(local) + nameLength + le16(local + 28);
                if (payload > centralStart || packedSize > centralStart - payload) return false;
                uint64_t localPacked = le32(local + 18), localUnpacked = le32(local + 22);
                if (localPacked == UINT32_MAX || localUnpacked == UINT32_MAX) {
                    std::vector<uint8_t> extra(le16(local + 28));
                    if (reader.Read(extra.data(), extra.size()) != extra.size()) return false;
                    bool zip64 = false;
                    for (size_t at = 0; at + 4 <= extra.size();) {
                        const uint16_t type = le16(extra.data() + at), size = le16(extra.data() + at + 2);
                        at += 4;
                        if (size > extra.size() - at) return false;
                        if (type == 1) {
                            size_t value = at, end = at + size;
                            if (localUnpacked == UINT32_MAX) { if (end - value < 8) return false; localUnpacked = le64(extra.data() + value); value += 8; }
                            if (localPacked == UINT32_MAX) { if (end - value < 8) return false; localPacked = le64(extra.data() + value); }
                            zip64 = true; break;
                        }
                        at += size;
                    }
                    if (!zip64) return false;
                }
                if ((le16(local + 6) & 8) == 0 &&
                    (le32(local + 14) != le32(central + 12) || localPacked != packedSize ||
                     localUnpacked != le32(central + 20))) return false;
                const std::string member(name.begin(), name.end());
                if (member == "[Content_Types].xml") package |= 1;
                if (member == "_rels/.rels") package |= 2;
                if (member == "word/document.xml") package |= 4;
                if (member == "xl/workbook.xml") package |= 8;
                if (member == "ppt/presentation.xml") package |= 16;
                if (!reader.Seek(resume)) return false;
                centralEnd = resume;
                ++entries;
                return true;
            };
            if (!validCentral()) {
                entries = 0; package = 0; centralStart = centralEnd = 0;
                if (!reader.Seek(pos + 4)) return std::nullopt;
            }
            window = 0;
        } else if (window == 0x06054B50) {
            const uint64_t pos = reader.Position() - 4;
            uint8_t end[18];
            if (reader.Read(end, sizeof(end)) != sizeof(end)) return std::nullopt;
            if (entries != 0 && entries < UINT16_MAX && pos == centralEnd &&
                le16(end) == 0 && le16(end + 2) == 0 &&
                le16(end + 4) == entries && le16(end + 6) == entries &&
                le32(end + 8) == centralEnd - centralStart && le32(end + 12) == centralStart) {
                // Reading, rather than skipping, confirms that the entire
                // comment exists even when the disk read is short.
                std::vector<uint8_t> comment(le16(end + 16));
                if (reader.Read(comment.data(), comment.size()) != comment.size()) return std::nullopt;
                if (detected && (package & 3) == 3) {
                    if ((package & 28) == 4) *detected = FileSignatures::DOCX;
                    if ((package & 28) == 8) *detected = FileSignatures::XLSX;
                    if ((package & 28) == 16) *detected = FileSignatures::PPTX;
                }
                return reader.Position();
            }
            window = 0;
        }
    }
    return std::nullopt;
}


}
