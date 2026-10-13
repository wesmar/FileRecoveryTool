// Byte-exact carving regressions, using isolated raw image files.
#include "carving/FileCarver.h"
#include <Windows.h>
#include <cstdio>
#include <stdexcept>
#include <utility>

using Bytes = std::vector<uint8_t>;
constexpr uint64_t BPC = 4096;

void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void U16(Bytes& b, uint16_t v) { b.push_back(uint8_t(v)); b.push_back(uint8_t(v >> 8)); }
void U32(Bytes& b, uint32_t v) { U16(b, uint16_t(v)); U16(b, uint16_t(v >> 16)); }
void Patch32(Bytes& b, size_t offset, uint32_t v) {
    for (size_t i = 0; i < 4; ++i) b.at(offset + i) = uint8_t(v >> (i * 8));
}
uint32_t Crc(const Bytes& b) {
    uint32_t crc = UINT32_MAX;
    for (uint8_t byte : b) {
        crc ^= byte;
        for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}
struct Zip { Bytes bytes; size_t central; size_t end; };
Zip MakeZip(const Bytes& payload, const Bytes& comment = {}, bool descriptor = false) {
    const uint32_t size = static_cast<uint32_t>(payload.size()), crc = Crc(payload);
    Zip z;
    Bytes& b = z.bytes;
    U32(b, 0x04034B50); U16(b, 20); U16(b, descriptor ? 8 : 0); U16(b, 0); U32(b, 0);
    U32(b, descriptor ? 0 : crc); U32(b, descriptor ? 0 : size); U32(b, descriptor ? 0 : size);
    U16(b, 5); U16(b, 0); b.insert(b.end(), {'a', '.', 't', 'x', 't'});
    b.insert(b.end(), payload.begin(), payload.end());
    if (descriptor) { U32(b, 0x08074B50); U32(b, crc); U32(b, size); U32(b, size); }
    z.central = b.size();
    U32(b, 0x02014B50); U16(b, 20); U16(b, 20); U16(b, descriptor ? 8 : 0); U16(b, 0); U32(b, 0);
    U32(b, crc); U32(b, size); U32(b, size); U16(b, 5); U16(b, 0); U16(b, 0);
    U16(b, 0); U16(b, 0); U32(b, 0); U32(b, 0); b.insert(b.end(), {'a', '.', 't', 'x', 't'});
    z.end = b.size();
    U32(b, 0x06054B50); U16(b, 0); U16(b, 0); U16(b, 1); U16(b, 1);
    U32(b, static_cast<uint32_t>(z.end - z.central)); U32(b, static_cast<uint32_t>(z.central));
    U16(b, static_cast<uint16_t>(comment.size())); b.insert(b.end(), comment.begin(), comment.end());
    return z;
}

struct TempImage {
    wchar_t path[MAX_PATH] = {};
    explicit TempImage(const Bytes& bytes) {
        wchar_t dir[MAX_PATH];
        Require(GetTempPathW(MAX_PATH, dir) != 0 && GetTempFileNameW(dir, L"frt", 0, path) != 0, "temporary path");
        HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        Require(h != INVALID_HANDLE_VALUE, "temporary image");
        DWORD written = 0;
        bool ok = WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) && written == bytes.size();
        CloseHandle(h);
        Require(ok, "image write");
    }
    ~TempImage() { DeleteFileW(path); }
};
using Expected = std::vector<std::pair<uint64_t, Bytes>>;
void Text(Bytes& output, const std::string& text) { output.insert(output.end(), text.begin(), text.end()); }
struct Pdf { Bytes bytes; uint64_t xref; };
Pdf MakePdf(const std::string& ending = "\n", bool falseFooter = false) {
    Pdf pdf{}; Text(pdf.bytes, "%PDF-1.7" + ending);
    const std::string entryPadding = ending == "\r\n" ? "" : " ";
    std::vector<uint64_t> offsets{0};
    std::vector<std::string> objects = {
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"};
    if (falseFooter) objects.push_back("<< /Length 25 >>\nstream\nstartxref\n0\n%%EOF\nFAKE!!\nendstream");
    for (size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(pdf.bytes.size());
        Text(pdf.bytes, std::to_string(i + 1) + " 0 obj" + ending + objects[i] + ending + "endobj" + ending);
    }
    pdf.xref = pdf.bytes.size();
    Text(pdf.bytes, "xref" + ending + "0 " + std::to_string(offsets.size()) + ending + "0000000000 65535 f" + entryPadding + ending);
    for (size_t i = 1; i < offsets.size(); ++i) {
        char line[64]; std::snprintf(line, sizeof(line), "%010llu 00000 n", static_cast<unsigned long long>(offsets[i]));
        Text(pdf.bytes, line + entryPadding + ending);
    }
    Text(pdf.bytes, "trailer" + ending + "<< /Size " + std::to_string(offsets.size()) + " /Root 1 0 R >>" + ending +
        "startxref" + ending + std::to_string(pdf.xref) + ending + "%%EOF" + ending);
    return pdf;
}
Pdf UpdatePdf(Pdf pdf) {
    const uint64_t object = pdf.bytes.size();
    Text(pdf.bytes, "4 0 obj\n<< /Producer (fixture /Prev 0) >>\nendobj\n");
    const uint64_t current = pdf.bytes.size();
    char entry[64]; std::snprintf(entry, sizeof(entry), "%010llu 00000 n \n", static_cast<unsigned long long>(object));
    Text(pdf.bytes, std::string("xref\n4 1\n") + entry + "trailer\n<< /Size 5 /Root 1 0 R /Prev " + std::to_string(pdf.xref) +
        " >>\nstartxref\n" + std::to_string(current) + "\n%%EOF\n");
    pdf.xref = current; return pdf;
}
Bytes MakeSevenZip() {
    Bytes bytes(32, 0);
    const uint8_t signature[] = {0x37,0x7A,0xBC,0xAF,0x27,0x1C};
    std::copy(std::begin(signature), std::end(signature), bytes.begin()); bytes[7] = 4;
    Patch32(bytes, 8, Crc(Bytes(bytes.begin() + 12, bytes.end())));
    return bytes;
}
void Check(const char* name, Bytes image, const Expected& expected,
           KVC::DedupMode mode = KVC::DedupMode::FastDedup, bool cancel = false,
           const std::unordered_map<uint64_t, KVC::FragmentMap>& hints = {}, bool raw = false, bool partial = false) {
    const uint64_t unit = raw ? 1 : BPC;
    if (!raw) image.resize((image.size() + BPC - 1) / BPC * BPC, 0);
    TempImage temp(image);
    KVC::DiskHandle disk(temp.path);
    Require(disk.Open(), "open image");
    Require(disk.GetDiskSize() == image.size(), "exact flat image length");
    KVC::VolumeGeometry geom{512, unit, image.size() / unit, 0, KVC::FilesystemType::Unknown};
    KVC::VolumeReader volume(disk, geom);
    KVC::CarvingOptions options;
    options.signatures = KVC::FileSignatures::GetAllSignatures();
    options.fragmentHints = hints;
    options.batchClusters = raw ? 64 : 1; // exercise batch boundaries
    options.dedupMode = mode;
    std::atomic<bool> stop = false;
    KVC::FileCarver carver;
    auto result = carver.CarveVolume(volume, options, [](const KVC::CarvedFile&) {},
        [&](const std::wstring&, float) { if (cancel) stop = true; }, stop);
    Require(result.files.size() == expected.size(), "candidate count");
    Require(result.complete == !cancel, "scan completion state");
    Require(result.stats.totalSignaturesFound >= result.files.size(), "statistics initialized");
    for (size_t i = 0; i < expected.size(); ++i) {
        const auto& f = result.files[i];
        Require(f.incompleteRevision == partial, "PDF revision completeness");
        Require(f.startLCN == expected[i].first && f.fileSize == expected[i].second.size(), "candidate boundary");
        KVC::SequentialReader reader(disk, f.fragments, 512);
        Bytes recovered(static_cast<size_t>(f.fileSize));
        Require(reader.Read(recovered.data(), recovered.size()) == recovered.size() && recovered == expected[i].second,
                "recovered bytes");
    }
    KVC::SequentialReader overflow(disk, 0, 100, 512);
    Require(overflow.Seek(7) && !overflow.Skip(UINT64_MAX) && overflow.Position() == 100, "skip overflow");
    std::printf("PASS %s\n", name);
}

int main() {
    try {
        const auto a = MakeZip(Bytes(120000, 'A'));
        const auto b = MakeZip(Bytes(3000, 'B'), {'c','o','m','m','e','n','t'});
        Check("ZIP spans multiple buffers", a.bytes, {{0, a.bytes}});
        Check("ZIP comment preserved", b.bytes, {{0, b.bytes}});
        Bytes adjacent = a.bytes;
        const size_t second = (adjacent.size() + BPC - 1) / BPC;
        adjacent.resize(second * BPC); adjacent.insert(adjacent.end(), b.bytes.begin(), b.bytes.end());
        Check("adjacent ZIPs stay separate", adjacent, {{0, a.bytes}, {second, b.bytes}});
        Check("forensic ZIP dedup", adjacent, {{0, a.bytes}, {second, b.bytes}}, KVC::DedupMode::ForensicFull);
        const auto descriptor = MakeZip(Bytes(70000, 'D'), {}, true);
        Check("ZIP data descriptor", descriptor.bytes, {{0, descriptor.bytes}});
        Bytes fake(2000, 'F');
        const Bytes marker = {0x50,0x4B,0x05,0x06,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0};
        std::copy(marker.begin(), marker.end(), fake.begin() + 100);
        const auto embedded = MakeZip(fake);
        Check("false EOCD in payload", embedded.bytes, {{0, embedded.bytes}});
        fake[100] = 0x50; fake[101] = 0x4B; fake[102] = 0x01; fake[103] = 0x02;
        const auto fakeCentral = MakeZip(fake);
        Check("false central header in payload", fakeCentral.bytes, {{0, fakeCentral.bytes}});
        const auto commentMarker = MakeZip(Bytes(100, 'C'), marker);
        Check("false EOCD in comment", commentMarker.bytes, {{0, commentMarker.bytes}});
        Bytes corrupt = a.bytes; Patch32(corrupt, a.end + 16, static_cast<uint32_t>(a.central + 1));
        Check("bad central directory offset rejected", corrupt, {});
        corrupt = a.bytes; Patch32(corrupt, a.end + 12, 1);
        Check("bad central directory size rejected", corrupt, {});
        corrupt = a.bytes; corrupt[a.end + 10] = 2;
        Check("bad entry count rejected", corrupt, {});
        corrupt = a.bytes; Patch32(corrupt, a.central + 42, static_cast<uint32_t>(a.central));
        Check("bad local header offset rejected", corrupt, {});
        corrupt = a.bytes; corrupt[a.central + 16] ^= 1;
        Check("local and central CRC mismatch rejected", corrupt, {});
        corrupt = a.bytes; corrupt.resize(a.end + 10);
        Check("truncated EOCD rejected", corrupt, {});
        auto hugeComment = MakeZip(Bytes(3960, 'H'), Bytes(65535, 'X'));
        Check("maximum ZIP comment", hugeComment.bytes, {{0, hugeComment.bytes}});
        Check("cancellation before scan", a.bytes, {}, KVC::DedupMode::FastDedup, true);
        const Bytes gif = {'G','I','F','8','9','a',1,0,1,0,0x80,0,0,0,0,0x3B,255,255,255,
            0x21,0xFE,3,0x3B,0x3B,0x3B,0,0x2C,0,0,0,0,1,0,1,0,0,2,2,0x44,0x01,0,0x3B};
        Check("GIF palette and comment trailer bytes", gif, {{0, gif}});
        Bytes brokenGif = gif; brokenGif.pop_back();
        Check("GIF missing trailer", brokenGif, {});
        const Bytes mp4 = {0,0,0,16,'f','t','y','p','i','s','o','m',0,0,0,0,
            0,0,0,8,'m','o','o','v',0,0,0,16,'m','d','a','t',0,1,2,3,4,5,6,7};
        Check("MP4 excludes cluster padding", mp4, {{0, mp4}});
        Bytes brokenMovie = mp4; brokenMovie[24] = 0x7F;
        Check("MP4 overlong box rejected", brokenMovie, {});
        const auto mapped = MakeZip(Bytes(6000, 'M'));
        Bytes interrupted(5 * BPC, 0);
        std::copy_n(mapped.bytes.begin(), BPC, interrupted.begin());
        std::copy(mapped.bytes.begin() + BPC, mapped.bytes.end(), interrupted.begin() + 3 * BPC);
        KVC::FragmentMap map(BPC);
        map.AddRun(0, 1); map.AddRun(3, 1); map.SetTotalSize(mapped.bytes.size());
        Check("journal map skips metadata and fragmentation", interrupted, {{0, mapped.bytes}}, KVC::DedupMode::FastDedup, false, {{0,map}});
        Bytes backwards(4 * BPC, 0);
        std::copy_n(mapped.bytes.begin(), BPC, backwards.begin() + 3 * BPC);
        std::copy(mapped.bytes.begin() + BPC, mapped.bytes.end(), backwards.begin());
        KVC::FragmentMap reverse(BPC);
        reverse.AddRun(3,1); reverse.AddRun(0,1); reverse.SetTotalSize(mapped.bytes.size());
        Check("journal map may continue before its first block", backwards, {{3,mapped.bytes}}, KVC::DedupMode::FastDedup, false, {{3,reverse}});
        Bytes rawZip(61, 0); rawZip.insert(rawZip.end(), b.bytes.begin(), b.bytes.end());
        Check("RAW ZIP unaligned header spans batches and ends at EOF", rawZip, {{61,b.bytes}}, KVC::DedupMode::FastDedup, false, {}, true);
        Bytes rawMovie(61, 0); rawMovie.insert(rawMovie.end(), mp4.begin(), mp4.end());
        Check("RAW MP4 ftyp spans batches", rawMovie, {{61,mp4}}, KVC::DedupMode::FastDedup, false, {}, true);
        Bytes rawAdjacent(19, 0); rawAdjacent.insert(rawAdjacent.end(), b.bytes.begin(), b.bytes.end());
        const uint64_t gifOffset = rawAdjacent.size(); rawAdjacent.insert(rawAdjacent.end(), gif.begin(), gif.end());
        Check("RAW adjacent files within a sector", rawAdjacent, {{19,b.bytes},{gifOffset,gif}}, KVC::DedupMode::FastDedup, false, {}, true);
        Check("RAW truncated signature at exact EOF", Bytes{0,0,0xFF,0xD8}, {}, KVC::DedupMode::FastDedup, false, {}, true);
        const Bytes overlongWave = {'R','I','F','F',0,1,0,0,'W','A','V','E'};
        Check("RAW declared size cannot exceed source EOF", overlongWave, {}, KVC::DedupMode::FastDedup, false, {}, true);
        Check("RAW zero-filled discarded bytes", Bytes(131071, 0), {}, KVC::DedupMode::FastDedup, false, {}, true);
        Check("RAW cancellation", rawZip, {}, KVC::DedupMode::FastDedup, true, {}, true);
        Check("JPEG boot-sector marker pair is not an image", Bytes{0xFF,0xD8,0xFF,0xD9}, {});
        const Bytes jpeg = {0xFF,0xD8,0xFF,0xC0,0,11,8,0,1,0,1,1,1,0x11,0,
            0xFF,0xDA,0,8,1,1,0,0,63,0,0x42,0xFF,0,0x43,0xFF,0xD9};
        Check("JPEG frame scan and stuffed entropy", jpeg, {{0,jpeg}});
        Bytes progressive = jpeg; progressive[3] = 0xC2;
        progressive.resize(progressive.size() - 2);
        progressive.insert(progressive.end(), {0xFF,0xFE,0,3,'X',0xFF,0xDA,0,8,1,1,0,1,63,0,0x42,0xFF,0xFF,0xD9});
        Check("JPEG progressive marker preserved between scans", progressive, {{0,progressive}});
        Bytes noFrame = jpeg; noFrame.erase(noFrame.begin() + 2, noFrame.begin() + 15);
        Check("JPEG scan without frame rejected", noFrame, {});
        Bytes brokenFrame = jpeg; brokenFrame[7] = brokenFrame[8] = 0;
        Check("JPEG zero-height frame rejected", brokenFrame, {});
        const auto pdf = MakePdf();
        Check("PDF classic xref and final LF", pdf.bytes, {{0,pdf.bytes}});
        const auto crlfPdf = MakePdf("\r\n");
        Check("PDF preserves CRLF", crlfPdf.bytes, {{0,crlfPdf.bytes}});
        Bytes twoPdfs = pdf.bytes; twoPdfs.insert(twoPdfs.end(), crlfPdf.bytes.begin(), crlfPdf.bytes.end());
        Check("PDF adjacent documents stay separate", twoPdfs, {{0,pdf.bytes},{pdf.bytes.size(),crlfPdf.bytes}}, KVC::DedupMode::FastDedup, false, {}, true);
        const auto updated = UpdatePdf(pdf);
        Check("PDF linked incremental update preserved", updated.bytes, {{0,updated.bytes}});
        const auto twice = UpdatePdf(updated);
        Check("PDF two incremental updates", twice.bytes, {{0,twice.bytes}});
        Bytes truncated = updated.bytes; truncated.resize(truncated.size() - 4);
        Check("PDF incomplete update returns partial earlier revision", truncated, {{0,pdf.bytes}}, KVC::DedupMode::FastDedup, false, {}, true, true);
        const auto fakePdf = MakePdf("\n", true);
        Check("PDF false EOF inside stream ignored", fakePdf.bytes, {{0,fakePdf.bytes}});
        Bytes badPdf = pdf.bytes; badPdf.resize(badPdf.size() - 7);
        Check("PDF missing EOF rejected", badPdf, {});
        const Bytes footerOnly = {'%','P','D','F','-','1','.','7','\n','%','%','E','O','F'};
        Check("PDF signature plus EOF is not a document", footerOnly, {});
        Bytes emptyZip; U32(emptyZip,0x06054B50); emptyZip.resize(22);
        Check("empty ZIP recovered", emptyZip, {{0,emptyZip}});
        Bytes wrongEmpty = emptyZip; wrongEmpty[10] = 1;
        Check("ZIP footer with missing entries rejected", wrongEmpty, {});
        Bytes localZip64 = b.bytes;
        Bytes extra; U16(extra,1); U16(extra,16);
        U32(extra,3000); U32(extra,0); U32(extra,3000); U32(extra,0);
        localZip64.insert(localZip64.begin() + 35, extra.begin(), extra.end());
        localZip64[28] = 20; Patch32(localZip64,18,UINT32_MAX); Patch32(localZip64,22,UINT32_MAX);
        Patch32(localZip64,b.end + 20 + 16,static_cast<uint32_t>(b.central + 20));
        Check("ZIP64 local sizes with ordinary directory", localZip64, {{0,localZip64}});
        const auto seven = MakeSevenZip();
        Check("empty 7z header CRC", seven, {{0,seven}});
        Bytes badSeven = seven; badSeven[8] ^= 1;
        Check("7z corrupt start header rejected", badSeven, {});
        badSeven = seven; Patch32(badSeven,12,UINT32_MAX); Patch32(badSeven,16,UINT32_MAX);
        Patch32(badSeven,8,Crc(Bytes(badSeven.begin() + 12,badSeven.end())));
        Check("7z next-header offset overflow rejected", badSeven, {});
        {
            TempImage shortImage(Bytes(512, 0)); KVC::DiskHandle shortDisk(shortImage.path);
            Require(shortDisk.Open(), "open short source");
            KVC::VolumeReader shortReader(shortDisk, {512, 1, 2048, 0, KVC::FilesystemType::Unknown});
            KVC::CarvingOptions options; options.batchClusters = 512;
            std::atomic<bool> stop = false; KVC::FileCarver carver;
            const auto result = carver.CarveVolume(shortReader, options, [](const KVC::CarvedFile&) {}, [](const std::wstring&, float) {}, stop);
            Require(!result.complete && result.stats.readErrorBatches != 0, "short source must not look successful");
            Require(shortDisk.ReadBytes(UINT64_MAX - 1, 10).empty(), "byte-range overflow");
            std::puts("PASS RAW read failure and byte-range overflow");
        }
        std::puts("All carving regressions passed.");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
        return 1;
    }
}
