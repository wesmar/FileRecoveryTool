// PDF boundary checks: classic/xref-stream trailers and linked incremental revisions.
#include "carving/FileCarver.h"
#include <charconv>
#include <array>
#include <algorithm>
#include <cstring>

namespace KVC {
namespace {
bool Space(uint8_t c) { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32; }
bool Delimiter(uint8_t c) { return Space(c) || std::strchr("()<>[]{}/%", c) != nullptr; }
bool Number(const std::string& word, uint64_t& value) {
    if (word.empty()) return false;
    const auto result = std::from_chars(word.data(), word.data() + word.size(), value);
    return result.ec == std::errc{} && result.ptr == word.data() + word.size();
}
class Tokens {
public:
    Tokens(SequentialReader& source, uint64_t limit) : reader(source), end(limit) {}
    bool Next(std::string& word) {
        word.clear(); uint8_t c;
        while (Peek(c)) {
            if (Space(c)) { reader.ReadByte(c); continue; }
            if (c == '%') {
                while (Peek(c) && c != 10 && c != 13) reader.ReadByte(c);
                continue;
            }
            break;
        }
        if (!Read(c)) return false;
        word += static_cast<char>(c);
        if (c == '(') {
            unsigned depth = 1;
            while (depth && Read(c)) {
                if (c == '\\') { if (!Read(c)) return false; continue; }
                if (c == '(') ++depth; else if (c == ')') --depth;
            }
            word = "<string>"; return depth == 0;
        }
        if (c == '<' || c == '>') {
            const uint8_t first = c;
            if (Peek(c) && c == first) { Read(c); word += static_cast<char>(c); return true; }
            if (first == '>') return false;
            while (Read(c) && c != '>') {}
            word = "<string>"; return c == '>';
        }
        if (c == '[' || c == ']') return true;
        while (Peek(c) && !Delimiter(c)) {
            if (word.size() >= 256) return false;
            Read(c); word += static_cast<char>(c);
        }
        return true;
    }
    bool Peek(uint8_t& c) { return reader.Position() < end && reader.Peek(c); }
    bool Read(uint8_t& c) { return reader.Position() < end && reader.ReadByte(c); }
    SequentialReader& reader;
    uint64_t end;
};
struct Trailer {
    uint64_t size = 0, previous = 0, length = 0;
    bool hasPrevious = false, hasLength = false, root = false, xrefStream = false, widths = false;
};
bool Dictionary(Tokens& tokens, Trailer& trailer) {
    std::string word;
    if (!tokens.Next(word) || word != "<<") return false;
    unsigned depth = 1;
    while (tokens.Next(word)) {
        if (word == "<<") { if (++depth > 64) return false; continue; }
        if (word == ">>") { if (--depth == 0) return true; continue; }
        if (depth != 1) continue;
        if (word == "/Size" || word == "/Prev" || word == "/Length") {
            const auto key = word; uint64_t value;
            if (!tokens.Next(word) || !Number(word, value)) return false;
            if (key == "/Size") trailer.size = value;
            if (key == "/Prev") { trailer.previous = value; trailer.hasPrevious = true; }
            if (key == "/Length") { trailer.length = value; trailer.hasLength = true; }
        } else if (word == "/Root") {
            uint64_t object, generation;
            if (!tokens.Next(word) || !Number(word, object) || object == 0 ||
                !tokens.Next(word) || !Number(word, generation) || generation > 65535 ||
                !tokens.Next(word) || word != "R") return false;
            trailer.root = true;
        } else if (word == "/Type") {
            if (!tokens.Next(word)) return false;
            trailer.xrefStream = word == "/XRef";
        } else if (word == "/W") {
            if (!tokens.Next(word) || word != "[") return false;
            uint64_t total = 0, width;
            for (int i = 0; i < 3; ++i) {
                if (!tokens.Next(word) || !Number(word, width) || width > 8) return false;
                total += width;
            }
            if (!tokens.Next(word) || word != "]" || total == 0) return false;
            trailer.widths = true;
        } else if (word == "[") {
            unsigned arrays = 1;
            while (arrays && tokens.Next(word)) {
                if (word == "[") ++arrays; else if (word == "]") --arrays;
                if (arrays > 64) return false;
            }
            if (arrays) return false;
        }
    }
    return false;
}
std::optional<Trailer> CheckCrossReference(SequentialReader& reader, uint64_t offset, uint64_t eofMarkerEnd) {
    if (offset >= eofMarkerEnd || !reader.Seek(offset)) return std::nullopt;
    Tokens tokens(reader, eofMarkerEnd);
    std::string word; Trailer trailer;
    if (!tokens.Next(word)) return std::nullopt;
    if (word == "xref") {
        uint64_t total = 0;
        for (;;) {
            if (!tokens.Next(word)) return std::nullopt;
            if (word == "trailer") break;
            uint64_t first, count;
            if (!Number(word, first) || !tokens.Next(word) || !Number(word, count) ||
                first > 10000000 || count > 1000000 - total) return std::nullopt;
            total += count;
            for (uint64_t i = 0; i < count; ++i) {
                uint64_t location, generation;
                if (!tokens.Next(word) || !Number(word, location) ||
                    !tokens.Next(word) || !Number(word, generation) || generation > 65535 ||
                    !tokens.Next(word) || (word != "n" && word != "f") ||
                    (word == "n" && location >= offset)) return std::nullopt;
            }
        }
        if (!Dictionary(tokens, trailer)) return std::nullopt;
    } else {
        uint64_t object, generation;
        if (!Number(word, object) || object == 0 || !tokens.Next(word) || !Number(word, generation) ||
            generation > 65535 || !tokens.Next(word) || word != "obj" ||
            !Dictionary(tokens, trailer) || !trailer.xrefStream || !trailer.widths || !trailer.hasLength ||
            !tokens.Next(word) || word != "stream") return std::nullopt;
        uint8_t line;
        if (!tokens.Read(line) || (line != 10 && line != 13)) return std::nullopt;
        if (line == 13 && tokens.Peek(line) && line == 10) tokens.Read(line);
        if (trailer.length > eofMarkerEnd - reader.Position() || !reader.Skip(trailer.length) ||
            !tokens.Next(word) || word != "endstream" || !tokens.Next(word) || word != "endobj") return std::nullopt;
    }
    if (!trailer.size || trailer.size > 10000000 || (!trailer.root && !trailer.hasPrevious) ||
        (trailer.hasPrevious && trailer.previous >= offset) ||
        !tokens.Next(word) || word != "startxref" || !tokens.Next(word)) return std::nullopt;
    uint64_t declared;
    if (!Number(word, declared) || declared != offset) return std::nullopt;
    uint8_t c;
    while (tokens.Peek(c) && Space(c)) tokens.Read(c);
    uint8_t eof[5];
    if (reader.Read(eof, 5) != 5 || std::memcmp(eof, "%%EOF", 5) || reader.Position() != eofMarkerEnd) return std::nullopt;
    return trailer;
}
bool NextRevision(SequentialReader& reader, uint64_t position) {
    if (!reader.Seek(position)) return false;
    uint8_t c;
    while (reader.Position() - position < 65536 && reader.Peek(c)) {
        if (Space(c)) { reader.ReadByte(c); continue; }
        if (c != '%') break;
        const uint64_t comment = reader.Position();
        uint8_t prefix[5];
        const size_t read = reader.Read(prefix, sizeof(prefix));
        if (!reader.Seek(comment)) return false;
        if (read == 5 && std::memcmp(prefix, "%PDF-", 5) == 0) return false;
        while (reader.ReadByte(c) && c != 10 && c != 13) {}
    }
    Tokens tokens(reader, std::min(reader.MaxSize(), position + 65536));
    std::string word; uint64_t object, generation;
    if (!tokens.Next(word)) return false;
    if (word == "xref") return true;
    return Number(word, object) && object != 0 && tokens.Next(word) && Number(word, generation) &&
           generation <= 65535 && tokens.Next(word) && word == "obj";
}
}

std::optional<uint64_t> FileCarver::ParsePdfEnd(SequentialReader& reader, bool* incompleteRevision) {
    uint8_t header[8];
    if (reader.Read(header, 8) != 8 || std::memcmp(header, "%PDF-", 5) ||
        (header[5] != '1' && header[5] != '2') || header[6] != '.' || header[7] < '0' || header[7] > '9') return std::nullopt;
    std::array<char, 128> tail{};
    uint64_t seen = 0, rolling = 0, accepted = 0, acceptedXref = 0;
    bool updateStarted = false;
    uint8_t c;
    while (reader.ReadByte(c)) {
        tail[seen++ % tail.size()] = static_cast<char>(c);
        rolling = ((rolling << 8) | c) & 0xFFFFFFFFFFull;
        if (rolling != 0x2525454F46ull) continue;
        const uint64_t markerEnd = reader.Position();
        const size_t count = static_cast<size_t>(std::min<uint64_t>(seen, tail.size()));
        std::string text; text.reserve(count);
        for (uint64_t i = seen - count; i < seen; ++i) text += tail[i % tail.size()];
        size_t end = text.size() - 5;
        while (end && Space(static_cast<uint8_t>(text[end - 1]))) --end;
        const size_t digitsEnd = end;
        while (end && text[end - 1] >= '0' && text[end - 1] <= '9') --end;
        uint64_t offset;
        if (!Number(text.substr(end, digitsEnd - end), offset)) continue;
        while (end && Space(static_cast<uint8_t>(text[end - 1]))) --end;
        if (end < 9 || text.compare(end - 9, 9, "startxref") ||
            (end > 9 && !Space(static_cast<uint8_t>(text[end - 10])))) continue;
        const auto trailer = CheckCrossReference(reader, offset, markerEnd);
        if (!reader.Seek(markerEnd)) return std::nullopt;
        if (!trailer || (accepted && (!trailer->hasPrevious || trailer->previous != acceptedXref)) ||
            (!accepted && trailer->hasPrevious)) continue;
        accepted = markerEnd; acceptedXref = offset; updateStarted = false;
        // Preserve the EOF line ending, but never absorb cluster padding.
        if (reader.Peek(c) && c == 13) { reader.ReadByte(c); accepted = reader.Position(); }
        if (reader.Peek(c) && c == 10) { reader.ReadByte(c); accepted = reader.Position(); }
        if (!NextRevision(reader, accepted)) return accepted;
        updateStarted = true;
        if (!reader.Seek(accepted)) return std::nullopt;
        seen = rolling = 0;
    }
    if (accepted && incompleteRevision) *incompleteRevision = updateStarted;
    return accepted ? std::optional<uint64_t>(accepted) : std::nullopt;
}
}
