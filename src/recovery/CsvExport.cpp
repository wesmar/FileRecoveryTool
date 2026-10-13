// ============================================================================
// CsvExport.cpp - Scan results as CSV
// ============================================================================

#include "recovery/CsvExport.h"

#include <Windows.h>
#include <chrono>
#include <cstdio>
#include <ctime>

namespace KVC {

namespace {

std::string ToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string Field(const std::wstring& text) {
    std::string utf8 = ToUtf8(text);
    if (utf8.find_first_of(",\"\r\n") == std::string::npos) return utf8;
    std::string quoted = "\"";
    for (char c : utf8) {
        if (c == '"') quoted += '"';
        quoted += c;
    }
    return quoted + "\"";
}

const char* QualityName(RecoveryQuality q) {
    switch (q) {
    case RecoveryQuality::Full: return "Full";
    case RecoveryQuality::Partial: return "Partial";
    case RecoveryQuality::MetadataOnly: return "MetadataOnly";
    default: return "Unrecoverable";
    }
}

} // namespace

bool ExportCandidatesToCsv(const std::wstring& path, const std::vector<RecoveryCandidate>& files) {
    FILE* csv = nullptr;
    if (_wfopen_s(&csv, path.c_str(), L"wb") != 0 || csv == nullptr) {
        return false;
    }
    fputs("\xEF\xBB\xBF", csv);
    fputs("Name,Path,Size,Size_Formatted,Filesystem,Quality,Recoverable,Has_Deleted_Time,Deleted_Time\r\n", csv);
    for (const auto& file : files) {
        std::wstring when;
        if (file.hasDeletedTime && file.deletedTime.has_value()) {
            const auto t = std::chrono::system_clock::to_time_t(file.deletedTime.value());
            std::tm tm_val;
            localtime_s(&tm_val, &t);
            wchar_t buf[64];
            wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S", &tm_val);
            when = buf;
        }
        const bool recoverable = file.IsRecoverable() || file.file.HasResidentData();
        const std::string line = Field(file.name) + "," + Field(file.path) + "," +
                                 std::to_string(file.fileSize) + "," + Field(file.sizeFormatted) + "," +
                                 Field(file.filesystemType) + "," + QualityName(file.quality) + "," +
                                 (recoverable ? "Yes" : "No") + "," + (file.hasDeletedTime ? "Yes" : "No") + "," +
                                 Field(when) + "\r\n";
        fputs(line.c_str(), csv);
    }
    const bool ok = ferror(csv) == 0;
    return fclose(csv) == 0 && ok;
}

} // namespace KVC
