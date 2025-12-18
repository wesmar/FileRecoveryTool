// ============================================================================
// StringUtils.h - String Utility Functions
// ============================================================================
// Helper functions for string operations and formatting.
// ============================================================================

#pragma once

#include <string>
#include <algorithm>
#include <cwctype>
#include <cstdio>
#include <cstdint>

namespace KVC {
namespace StringUtils {

// Convert wide string to lowercase for case-insensitive filtering.
inline std::wstring ToLower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

// Format byte count into human-readable string.
inline std::wstring FormatFileSize(uint64_t bytes) {
    wchar_t buffer[64];
    if (bytes >= 1000000000) {
        swprintf_s(buffer, L"%.2f GB", bytes / 1000000000.0);
    } else if (bytes >= 1000000) {
        swprintf_s(buffer, L"%.2f MB", bytes / 1000000.0);
    } else if (bytes >= 1000) {
        swprintf_s(buffer, L"%.2f KB", bytes / 1000.0);
    } else {
        swprintf_s(buffer, L"%llu bytes", bytes);
    }
    return std::wstring(buffer);
}

} // namespace StringUtils
} // namespace KVC
