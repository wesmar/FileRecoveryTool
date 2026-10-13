// ============================================================================
// NameFilter.h - Name and folder filters
// ============================================================================
// Case-insensitive. A filter holding * or ? is a wildcard pattern over the
// whole name ("*.jpg", "IMG_????.*"); one without is a substring. Several
// filters are separated by ';' ("*.jpg;*.png").
// ============================================================================

#pragma once

#include <string>
#include <cwctype>

namespace KVC {

namespace detail {

inline bool WildcardMatch(const wchar_t* name, const wchar_t* pattern) {
    const wchar_t* star = nullptr;
    const wchar_t* resume = nullptr;
    while (*name) {
        if (*pattern == L'?' || towlower(*pattern) == towlower(*name)) {
            ++name;
            ++pattern;
        } else if (*pattern == L'*') {
            star = pattern++;
            resume = name;
        } else if (star) {
            pattern = star + 1;
            name = ++resume;
        } else {
            return false;
        }
    }
    while (*pattern == L'*') {
        ++pattern;
    }
    return *pattern == 0;
}

inline bool ContainsNoCase(const std::wstring& text, const std::wstring& part) {
    if (part.size() > text.size()) return false;
    for (size_t i = 0; i + part.size() <= text.size(); ++i) {
        size_t k = 0;
        while (k < part.size() && towlower(text[i + k]) == towlower(part[k])) ++k;
        if (k == part.size()) return true;
    }
    return false;
}

} // namespace detail

inline bool MatchesNameFilter(const std::wstring& name, const std::wstring& filter) {
    if (filter.empty()) {
        return true;
    }
    size_t start = 0;
    while (start <= filter.size()) {
        size_t end = filter.find(L';', start);
        if (end == std::wstring::npos) end = filter.size();
        const std::wstring one = filter.substr(start, end - start);
        if (!one.empty()) {
            const bool wildcard = one.find_first_of(L"*?") != std::wstring::npos;
            if (wildcard ? detail::WildcardMatch(name.c_str(), one.c_str())
                         : detail::ContainsNoCase(name, one)) {
                return true;
            }
        }
        start = end + 1;
    }
    return false;
}

inline bool MatchesFolderFilter(const std::wstring& folder, const std::wstring& filter) {
    return filter.empty() || detail::ContainsNoCase(folder, filter);
}

} // namespace KVC
