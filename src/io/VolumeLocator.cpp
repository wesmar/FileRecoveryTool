// ============================================================================
// VolumeLocator.cpp - Naming, listing and comparing volumes
// ============================================================================

#include "io/VolumeLocator.h"

#include <Windows.h>
#include <algorithm>
#include <cwctype>
#include <map>

namespace KVC {

namespace {

std::wstring QueryTarget(const std::wstring& dosName) {
    std::vector<wchar_t> buffer(1024);
    if (QueryDosDeviceW(dosName.c_str(), buffer.data(), static_cast<DWORD>(buffer.size())) == 0) {
        return {};
    }
    return buffer.data();       // the first target is the current one
}

// "\\.\X:" / "\\?\Volume{..}" / "\\.\HarddiskVolume7" -> the name QueryDosDevice takes
std::wstring DosNameOf(const std::wstring& volumePath) {
    std::wstring name = volumePath;
    if (name.rfind(L"\\\\.\\", 0) == 0 || name.rfind(L"\\\\?\\", 0) == 0) {
        name = name.substr(4);
    }
    while (!name.empty() && name.back() == L'\\') {
        name.pop_back();
    }
    return name;
}

} // namespace

std::wstring NormalizeVolumePath(const std::wstring& spec) {
    std::wstring s = spec;
    while (s.size() > 1 && (s.back() == L'\\' || s.back() == L'/')) {
        s.pop_back();
    }
    if (s.size() == 1 && iswalpha(s[0])) {
        return std::wstring(L"\\\\.\\") + static_cast<wchar_t>(towupper(s[0])) + L":";
    }
    if (s.size() == 2 && iswalpha(s[0]) && s[1] == L':') {
        return std::wstring(L"\\\\.\\") + static_cast<wchar_t>(towupper(s[0])) + L":";
    }
    if (s.rfind(L"\\\\", 0) != 0 && s.rfind(L"HarddiskVolume", 0) == 0) {
        return L"\\\\.\\" + s;      // a bare object name
    }
    return s;
}

wchar_t DriveLetterOf(const std::wstring& volumePath) {
    const std::wstring name = DosNameOf(volumePath);
    if (name.size() == 2 && iswalpha(name[0]) && name[1] == L':') {
        return static_cast<wchar_t>(towupper(name[0]));
    }
    return 0;
}

std::wstring NtDeviceOfVolume(const std::wstring& volumePath) {
    return QueryTarget(DosNameOf(volumePath));
}

std::wstring NtDeviceOfFolder(const std::wstring& folder) {
    wchar_t full[MAX_PATH] = {};
    if (GetFullPathNameW(folder.c_str(), MAX_PATH, full, nullptr) == 0) {
        return {};
    }
    wchar_t mountPoint[MAX_PATH] = {};
    if (!GetVolumePathNameW(full, mountPoint, MAX_PATH)) {
        return {};
    }
    wchar_t volumeName[MAX_PATH] = {};
    if (GetVolumeNameForVolumeMountPointW(mountPoint, volumeName, MAX_PATH)) {
        return QueryTarget(DosNameOf(volumeName));
    }
    return QueryTarget(DosNameOf(mountPoint));      // a network or substituted drive
}

std::vector<VolumeEntry> EnumerateVolumes() {
    // all DOS device names, NUL-separated; the list grows with the system
    std::vector<wchar_t> names(1 << 16);
    while (QueryDosDeviceW(nullptr, names.data(), static_cast<DWORD>(names.size())) == 0) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || names.size() > (1u << 24)) {
            return {};
        }
        names.resize(names.size() * 2);
    }

    std::map<std::wstring, VolumeEntry> byDevice;
    std::vector<std::wstring> letters;
    for (const wchar_t* p = names.data(); *p; p += wcslen(p) + 1) {
        const std::wstring name = p;
        // HarddiskVolumeN, not HarddiskVolumeShadowCopyN
        if (name.rfind(L"HarddiskVolume", 0) == 0 && name.size() > 14 &&
            name.find_first_not_of(L"0123456789", 14) == std::wstring::npos) {
            const std::wstring target = QueryTarget(name);
            if (!target.empty() && byDevice.find(target) == byDevice.end()) {
                byDevice[target] = VolumeEntry{ L"\\\\.\\" + name, target, L"" };
            }
        } else if (name.size() == 2 && iswalpha(name[0]) && name[1] == L':') {
            letters.push_back(name);
        }
    }
    for (const auto& letter : letters) {
        const std::wstring target = QueryTarget(letter);
        auto it = byDevice.find(target);
        if (it != byDevice.end()) {
            it->second.path = L"\\\\.\\" + letter;
            it->second.letters += it->second.letters.empty() ? letter : L" " + letter;
        }
    }

    std::vector<VolumeEntry> result;
    for (auto& [device, entry] : byDevice) {
        result.push_back(entry);
    }
    // lettered volumes first, in letter order; then the rest by device number
    std::sort(result.begin(), result.end(), [](const VolumeEntry& a, const VolumeEntry& b) {
        if (a.letters.empty() != b.letters.empty()) return !a.letters.empty();
        if (!a.letters.empty()) return a.letters < b.letters;
        auto number = [](const std::wstring& d) {
            size_t i = d.find_last_not_of(L"0123456789");
            return i == std::wstring::npos ? 0 : _wtoi(d.c_str() + i + 1);
        };
        return number(a.ntDevice) < number(b.ntDevice);
    });
    return result;
}

} // namespace KVC
