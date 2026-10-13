// Physical source/destination checks, including volumes spanning several disks.
#include "io/VolumeLocator.h"
#include <Windows.h>
#include <winioctl.h>
#include <algorithm>

namespace KVC {
namespace {

class Handle {
public:
    explicit Handle(const std::wstring& path) : value(CreateFileW(path.c_str(), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr)) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    HANDLE value;
};

std::optional<std::vector<uint32_t>> DiskNumbers(const std::wstring& path) {
    Handle handle(path);
    if (handle.value == INVALID_HANDLE_VALUE) return std::nullopt;
    std::vector<uint8_t> buffer(sizeof(VOLUME_DISK_EXTENTS));
    DWORD returned = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const BOOL ok = DeviceIoControl(handle.value, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0,
            buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buffer.data());
        if (ok) {
            if (returned < sizeof(VOLUME_DISK_EXTENTS) || extents->NumberOfDiskExtents == 0 ||
                extents->NumberOfDiskExtents > (returned - offsetof(VOLUME_DISK_EXTENTS, Extents)) / sizeof(DISK_EXTENT)) return std::nullopt;
            std::vector<uint32_t> disks;
            for (DWORD i = 0; i < extents->NumberOfDiskExtents; ++i) disks.push_back(extents->Extents[i].DiskNumber);
            return disks;
        }
        if (error != ERROR_MORE_DATA || returned < sizeof(VOLUME_DISK_EXTENTS) ||
            extents->NumberOfDiskExtents > 4096 || extents->NumberOfDiskExtents == 0) break;
        const size_t bytes = offsetof(VOLUME_DISK_EXTENTS, Extents) + extents->NumberOfDiskExtents * sizeof(DISK_EXTENT);
        buffer.resize(bytes);
    }
    // A physical disk has no volume extents. Accept the device-number query
    // only for the whole disk, never as a substitute for a spanned volume.
    STORAGE_DEVICE_NUMBER number{};
    if (DeviceIoControl(handle.value, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0,
        &number, sizeof(number), &returned, nullptr) && number.DeviceType == FILE_DEVICE_DISK &&
        (number.PartitionNumber == 0 || number.PartitionNumber == UINT32_MAX)) return std::vector<uint32_t>{number.DeviceNumber};
    return std::nullopt;
}

} // namespace

std::optional<std::vector<uint32_t>> PhysicalDisksOfSource(const std::wstring& source) {
    const DWORD attributes = GetFileAttributesW(source.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES) return std::nullopt;
    return DiskNumbers(NormalizeVolumePath(source));
}

std::optional<std::vector<uint32_t>> PhysicalDisksOfFolder(const std::wstring& folder) {
    wchar_t full[32768]{}, mount[32768]{}, volume[MAX_PATH]{};
    const DWORD length = GetFullPathNameW(folder.c_str(), static_cast<DWORD>(std::size(full)), full, nullptr);
    if (length == 0 || length >= std::size(full) ||
        !GetVolumePathNameW(full, mount, static_cast<DWORD>(std::size(mount))) ||
        !GetVolumeNameForVolumeMountPointW(mount, volume, MAX_PATH)) return std::nullopt;
    return DiskNumbers(NormalizeVolumePath(volume));
}

bool PathsReferToSameFile(const std::wstring& first, const std::wstring& second) {
    Handle a(first), b(second);
    BY_HANDLE_FILE_INFORMATION ai{}, bi{};
    if (!GetFileInformationByHandle(a.value, &ai) || !GetFileInformationByHandle(b.value, &bi)) return false;
    return ai.dwVolumeSerialNumber == bi.dwVolumeSerialNumber && ai.nFileIndexHigh == bi.nFileIndexHigh && ai.nFileIndexLow == bi.nFileIndexLow;
}

std::vector<std::wstring> EnumeratePhysicalDisks() {
    std::vector<wchar_t> names(65536);
    while (!QueryDosDeviceW(nullptr, names.data(), static_cast<DWORD>(names.size()))) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || names.size() >= (1u << 24)) return {};
        names.resize(names.size() * 2);
    }
    std::vector<std::wstring> disks;
    for (const wchar_t* p = names.data(); *p; p += wcslen(p) + 1) {
        const std::wstring name(p);
        if (name.rfind(L"PhysicalDrive", 0) == 0 && name.size() > 13 &&
            name.find_first_not_of(L"0123456789", 13) == std::wstring::npos) disks.push_back(L"\\\\.\\" + name);
    }
    std::sort(disks.begin(), disks.end(), [](const auto& a, const auto& b) {
        const auto ai = a.substr(17), bi = b.substr(17);
        return ai.size() == bi.size() ? ai < bi : ai.size() < bi.size();
    });
    return disks;
}

} // namespace KVC
