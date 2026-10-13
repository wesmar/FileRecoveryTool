// ============================================================================
// VolumeLocator.h - Naming, listing and comparing volumes
// ============================================================================
// A source volume is named by a drive letter ("D", "D:") or by a device path
// ("\\.\HarddiskVolume7", "\\?\Volume{GUID}"). Volumes without a letter -
// Linux partitions above all - are listed from the object namespace, where
// every partition has a HarddiskVolumeN name whether it is mounted or not.
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace KVC {

// "D", "D:", "D:\" -> "\\.\D:"; device paths are kept, minus a trailing '\'.
std::wstring NormalizeVolumePath(const std::wstring& spec);

// The drive letter of a source, or 0 when it is named by a device path.
wchar_t DriveLetterOf(const std::wstring& volumePath);

// \Device\HarddiskVolumeN behind a volume path or a folder on a volume, or
// an empty string when it cannot be resolved.
std::wstring NtDeviceOfVolume(const std::wstring& volumePath);
std::wstring NtDeviceOfFolder(const std::wstring& folder);

// No value means the storage topology cannot be queried. Flat image files
// are excluded; their host disk is not the source disk represented by them.
std::optional<std::vector<uint32_t>> PhysicalDisksOfSource(const std::wstring& source);
std::optional<std::vector<uint32_t>> PhysicalDisksOfFolder(const std::wstring& folder);
bool PathsReferToSameFile(const std::wstring& first, const std::wstring& second);

struct VolumeEntry {
    std::wstring path;          // what DiskHandle opens
    std::wstring ntDevice;      // \Device\HarddiskVolumeN
    std::wstring letters;       // "D:" or "" for a volume without one
};

// Every disk volume: lettered ones and the HarddiskVolumeN without a letter.
std::vector<VolumeEntry> EnumerateVolumes();
std::vector<std::wstring> EnumeratePhysicalDisks();

} // namespace KVC
