// ============================================================================
// DiskHandle.cpp - Low-level volume I/O
// ============================================================================

#include "io/DiskHandle.h"
#include "support/Constants.h"
#include "support/SafetyLimits.h"

#include <winioctl.h>
#include <algorithm>
#include <climits>

namespace KVC {

DiskHandle::DiskHandle(std::wstring devicePath)
    : m_path(std::move(devicePath))
    , m_handle(INVALID_HANDLE_VALUE)
    , m_mappingHandle(nullptr)
    , m_mappedView(nullptr)
    , m_currentMappedOffset(0)
    , m_currentMappedSize(0)
    , m_sectorSize(0)
    , m_diskSize(0)
{
}

DiskHandle::DiskHandle(wchar_t driveLetter)
    : DiskHandle(std::wstring(L"\\\\.\\") + driveLetter + L":")
{
}

DiskHandle::~DiskHandle() {
    Close();
}

bool DiskHandle::Open() {
    Close();
    m_sectorSize = 0;
    m_diskSize = 0;
    m_handle = CreateFileW(
        m_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (m_handle == INVALID_HANDLE_VALUE) {
        return false;
    }

    // Reads past the file system's own end (the volume can be larger than
    // what the file system covers, and a damaged boot sector says nothing
    // reliable about it) are allowed only with extended DASD I/O.
    DWORD returned = 0;
    DeviceIoControl(m_handle, FSCTL_ALLOW_EXTENDED_DASD_IO, nullptr, 0, nullptr, 0, &returned, nullptr);
    return true;
}

void DiskHandle::Close() {
    if (m_mappedView != nullptr) {
        UnmapViewOfFile(m_mappedView);
        m_mappedView = nullptr;
    }
    m_currentMappedOffset = 0;
    m_currentMappedSize = 0;

    if (m_mappingHandle != nullptr && m_mappingHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_mappingHandle);
    }
    m_mappingHandle = nullptr;

    if (m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
}

std::vector<uint8_t> DiskHandle::ReadSectors(uint64_t startSector, uint64_t numSectors, uint64_t sectorSize) {
    if (m_handle == INVALID_HANDLE_VALUE || numSectors == 0 || sectorSize == 0) {
        return {};
    }
    if (numSectors > (UINT64_MAX / sectorSize) || startSector > (UINT64_MAX / sectorSize)) {
        return {};
    }

    const uint64_t totalBytes = numSectors * sectorSize;
    if (totalBytes > Limits::MAX_SINGLE_READ) {
        return {};
    }

    LARGE_INTEGER offset;
    offset.QuadPart = static_cast<LONGLONG>(startSector * sectorSize);
    if (SetFilePointerEx(m_handle, offset, nullptr, FILE_BEGIN) == 0) {
        return {};
    }

    std::vector<uint8_t> buffer;
    try {
        buffer.resize(static_cast<size_t>(totalBytes));
    } catch (const std::bad_alloc&) {
        return {};
    }

    uint64_t done = 0;
    while (done < totalBytes) {
        const uint64_t chunk = std::min(totalBytes - done, Constants::MAX_READ_CHUNK);
        DWORD bytesRead = 0;
        const BOOL ok = ReadFile(m_handle, buffer.data() + done, static_cast<DWORD>(chunk), &bytesRead, nullptr);
        if (!ok || bytesRead == 0) {
            break;
        }
        done += bytesRead;
        if (bytesRead < chunk) {
            break;
        }
    }
    buffer.resize(static_cast<size_t>(done));
    return buffer;
}

std::vector<uint8_t> DiskHandle::ReadBytes(uint64_t offset, uint64_t length) {
    const uint64_t sector = GetSectorSize();
    if (length == 0 || sector == 0 || length > UINT64_MAX - offset ||
        offset + length > UINT64_MAX - (sector - 1)) {
        return {};
    }
    const uint64_t first = offset / sector;
    const uint64_t last = (offset + length + sector - 1) / sector;
    auto data = ReadSectors(first, last - first, sector);

    const uint64_t skip = offset - first * sector;
    if (data.size() <= skip) {
        return {};
    }
    const uint64_t available = std::min<uint64_t>(length, data.size() - skip);
    return std::vector<uint8_t>(data.begin() + static_cast<ptrdiff_t>(skip),
                                data.begin() + static_cast<ptrdiff_t>(skip + available));
}

uint64_t DiskHandle::GetSectorSize() const {
    if (m_sectorSize != 0) {
        return m_sectorSize;
    }
    if (m_handle == INVALID_HANDLE_VALUE) {
        return Limits::DEFAULT_SECTOR_SIZE;
    }

    DISK_GEOMETRY geometry = {};
    DWORD bytesReturned = 0;
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0,
                        &geometry, sizeof(geometry), &bytesReturned, nullptr) &&
        geometry.BytesPerSector != 0) {
        m_sectorSize = geometry.BytesPerSector;
    } else {
        m_sectorSize = Limits::DEFAULT_SECTOR_SIZE;
    }
    return m_sectorSize;
}

uint64_t DiskHandle::GetDiskSize() const {
    if (m_diskSize != 0) {
        return m_diskSize;
    }
    if (m_handle == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD bytesReturned = 0;
    GET_LENGTH_INFORMATION lengthInfo = {};
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                        &lengthInfo, sizeof(lengthInfo), &bytesReturned, nullptr)) {
        m_diskSize = static_cast<uint64_t>(lengthInfo.Length.QuadPart);
        return m_diskSize;
    }

    // Flat images are ordinary files, not block devices. Their exact length
    // may include a final incomplete sector.
    LARGE_INTEGER fileSize{};
    if (GetFileSizeEx(m_handle, &fileSize) && fileSize.QuadPart >= 0) {
        m_diskSize = static_cast<uint64_t>(fileSize.QuadPart);
        return m_diskSize;
    }

    DISK_GEOMETRY geometry = {};
    if (DeviceIoControl(m_handle, IOCTL_DISK_GET_DRIVE_GEOMETRY, nullptr, 0,
                        &geometry, sizeof(geometry), &bytesReturned, nullptr)) {
        m_diskSize = static_cast<uint64_t>(geometry.Cylinders.QuadPart) *
                     geometry.TracksPerCylinder * geometry.SectorsPerTrack * geometry.BytesPerSector;
    }
    return m_diskSize;
}

DiskHandle::MappedRegion DiskHandle::MapDiskRegion(uint64_t offset, uint64_t size) {
    MappedRegion region;
    if (m_handle == INVALID_HANDLE_VALUE) {
        return region;
    }

    if (m_mappedView != nullptr &&
        offset >= m_currentMappedOffset &&
        offset + size <= m_currentMappedOffset + m_currentMappedSize) {
        region.data = static_cast<const uint8_t*>(m_mappedView) + (offset - m_currentMappedOffset);
        region.size = size;
        region.diskOffset = offset;
        return region;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t granularity = sysInfo.dwAllocationGranularity;
    const uint64_t alignedOffset = (offset / granularity) * granularity;
    const uint64_t extraBytes = offset - alignedOffset;
    const uint64_t adjustedSize = std::min<uint64_t>(size + extraBytes, Limits::MAX_MAPPING_SIZE);

    HANDLE hMapping = CreateFileMappingW(m_handle, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (hMapping == nullptr) {
        return region;
    }

    LARGE_INTEGER fileOffset;
    fileOffset.QuadPart = static_cast<LONGLONG>(alignedOffset);
    void* pView = MapViewOfFile(hMapping, FILE_MAP_READ, static_cast<DWORD>(fileOffset.HighPart),
                                fileOffset.LowPart, static_cast<SIZE_T>(adjustedSize));
    if (pView == nullptr) {
        CloseHandle(hMapping);
        return region;
    }

    if (m_mappingHandle != nullptr) {
        CloseHandle(m_mappingHandle);
    }
    if (m_mappedView != nullptr) {
        UnmapViewOfFile(m_mappedView);
    }
    m_mappingHandle = hMapping;
    m_mappedView = pView;
    m_currentMappedOffset = alignedOffset;
    m_currentMappedSize = adjustedSize;

    region.data = static_cast<const uint8_t*>(pView) + extraBytes;
    region.size = adjustedSize - extraBytes;
    region.diskOffset = offset;
    return region;
}

void DiskHandle::UnmapRegion(MappedRegion& region) {
    region.data = nullptr;
    region.size = 0;
    region.diskOffset = 0;
}

} // namespace KVC
