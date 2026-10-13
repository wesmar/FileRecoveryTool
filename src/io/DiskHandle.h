// ============================================================================
// DiskHandle.h - Low-level volume I/O
// ============================================================================
// Raw, read-only access to one volume: by drive letter (\\.\X:) or by any
// device path (\\.\HarddiskVolume7, \\?\Volume{GUID}) - the latter reaches
// partitions that have no drive letter, such as Linux ext4 ones.
// ============================================================================

#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace KVC {

class DiskHandle {
public:
    explicit DiskHandle(std::wstring devicePath);
    explicit DiskHandle(wchar_t driveLetter);
    ~DiskHandle();

    DiskHandle(const DiskHandle&) = delete;
    DiskHandle& operator=(const DiskHandle&) = delete;

    bool Open();
    void Close();
    bool IsOpen() const { return m_handle != INVALID_HANDLE_VALUE; }
    const std::wstring& Path() const { return m_path; }

    // Whole sectors from the start of the volume. Returns fewer bytes (or
    // none) when the volume ends or the device fails.
    std::vector<uint8_t> ReadSectors(uint64_t startSector, uint64_t numSectors, uint64_t sectorSize);

    // Any byte range: the covering sectors are read and the range cut out.
    std::vector<uint8_t> ReadBytes(uint64_t offset, uint64_t length);

    uint64_t GetSectorSize() const;     // asked once, then remembered
    uint64_t GetDiskSize() const;       // the volume's length in bytes

    struct MappedRegion {
        const uint8_t* data;
        uint64_t size;
        uint64_t diskOffset;

        MappedRegion() : data(nullptr), size(0), diskOffset(0) {}
        bool IsValid() const { return data != nullptr; }
    };

    MappedRegion MapDiskRegion(uint64_t offset, uint64_t size);
    void UnmapRegion(MappedRegion& region);

private:
    std::wstring m_path;
    HANDLE m_handle;
    HANDLE m_mappingHandle;
    void* m_mappedView;
    uint64_t m_currentMappedOffset;
    uint64_t m_currentMappedSize;
    mutable uint64_t m_sectorSize;
    mutable uint64_t m_diskSize;
};

} // namespace KVC
