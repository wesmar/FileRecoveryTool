// ============================================================================
// DiskHandle.h - Low-level disk I/O abstraction
// ============================================================================
// Provides raw sector reading and memory-mapped file access.
// ============================================================================

#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>

namespace KVC {

class DiskHandle {
public:
    explicit DiskHandle(wchar_t driveLetter);
    ~DiskHandle();

    bool Open();
    void Close();
    bool IsOpen() const { return m_handle != INVALID_HANDLE_VALUE; }

    std::vector<uint8_t> ReadSectors(uint64_t startSector, uint64_t numSectors, uint64_t sectorSize);
    uint64_t GetSectorSize() const;
    uint64_t GetDiskSize() const;

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
    wchar_t m_driveLetter;
    HANDLE m_handle;
    HANDLE m_mappingHandle;
    void* m_mappedView;
    uint64_t m_currentMappedOffset;
    uint64_t m_currentMappedSize;
};

} // namespace KVC