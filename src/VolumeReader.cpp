// ============================================================================
// VolumeReader.cpp - Volume I/O Abstraction Implementation
// ============================================================================

#include "VolumeReader.h"
#include "FragmentedFile.h"
#include "SafetyLimits.h"

#include <climits>
#include <stdexcept>
#include <algorithm>

namespace KVC {

VolumeReader::VolumeReader(DiskHandle& disk, const VolumeGeometry& geometry)
    : m_disk(disk)
    , m_geometry(geometry)
    , m_mappedStartLCN(0)
    , m_mappedClusterCount(0)
{
}

VolumeReader::~VolumeReader() {
    if (m_currentMapping.IsValid()) {
        m_disk.UnmapRegion(m_currentMapping);
    }
}

std::vector<uint8_t> VolumeReader::ReadClusters(uint64_t startLCN, uint64_t count) {
    if (count == 0) {
        return {};
    }
    
    // Validate bounds
    if (!m_geometry.IsValidLCN(startLCN)) {
        throw ClusterOutOfBoundsError(startLCN, m_geometry.totalClusters);
    }
    
    if (!m_geometry.IsValidLCN(startLCN + count - 1)) {
        throw ClusterOutOfBoundsError(startLCN + count - 1, m_geometry.totalClusters);
    }
    
    // Overflow check
    uint64_t bytesToRead = count * m_geometry.bytesPerCluster;
    if (count > UINT64_MAX / m_geometry.bytesPerCluster) {
        throw std::overflow_error("Cluster count too large");
    }
    
    // Convert LCN to physical offset
    uint64_t physicalOffset = m_geometry.LCNToPhysicalOffset(startLCN);
    
    // Calculate sector range
    uint64_t startSector = physicalOffset / m_geometry.sectorSize;
    uint64_t sectorsNeeded = (bytesToRead + m_geometry.sectorSize - 1) / m_geometry.sectorSize;
    
    // Read via DiskHandle
    auto data = m_disk.ReadSectors(startSector, sectorsNeeded, m_geometry.sectorSize);
    
    if (data.empty()) {
        throw DiskReadError(startSector, sectorsNeeded, GetLastError());
    }
    
    // Trim to exact cluster boundary
    if (data.size() > bytesToRead) {
        data.resize(static_cast<size_t>(bytesToRead));
    }
    
    return data;
}

std::vector<uint8_t> VolumeReader::ReadClusterRun(const ClusterRun& run) {
    if (!run.IsValid()) {
        return {};
    }
    
    return ReadClusters(run.startCluster, run.clusterCount);
}

VolumeReader::MappedView VolumeReader::MapClusters(uint64_t startLCN, uint64_t count) {
    MappedView view;
    view.valid = false;
    view.data = nullptr;
    view.size = 0;
    view.startLCN = startLCN;
    
    if (count == 0) {
        return view;
    }
    
    // Validate bounds
    if (!m_geometry.IsValidLCN(startLCN) || 
        !m_geometry.IsValidLCN(startLCN + count - 1)) {
        return view;
    }
    
    // Check if already mapped (sliding window reuse)
    if (m_currentMapping.IsValid() &&
        startLCN >= m_mappedStartLCN &&
        startLCN + count <= m_mappedStartLCN + m_mappedClusterCount) {
        
        uint64_t offsetInMapping = (startLCN - m_mappedStartLCN) * m_geometry.bytesPerCluster;
        view.data = m_currentMapping.data + offsetInMapping;
        view.size = count * m_geometry.bytesPerCluster;
        view.startLCN = startLCN;
        view.valid = true;
        return view;
    }
    
    // Unmap previous region
    if (m_currentMapping.IsValid()) {
        m_disk.UnmapRegion(m_currentMapping);
        m_currentMapping = DiskHandle::MappedRegion();
    }
    
    // Calculate mapping size
    uint64_t bytesToMap = count * m_geometry.bytesPerCluster;
    
    // Limit to MAX_MAPPING_SIZE
    if (bytesToMap > Limits::MAX_MAPPING_SIZE) {
        bytesToMap = Limits::MAX_MAPPING_SIZE;
        count = bytesToMap / m_geometry.bytesPerCluster;
    }
    
    // Convert LCN to physical offset
    uint64_t physicalOffset = m_geometry.LCNToPhysicalOffset(startLCN);
    
    // Try to map
    m_currentMapping = m_disk.MapDiskRegion(physicalOffset, bytesToMap);
    
    if (m_currentMapping.IsValid()) {
        m_mappedStartLCN = startLCN;
        m_mappedClusterCount = bytesToMap / m_geometry.bytesPerCluster;
        
        view.data = m_currentMapping.data;
        view.size = m_currentMapping.size;
        view.startLCN = startLCN;
        view.valid = true;
    }
    
    return view;
}

void VolumeReader::UnmapView(MappedView& view) {
    // Actual unmapping happens in destructor or on next MapClusters
    // Just invalidate the view struct
    view.valid = false;
    view.data = nullptr;
    view.size = 0;
}

bool VolumeReader::ValidateClusterRange(uint64_t startLCN, uint64_t count) {
    if (count == 0) {
        return true;
    }
    
    if (!m_geometry.IsValidLCN(startLCN) || 
        !m_geometry.IsValidLCN(startLCN + count - 1)) {
        return false;
    }
    
    try {
        // Try to read first cluster only (optimization)
        auto data = ReadClusters(startLCN, 1);
        return !data.empty();
    } catch (const DiskReadError&) {
        return false;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace KVC