// ============================================================================
// ForensicsExceptions.h - Exception Hierarchy for Forensics Operations
// ============================================================================
// Modern C++ exception classes for disk forensics error handling.
// Replaces bool return codes with semantic exception types.
// ============================================================================

#pragma once

#include <stdexcept>
#include <string>
#include <cstdint>

namespace KVC {

// ============================================================================
// Base Exception
// ============================================================================

class ForensicsException : public std::runtime_error {
public:
    explicit ForensicsException(const std::string& message)
        : std::runtime_error(message)
        , m_errorCode(0)
    {}
    
    ForensicsException(const std::string& message, uint32_t errorCode)
        : std::runtime_error(message)
        , m_errorCode(errorCode)
    {}
    
    uint32_t ErrorCode() const noexcept { return m_errorCode; }

protected:
    uint32_t m_errorCode;
};

// ============================================================================
// Disk I/O Errors
// ============================================================================

class DiskIOError : public ForensicsException {
public:
    DiskIOError(const std::string& message, uint64_t sector = 0, uint64_t count = 0)
        : ForensicsException(message)
        , m_sector(sector)
        , m_sectorCount(count)
    {}
    
    DiskIOError(const std::string& message, uint32_t errorCode, uint64_t sector = 0)
        : ForensicsException(message, errorCode)
        , m_sector(sector)
        , m_sectorCount(0)
    {}
    
    uint64_t Sector() const noexcept { return m_sector; }
    uint64_t SectorCount() const noexcept { return m_sectorCount; }

private:
    uint64_t m_sector;
    uint64_t m_sectorCount;
};

class DiskReadError : public DiskIOError {
public:
    DiskReadError(uint64_t sector, uint64_t count, uint32_t errorCode = 0)
        : DiskIOError("Failed to read sectors from disk", errorCode, sector)
    {
        m_sectorCount = count;
    }
    
private:
    uint64_t m_sectorCount;
};

class DiskMappingError : public DiskIOError {
public:
    DiskMappingError(uint64_t offset, uint64_t size)
        : DiskIOError("Failed to memory-map disk region")
        , m_offset(offset)
        , m_size(size)
    {}
    
    uint64_t Offset() const noexcept { return m_offset; }
    uint64_t Size() const noexcept { return m_size; }

private:
    uint64_t m_offset;
    uint64_t m_size;
};

// ============================================================================
// Filesystem Corruption Errors
// ============================================================================

class FilesystemCorruption : public ForensicsException {
public:
    enum class Type {
        InvalidSignature,
        InvalidBootSector,
        InvalidMFTRecord,
        InvalidDataRun,
        InvalidClusterChain,
        OutOfBounds,
        CircularReference
    };
    
    FilesystemCorruption(Type type, const std::string& message)
        : ForensicsException(message)
        , m_type(type)
        , m_location(0)
    {}
    
    FilesystemCorruption(Type type, const std::string& message, uint64_t location)
        : ForensicsException(message)
        , m_type(type)
        , m_location(location)
    {}
    
    Type CorruptionType() const noexcept { return m_type; }
    uint64_t Location() const noexcept { return m_location; }

private:
    Type m_type;
    uint64_t m_location;
};

class InvalidDataRunError : public FilesystemCorruption {
public:
    InvalidDataRunError(uint64_t mftRecord, const std::string& reason)
        : FilesystemCorruption(Type::InvalidDataRun, 
            "Invalid data run in MFT record " + std::to_string(mftRecord) + ": " + reason,
            mftRecord)
        , m_mftRecord(mftRecord)
    {}
    
    uint64_t MftRecord() const noexcept { return m_mftRecord; }

private:
    uint64_t m_mftRecord;
};

class ClusterOutOfBoundsError : public FilesystemCorruption {
public:
    ClusterOutOfBoundsError(uint64_t cluster, uint64_t maxCluster)
        : FilesystemCorruption(Type::OutOfBounds,
            "Cluster " + std::to_string(cluster) + " exceeds disk bounds (" + 
            std::to_string(maxCluster) + ")",
            cluster)
        , m_cluster(cluster)
        , m_maxCluster(maxCluster)
    {}
    
    uint64_t Cluster() const noexcept { return m_cluster; }
    uint64_t MaxCluster() const noexcept { return m_maxCluster; }

private:
    uint64_t m_cluster;
    uint64_t m_maxCluster;
};

// ============================================================================
// File Format Errors
// ============================================================================

class SignatureMismatch : public ForensicsException {
public:
    SignatureMismatch(const std::string& expectedFormat, uint64_t offset = 0)
        : ForensicsException("Signature mismatch: expected " + expectedFormat)
        , m_expectedFormat(expectedFormat)
        , m_offset(offset)
    {}
    
    const std::string& ExpectedFormat() const noexcept { return m_expectedFormat; }
    uint64_t Offset() const noexcept { return m_offset; }

private:
    std::string m_expectedFormat;
    uint64_t m_offset;
};

class FileFormatError : public ForensicsException {
public:
    FileFormatError(const std::string& format, const std::string& reason)
        : ForensicsException(format + " format error: " + reason)
        , m_format(format)
    {}
    
    const std::string& Format() const noexcept { return m_format; }

private:
    std::string m_format;
};

// ============================================================================
// Recovery Errors
// ============================================================================

class RecoveryError : public ForensicsException {
public:
    explicit RecoveryError(const std::string& message)
        : ForensicsException(message)
    {}
};

class DestinationError : public RecoveryError {
public:
    explicit DestinationError(const std::string& path)
        : RecoveryError("Invalid destination: " + path)
        , m_path(path)
    {}
    
    const std::string& Path() const noexcept { return m_path; }

private:
    std::string m_path;
};

class FragmentationError : public RecoveryError {
public:
    FragmentationError(uint64_t fileRecord, size_t fragmentCount)
        : RecoveryError("Excessive fragmentation in record " + std::to_string(fileRecord))
        , m_fileRecord(fileRecord)
        , m_fragmentCount(fragmentCount)
    {}
    
    uint64_t FileRecord() const noexcept { return m_fileRecord; }
    size_t FragmentCount() const noexcept { return m_fragmentCount; }

private:
    uint64_t m_fileRecord;
    size_t m_fragmentCount;
};

} // namespace KVC
