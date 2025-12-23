// ============================================================================
// ForensicsExceptions.h - Exception Types for Forensic Operations
// ============================================================================
// Defines custom exception classes for disk forensics error handling.
// Provides detailed error information for debugging and user feedback.
// ============================================================================


#pragma once

#include <climits>
#include <stdexcept>
#include <string>
#include <cstdint>

namespace KVC {

// ============================================================================
// Base Exception Class
// ============================================================================

class ForensicsException : public std::runtime_error {
public:
    explicit ForensicsException(const std::string& message)
        : std::runtime_error(message)
    {}
    
    explicit ForensicsException(const char* message)
        : std::runtime_error(message)
    {}
};

// ============================================================================
// Disk I/O Errors
// ============================================================================

class DiskReadError : public ForensicsException {
public:
    DiskReadError(uint64_t sector, uint64_t count, uint32_t errorCode)
        : ForensicsException(BuildMessage(sector, count, errorCode))
        , m_sector(sector)
        , m_count(count)
        , m_errorCode(errorCode)
    {}
    
    uint64_t Sector() const { return m_sector; }
    uint64_t Count() const { return m_count; }
    uint32_t ErrorCode() const { return m_errorCode; }

private:
    static std::string BuildMessage(uint64_t sector, uint64_t count, uint32_t errorCode) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), 
                "Failed to read %llu sectors starting at sector %llu (error code: 0x%08X)",
                static_cast<unsigned long long>(count),
                static_cast<unsigned long long>(sector),
                errorCode);
        return std::string(buffer);
    }
    
    uint64_t m_sector;
    uint64_t m_count;
    uint32_t m_errorCode;
};

class DiskWriteError : public ForensicsException {
public:
    DiskWriteError(const std::string& path, uint32_t errorCode)
        : ForensicsException(BuildMessage(path, errorCode))
        , m_path(path)
        , m_errorCode(errorCode)
    {}
    
    const std::string& Path() const { return m_path; }
    uint32_t ErrorCode() const { return m_errorCode; }

private:
    static std::string BuildMessage(const std::string& path, uint32_t errorCode) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer),
                "Failed to write to file '%s' (error code: 0x%08X)",
                path.c_str(), errorCode);
        return std::string(buffer);
    }
    
    std::string m_path;
    uint32_t m_errorCode;
};

// ============================================================================
// Cluster/Geometry Errors
// ============================================================================

class ClusterOutOfBoundsError : public ForensicsException {
public:
    ClusterOutOfBoundsError(uint64_t cluster, uint64_t maxCluster)
        : ForensicsException(BuildMessage(cluster, maxCluster))
        , m_cluster(cluster)
        , m_maxCluster(maxCluster)
    {}
    
    uint64_t Cluster() const { return m_cluster; }
    uint64_t MaxCluster() const { return m_maxCluster; }

private:
    static std::string BuildMessage(uint64_t cluster, uint64_t maxCluster) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer),
                "Cluster %llu is out of bounds (max: %llu)",
                static_cast<unsigned long long>(cluster),
                static_cast<unsigned long long>(maxCluster));
        return std::string(buffer);
    }
    
    uint64_t m_cluster;
    uint64_t m_maxCluster;
};

class InvalidGeometryError : public ForensicsException {
public:
    explicit InvalidGeometryError(const std::string& reason)
        : ForensicsException("Invalid volume geometry: " + reason)
    {}
};

// ============================================================================
// Filesystem Errors
// ============================================================================

class FilesystemError : public ForensicsException {
public:
    explicit FilesystemError(const std::string& message)
        : ForensicsException(message)
    {}
};

class CorruptedDataRunError : public FilesystemError {
public:
    CorruptedDataRunError(const std::string& details)
        : FilesystemError("Corrupted NTFS data run: " + details)
    {}
};

class InvalidMFTRecordError : public FilesystemError {
public:
    InvalidMFTRecordError(uint64_t recordNumber, const std::string& reason)
        : FilesystemError(BuildMessage(recordNumber, reason))
        , m_recordNumber(recordNumber)
    {}
    
    uint64_t RecordNumber() const { return m_recordNumber; }

private:
    static std::string BuildMessage(uint64_t recordNumber, const std::string& reason) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer),
                "Invalid MFT record %llu: %s",
                static_cast<unsigned long long>(recordNumber),
                reason.c_str());
        return std::string(buffer);
    }
    
    uint64_t m_recordNumber;
};

// ============================================================================
// File Carving Errors
// ============================================================================

class FileFormatError : public ForensicsException {
public:
    FileFormatError(const std::string& extension, const std::string& reason)
        : ForensicsException(BuildMessage(extension, reason))
        , m_extension(extension)
    {}
    
    const std::string& Extension() const { return m_extension; }

private:
    static std::string BuildMessage(const std::string& extension, const std::string& reason) {
        return "Invalid " + extension + " format: " + reason;
    }
    
    std::string m_extension;
};

class SignatureNotFoundError : public ForensicsException {
public:
    explicit SignatureNotFoundError(uint64_t offset)
        : ForensicsException(BuildMessage(offset))
        , m_offset(offset)
    {}
    
    uint64_t Offset() const { return m_offset; }

private:
    static std::string BuildMessage(uint64_t offset) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer),
                "No valid file signature found at offset %llu",
                static_cast<unsigned long long>(offset));
        return std::string(buffer);
    }
    
    uint64_t m_offset;
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

class InsufficientDataError : public RecoveryError {
public:
    InsufficientDataError(uint64_t expected, uint64_t actual)
        : RecoveryError(BuildMessage(expected, actual))
        , m_expected(expected)
        , m_actual(actual)
    {}
    
    uint64_t Expected() const { return m_expected; }
    uint64_t Actual() const { return m_actual; }

private:
    static std::string BuildMessage(uint64_t expected, uint64_t actual) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer),
                "Insufficient data: expected %llu bytes, got %llu bytes",
                static_cast<unsigned long long>(expected),
                static_cast<unsigned long long>(actual));
        return std::string(buffer);
    }
    
    uint64_t m_expected;
    uint64_t m_actual;
};

class DestinationInvalidError : public RecoveryError {
public:
    explicit DestinationInvalidError(const std::string& reason)
        : RecoveryError("Invalid recovery destination: " + reason)
    {}
};

} // namespace KVC