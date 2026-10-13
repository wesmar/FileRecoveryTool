// ============================================================================
// FilesystemDetector.cpp - What file system a volume holds, from its sectors
// ============================================================================

#include "filesystems/FilesystemDetector.h"

#include <cstring>

namespace KVC {

namespace {

uint16_t Le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint32_t Le32(const uint8_t* p) { return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
                                         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24); }

bool IsPowerOfTwo(uint32_t v) { return v != 0 && (v & (v - 1)) == 0; }

// Clusters below these counts make a volume FAT12, then FAT16 (FAT spec 1.03)
constexpr uint32_t FAT12_MAX_CLUSTERS = 4085;
constexpr uint32_t FAT16_MAX_CLUSTERS = 65525;

// ext2/3/4 superblock: 1024 bytes into the volume
constexpr uint64_t EXT_SUPERBLOCK_OFFSET = 1024;
constexpr uint16_t EXT_MAGIC = 0xEF53;
constexpr uint32_t EXT_COMPAT_HAS_JOURNAL = 0x0004;
constexpr uint32_t EXT_INCOMPAT_EXTENTS = 0x0040;
constexpr uint32_t EXT_INCOMPAT_64BIT = 0x0080;
constexpr uint32_t EXT_INCOMPAT_FLEX_BG = 0x0200;

} // namespace

std::optional<FatLayout> ParseFatBootSector(const uint8_t* s, size_t size) {
    if (size < 512) {
        return std::nullopt;
    }
    // jump instruction: EB xx 90 or E9 xx xx
    if (!(s[0] == 0xEB && s[2] == 0x90) && s[0] != 0xE9) {
        return std::nullopt;
    }

    FatLayout fat;
    fat.bytesPerSector = Le16(s + 11);
    fat.sectorsPerCluster = s[13];
    const uint32_t reserved = Le16(s + 14);
    fat.numberOfFats = s[16];
    const uint32_t rootEntries = Le16(s + 17);
    const uint32_t totalSectors16 = Le16(s + 19);
    const uint32_t fatSize16 = Le16(s + 22);
    const uint32_t totalSectors32 = Le32(s + 32);
    const uint32_t fatSize32 = Le32(s + 36);

    if (!IsPowerOfTwo(fat.bytesPerSector) || fat.bytesPerSector < 512 || fat.bytesPerSector > 4096 ||
        !IsPowerOfTwo(fat.sectorsPerCluster) || reserved == 0 || fat.numberOfFats == 0) {
        return std::nullopt;
    }

    fat.fatSectors = fatSize16 != 0 ? fatSize16 : fatSize32;
    const uint64_t totalSectors = totalSectors16 != 0 ? totalSectors16 : totalSectors32;
    fat.rootDirSectors = (static_cast<uint64_t>(rootEntries) * 32 + fat.bytesPerSector - 1) / fat.bytesPerSector;
    fat.fatStartSector = reserved;
    fat.rootDirStartSector = fat.fatStartSector + fat.numberOfFats * fat.fatSectors;
    fat.dataStartSector = fat.rootDirStartSector + fat.rootDirSectors;
    if (fat.fatSectors == 0 || totalSectors <= fat.dataStartSector) {
        return std::nullopt;
    }

    const uint64_t clusters = (totalSectors - fat.dataStartSector) / fat.sectorsPerCluster;
    if (clusters == 0 || clusters > 0x0FFFFFF5) {
        return std::nullopt;
    }
    fat.clusterCount = static_cast<uint32_t>(clusters);
    fat.clusterSize = fat.bytesPerSector * fat.sectorsPerCluster;

    if (fat.clusterCount < FAT12_MAX_CLUSTERS) {
        fat.type = FilesystemType::FAT12;
    } else if (fat.clusterCount < FAT16_MAX_CLUSTERS) {
        fat.type = FilesystemType::FAT16;
    } else {
        fat.type = FilesystemType::FAT32;
        fat.rootCluster = Le32(s + 44);
        if (rootEntries != 0 || fatSize16 != 0 || fat.rootCluster < 2) {
            return std::nullopt;
        }
    }
    // a FAT12/16 volume must say how big its root directory is
    if (fat.type != FilesystemType::FAT32 && rootEntries == 0) {
        return std::nullopt;
    }
    return fat;
}

VolumeInfo DetectFilesystem(DiskHandle& disk) {
    VolumeInfo info;
    info.size = disk.GetDiskSize();

    const auto boot = disk.ReadBytes(0, 512);
    if (boot.size() >= 512) {
        if (std::memcmp(boot.data() + 3, "NTFS    ", 8) == 0) {
            info.type = FilesystemType::NTFS;
        } else if (std::memcmp(boot.data() + 3, "EXFAT   ", 8) == 0) {
            info.type = FilesystemType::ExFAT;
        } else if (auto fat = ParseFatBootSector(boot.data(), boot.size())) {
            info.type = fat->type;
        }
        if (info.type != FilesystemType::Unknown) {
            info.name = FilesystemName(info.type);
            return info;
        }
    }

    const auto sb = disk.ReadBytes(EXT_SUPERBLOCK_OFFSET, 1024);
    if (sb.size() >= 1024 && Le16(sb.data() + 56) == EXT_MAGIC) {
        info.type = FilesystemType::Ext;
        const uint32_t compat = Le32(sb.data() + 92);
        const uint32_t incompat = Le32(sb.data() + 96);
        if (incompat & (EXT_INCOMPAT_EXTENTS | EXT_INCOMPAT_64BIT | EXT_INCOMPAT_FLEX_BG)) {
            info.name = L"ext4";
        } else if (compat & EXT_COMPAT_HAS_JOURNAL) {
            info.name = L"ext3";
        } else {
            info.name = L"ext2";
        }
        return info;
    }

    info.name = L"Unknown";
    return info;
}

const wchar_t* FilesystemName(FilesystemType type) {
    switch (type) {
    case FilesystemType::NTFS:  return L"NTFS";
    case FilesystemType::FAT12: return L"FAT12";
    case FilesystemType::FAT16: return L"FAT16";
    case FilesystemType::FAT32: return L"FAT32";
    case FilesystemType::ExFAT: return L"exFAT";
    case FilesystemType::Ext:   return L"ext2/3/4";
    default:                    return L"Unknown";
    }
}

} // namespace KVC
