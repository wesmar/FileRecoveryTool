# KVC File Recovery Tool

<div align="center">

![KVC File Recovery Tool](images/frt.gif)

**Native Windows recovery from file-system records, journals and raw bytes.**

**[Download FileRecoveryTool.7z](https://github.com/wesmar/FileRecoveryTool/releases/download/data-recovery/FileRecoveryTool.7z)** · **[Release notes](https://github.com/wesmar/FileRecoveryTool/releases/tag/data-recovery)** · **[kvc.pl](https://kvc.pl/repositories/filerecoverytool)**

**Archive password: `github.com`**

[![Windows](https://img.shields.io/badge/Windows-10%20%2F%2011-blue.svg)](https://github.com/wesmar/FileRecoveryTool/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

</div>

Recover deleted files from **NTFS, FAT12/16/32, exFAT and ext2/3/4**, or scan a whole disk or flat image without a usable file system. The native Win32 GUI and CLI use **the same scanning and recovery engine**. No installer, service or application framework is required; the static-runtime builds do not need a separate Visual C++ runtime.

The engine reads the source and writes recovered files to another disk. It uses surviving names, sizes and allocation maps where available, and checks file structure when carving. Results distinguish **Full, Partial, MetadataOnly and unavailable data**. A surviving file record is not a promise that its original bytes still exist.

## Changelog

**[13.10.2026]**

<details open>
<summary><strong>Engine expansion, whole-disk RAW scanning, document recovery and a native Windows 11 interface</strong></summary>

- **Recovery engine:** FAT12/16 support and ext2/3/4 parsing, ext3/4 journal recovery, and better handling of fragmented, sparse and compressed files. Deleted NTFS records whose allocation maps were cleared are reported as metadata only.
- **RAW sources:** scan whole physical disks, volumes or flat images without file-system metadata. Find signatures at arbitrary byte offsets, including buffer boundaries and the exact image end. GUI and CLI share this mode.
- **Images and video:** stricter JPEG structure checks, progressive JPEG handling, and more accurate GIF/MP4 boundaries. Recovered files exclude unrelated cluster padding.
- **Archives and documents:** improved ZIP boundaries, comments, descriptors, empty archives and local ZIP64 sizes; DOCX package recognition; 7z header CRC checks; PDF cross-reference checks and linked incremental updates. An incomplete later PDF update leaves the earlier revision explicitly Partial.
- **Interface:** Mica where supported, system light/dark and high-contrast colors, Per-Monitor V2 scaling, readable fonts and menus, responsive layouts, image selection and whole-disk sources.
- **Verification and maintenance:** repeatable Hyper-V tests, SHA-256 comparisons, measured physical fragmentation and a source tree organized by responsibility.

</details>

**[18.07.2026] — First public release**

NTFS, FAT32 and exFAT recovery, USN history, signature scanning, GUI/CLI operation and four x64/x86 binary variants.

## Recovery methods

| Method | What it uses | What it can recover |
| --- | --- | --- |
| **File-system records** | NTFS MFT, FAT/exFAT directory entries, ext directories and inodes | Original names, paths and file contents when the required metadata and bytes survive |
| **Deletion history** | NTFS USN journal; ext3/4 journal copies | Deletion events and names; ext journal copies may also preserve lost inode and block maps |
| **Free-space carving** | Supported signatures and file structure in unallocated space | Recognizable files whose directory records are lost |
| **RAW scanning** | All source bytes, without an allocation map | Recognizable files from whole disks, volumes and flat images, including live files |

**USN records alone do not reconstruct file contents.** If the matching MFT record is gone, its history is metadata only. Carving normally assumes contiguous data; complete surviving ext block maps can let it follow fragments and skip metadata blocks. RAW does not discover missing fragment maps.

Ext volumes are read directly by the engine; an installed ext driver is not required. Metadata parsing covers ext2/3/4; the recorded ext recovery scenarios exercise ext3 and ext4.

### File types

Metadata recovery is not limited to the extensions below. These are the formats exercised by the current signature-recovery tests:

| Family | Tested formats |
| --- | --- |
| Images | JPEG, PNG, GIF, BMP |
| Video and audio | MP4, AVI, WAV |
| Archives | ZIP, 7z |
| Documents | DOCX, PDF, including encrypted and incrementally updated PDF fixtures |

ZIP-based Office extensions are inferred from package member names. This does not validate their XML contents. The presence of a format's signature in the source code does not by itself establish complete recovery support.

## Download and requirements

Download the [password-protected archive](https://github.com/wesmar/FileRecoveryTool/releases/download/data-recovery/FileRecoveryTool.7z), extract it with **`github.com`**, and choose a binary:

| Binary | Architecture | Runtime |
| --- | --- | --- |
| **`FRT_x64.exe`** | x64 | Static runtime; recommended for Windows 10/11 x64 |
| `FRT_x86.exe` | x86 | Static runtime; 32-bit build |
| `FRT_x64_minSize.exe` | x64 | Dynamic runtime; matching Visual C++ Redistributable required |
| `FRT_x86_minSize.exe` | x86 | Dynamic runtime; matching Visual C++ Redistributable required |

Administrator rights are required for direct disk and volume access. Development validation is performed on **Windows 11 x64**. The application uses native Windows APIs; Mica depends on OS support and falls back to an opaque surface.

> **Preserve the source.** Stop writing to it after deletion, and save recovered files and reports to another physical disk. On SSD/NVMe, data already discarded through TRIM may no longer be readable.

## GUI

1. Run the application as administrator.
2. Select a volume, a whole disk, or **Open image** for a flat image.
3. Choose the discovery methods and optional name/path filters. Whole-disk and image sources enable **RAW**, which is separate from the file-system methods.
4. Start scanning and inspect names, sizes and reported recovery quality.
5. Select rows with Ctrl/Shift or Ctrl+A, then **Recover selected** to another physical disk.

Scanning runs in the background and results arrive in batches. The interface follows Windows light/dark and high-contrast settings. Fonts and controls scale with DPI, including 150% scaling.

## CLI

Run from an elevated terminal. `--mft` selects the source file system's own records, including FAT/exFAT and ext; it is not restricted to NTFS. Use `--usn` for NTFS history, `--carving` for free-space signatures, or `--all` to combine those methods. `--raw` is a separate mode.

```powershell
# List available volumes.
.\FRT_x64.exe --cli --list

# Recover from file-system records.
.\FRT_x64.exe --cli --drive E --mft --recover --output D:\Recovered

# Combine metadata, history and free-space signatures; save a report.
.\FRT_x64.exe --cli --drive E --all --csv D:\results.csv --recover --output D:\Recovered

# Scan a volume that has no drive letter, including an ext volume.
.\FRT_x64.exe --cli --volume \\.\HarddiskVolume7 --mft --recover --output D:\Recovered

# Scan a flat byte-for-byte image without file-system metadata.
.\FRT_x64.exe --cli --image D:\images\source.img --raw --diagnostics --recover --output E:\Recovered

# Scan a whole physical disk. Verify the device number before use.
.\FRT_x64.exe --cli --volume \\.\PhysicalDrive2 --raw --csv E:\raw.csv

.\FRT_x64.exe --help
```

VHD/VHDX containers must be mounted first and scanned through their disk or volume device. `--image` expects a flat image. The program checks the physical source disk against recovery/report destinations; another partition of the same disk is rejected. For flat images, overwriting the input, including through a hard link, is rejected.

## Validation

The tests create and delete their own fixtures on isolated disks in a Windows 11 Hyper-V guest. They recover through the production CLI, compare **SHA-256**, and check output counts and quality. Fragmentation is measured from the actual physical extent map before deletion.

Selected results recorded on **13.10.2026**:

| Coverage | Result |
| --- | --- |
| FAT12/16/32, exFAT, NTFS and ext3/4 metadata recovery | **563/563** byte-exact |
| Codec-generated images, MP4/AVI/WAV and ZIP carving | **56/56** byte-exact |
| NTFS/exFAT archive and document recovery, including eight-extent layouts | **42/42** byte-exact |
| RAW codec media from a flat image and a whole physical test disk | **8/8 + 8/8** byte-exact |
| Mixed RAW DOCX/PDF/ZIP/7z image | **13/13** byte-exact |
| Measured NTFS/exFAT fragmentation, 1–128 extents | **36/36** byte-exact |
| Measured exFAT fragmentation, 256/1024 extents | **4/4** byte-exact |
| File-boundary parser regressions | **50/50** passed |
| GUI font and layout scenarios across five DPI settings | **15/15** passed |

Additional cases check corrupted/truncated archives and PDFs, source immutability, RAW destination checks, menu text in three palettes, and truthful metadata-only results after NTFS loses extension-record maps.

These are controlled recovery tests, **not a physical NVMe/TRIM benchmark or a success rate for arbitrary damaged disks**. DPI changes are simulated; they do not replace physical multi-monitor testing. See [test methods, results and limitations](tests/README.md) for the detailed matrices.

## Current limits

- **Lost bytes:** overwritten or discarded/TRIMmed contents cannot be reconstructed by these methods.
- **Fragmentation:** without a surviving map, signature recovery cannot generally assemble arbitrary fragmented files. RAW currently assumes contiguous data and limits each candidate to 2 GiB.
- **NTFS:** deletion can clear maps held in extension records. Those files are metadata only; allocation-map recovery from `$LogFile` is not implemented.
- **Archives:** full ZIP64 central directories/end records and split archives are unsupported. 7z header CRC checks do not decode or validate every compressed payload.
- **PDF:** cross-reference streams require a direct length; their entries and the full document are not decoded. Complex or damaged PDFs need broader coverage.
- **Damaged file systems:** quick-format NTFS, damaged boot records and MFT/FAT fallback paths still need dedicated recovery tests.

**Full describes the available recovery map and boundaries, not a complete content-decoder verdict.** The tests independently open/decode selected recovered files, but scanning does not perform that validation for every format.

## Build and source layout

Use Visual Studio C++ tools with the platform toolset named by the project, a Windows SDK and PowerShell 7. The build script locates usable x64/x86 compilers, MSBuild and Windows SDK resource compilers from files on disk.

```powershell
pwsh -File build.ps1 -Rebuild
```

This builds all four release variants into `bin/`. `build_all.bat` calls the same script. For only the tested x64 static-runtime build, use `pwsh -File tests/build-x64.ps1 -Rebuild`. The solution is `kvc_recovery.slnx`.

`src/` separates entry points, GUI, scan orchestration, disk I/O, file-system parsers, carving, recovery and support code. Visual Studio filters mirror the directory structure. Both interfaces call `DiskForensicsCore` and `RecoveryEngine`; the CLI is also the route used by the recovery test harness.

## License and author

[MIT License](LICENSE.md).

**Marek Wesołowski (WESMAR)**<br>
[GitHub](https://github.com/wesmar) · [kvc.pl](https://kvc.pl) · [marek@wesolowski.eu.org](mailto:marek@wesolowski.eu.org)
