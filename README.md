# KVC File Recovery Tool

![KVC File Recovery Tool](images/frt.gif)

**Professional-grade file recovery for Windows • Ultra-lightweight • Zero dependencies**

A high-performance forensic tool that recovers deleted files from NTFS, FAT32, and exFAT filesystems by reading raw disk sectors directly.

## 🚀 Features

- **Multi-Filesystem Support**: NTFS (MFT parsing, resident/non-resident attributes), FAT32 (LFN entries, cluster chains), exFAT (allocation bitmaps)
- **Three-Stage Recovery Engine**:
  1. **MFT Scan** - Instant recovery of recently deleted files via file record flags
  2. **USN Journal Analysis** - Recovers files from NTFS Change Journal history, even when MFT entries are overwritten
  3. **File Carving** - Deep sector scanning using file signatures (PNG, JPG, PDF, ZIP, Office docs, videos, archives)
- **Pure Native Code**: Win32 API + Modern C++ (RAII, smart pointers, templates) - no Qt, MFC, or .NET bloat
- **Multi-threaded Architecture**: Responsive UI with background scanning
- **Safety First**: Built-in validation prevents overwriting data on source drive

## 📋 Requirements

- Windows 10/11 (64-bit)
- Administrator privileges (required for direct disk access)
- Visual Studio 2026 (default slnx) for building from source

## 🔧 Building

1. Clone the repository
2. Open the solution in Visual Studio 2022+
3. Set configuration to **Release | x64**
4. Build solution

The resulting executable is standalone with no external dependencies.

## 💡 Usage

1. **Run as Administrator** (required for sector-level disk access)
2. **Select Drive** - Choose the logical drive to scan (C:, D:, etc.)
3. **Configure Scan**:
   - **MFT**: Fast, recommended for NTFS
   - **USN Journal**: Finds deletion history
   - **File Carving**: Deep scan for formatted/corrupted drives (slower)
4. **Filter** (optional): Enter folder paths or filenames to narrow results
5. **Scan**: Click "Start Scan" - results appear in real-time
6. **Recover**: Select files and click "Recover Selected"
   - ⚠️ **Important**: Always save to a different drive to avoid overwriting recoverable data

## 🏗️ Architecture

- **DiskForensicsCore**: Direct disk I/O via `CreateFile` with `\\.\PhysicalDrive` semantics
- **NTFSScanner**: Manual MFT record parsing, data run interpretation, path reconstruction
- **FileCarver**: Signature-based recovery with intelligent file size detection
- **RecoveryEngine**: Safe file restoration with source drive validation
- **GUI**: Pure Win32 API with modern common controls (ListView, ProgressBar)

## 📦 Supported File Types

**Images**: PNG, JPG, GIF, BMP  
**Documents**: PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX  
**Archives**: ZIP, RAR, 7z  
**Media**: MP4, AVI, MKV, MP3, WAV

## ⚠️ Important Notes

- Always recover to a **different physical drive** than the source
- Stop writing to the source drive immediately after file deletion for best results
- File carving success depends on whether the sectors have been overwritten

## 📄 License

MIT License - see LICENSE file for details

## 👨‍💻 Author

Marek Wesołowski - WESMAR  
https://kvc.pl

---

**Note**: This tool accesses raw disk sectors. Use with caution and always maintain backups.