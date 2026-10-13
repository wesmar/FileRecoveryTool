# Recovery tests

These tests use isolated VHDX images, not the VM system disk. They create and delete their own fixture files, recover them through the production CLI, and compare SHA-256 hashes. The VM must be reachable through SSH as an administrator.

Machine settings belong in the ignored `tests/testenv.local.psd1`:

```powershell
@{ Vm = 'Win11'; User = 'Administrator'; SshKey = 'C:\path\to\test-key' }
```

## Parser and GUI regressions

```powershell
pwsh -File tests/build-x64.ps1 -TestCarver
bin/carver-tests.exe
pwsh -File tests/gui-vm.ps1 -Build
```

The carver regressions exercise ZIP comments/descriptors/empty archives/local ZIP64 sizes, adjacent archives, embedded false markers, corrupt directory fields, PDF cross-reference boundaries and incremental revisions, 7z header CRCs, GIF block boundaries, MP4 padding/overlong boxes, JPEG frame/scan validation and progressive marker transitions, cancellation, integer overflow, and fragment maps which skip metadata or go backwards on disk. They use raw temporary images and compare the recovered bytes.

GUI tests use the production GUI sources in the logged-in VM session. A brief inactive window obtains native menu rectangles, then the test window is hidden. Pixel checks verify visible opaque menu text in light, dark and high-contrast palettes, including selected and disabled popup entries. No system theme settings are changed. They also check Per-Monitor V2 awareness, font sizes, control bounds at 96/120/144/192/240 DPI, layouts of 640x480, 760x600 and 1100x680 logical pixels, incremental result batches, and worker progress without synchronous UI calls. DPI changes are simulated; physical monitor moves and visual theme appearance still require interactive review. SSH session 0 downgrades the awareness context, so the runner uses a temporary interactive scheduled task and removes it afterwards.

## Archives, Office packages and PDFs

```powershell
pwsh -File tests/word-fixtures.ps1
python tests/document-fixtures.py
pwsh -File tests/documents-vm.ps1
```

The fixture builder uses an already installed Word to create a DOCX with text,
a table and an embedded image, plus its exported PDF. Generate the codec
fixtures first. Create `tests/fixtures/documents/sample.7z` from the DOCX using
an already installed 7-Zip, then run the Python generator. The Python script
requires an existing pypdf installation; none of these scripts install tools.
Generated files and results stay in ignored directories.

The 13 files cover stored/deflated/BZIP2/LZMA ZIPs, a ZIP data descriptor, an
empty commented ZIP, local ZIP64 sizes with an ordinary directory, DOCX, 7z,
classic/incremental/encrypted PDFs and Word's PDF export. Python independently
checks ZIP payload CRCs, Office XML/text and PDF page/text extraction. 7-Zip
tests the recovered 7z payload. A native Windows PDF render was also inspected
for the Word export. Decoder checks supplement byte-exact recovery checks;
the production carver is not a complete decoder.

The guest runs ten RAW cases: a mixed unaligned source, directly adjacent PDFs,
an incomplete PDF update returning an explicitly Partial earlier revision,
and seven rejected ZIP/7z/PDF corruption/truncation cases. It checks extensions,
quality, output counts, source immutability and SHA-256. Metadata recovery then
tests all 13 files on each of NTFS and exFAT, plus DOCX/PDF/ZIP/7z with exactly
eight measured extents in forward and reverse order: 42 recoveries in total.
Fragmentation is proven with retrieval pointers and checked against the
requested map before deletion. RAW itself still assumes contiguous bytes.

Each run creates its own 128 MiB VHDX volumes, flushes file contents and metadata
**before** deletion, and saves logs, CSV, hashes and extent maps under
`tests/document-results/`. Flushing only after deletion was an error in the
initial generator: cached CopyFile data could disappear without having been
persisted. Controlled VHD and VHDX probes recovered the file byte-exact after
adding the pre-deletion flush. The initial zero-filled outputs are not evidence
of physical TRIM behavior. Failure disks are detached and retained in the guest.

## RAW sources

```powershell
pwsh -File tests/media-fixtures.ps1
pwsh -File tests/raw-vm.ps1
```

The RAW matrix uses eight real codec-generated formats (JPEG/PNG/GIF/BMP,
ZIP/MP4/AVI/WAV). It places files at unaligned byte offsets, an MP4 header
across the production 64 MiB batch boundary, and a WAV at the exact image EOF.
The same byte stream is written into the unallocated range of a separate
160 MiB VHDX with two small NTFS partitions, then recovered through
`PhysicalDriveN`. The writer obtains the disk from that exact VHDX and checks
its size, sector size and partition ranges before writing. SHA-256 must match
for both source forms. The flat source's hash must remain unchanged.

Nine negative CLI cases cover unknown metadata, incompatible modes, missing
sources, zeroed bytes, VHDX containers, direct/hard-link image overwrite,
whole-source disk writes, and writes onto a second partition of the same disk.
Parser regressions additionally check a short read and cancellation. Zeroed
fixtures simulate already-lost bytes; they are not physical TRIM tests.

Each run saves logs, CSV and media offsets/hashes in a separate ignored
`tests/raw-results/` directory. Failures retain the guest work folder and a
detached test VHDX. The initial physical-disk test found isolated JPEG
start/end markers inside NTFS metadata; they are now rejected, with a specific
parser regression. GUI smoke tests also run an unaligned RAW source through
the production GUI scan worker and recover it with the shared engine.

## FAT, exFAT and NTFS

```powershell
pwsh -File tests/build-x64.ps1 -Rebuild
pwsh -File tests/frt-vm.ps1 -Media -Modes mft
pwsh -File tests/frt-vm.ps1 -Media -Modes carving
```

The default matrix covers FAT12/16/32, exFAT and NTFS. Metadata tests include empty/resident files, names in several scripts, deleted directories, fragmentation, cluster reuse, and NTFS sparse/compressed files and alternate streams. Carving tests expect actual codec media. Marker-wrapped random JPG fixtures are metadata tests, not valid images; strict carving now rejects them. Earlier 55/55 and 22/22 carving totals included these fixtures. The current corresponding totals are 40/40 and 16/16 real media files.

`-Media` generates real JPEG, PNG, GIF and BMP images with Windows codecs, ZIP archives with .NET, and MP4/AVI/WAV samples with an already installed FFmpeg. It installs nothing and downloads no samples. Generated fixtures stay in the ignored `tests/fixtures/` directory. `-Fs NTFS,FAT32` restricts a matrix. `-Keep` retains the guest disk and outputs for diagnosing a failure; rerunning the same file system detaches and replaces that test disk.

## Measured NTFS/exFAT fragmentation

```powershell
pwsh -File tests/fragmentation-vm.ps1
pwsh -File tests/fragmentation-vm.ps1 -Fs exFAT -ClusterSizes 4096 -Counts '256,1024'
pwsh -File tests/fragmentation-vm.ps1 -Fs NTFS -ClusterSizes 4096 -Counts '256,1024' -ExpectedOutcome MetadataOnly
```

The default matrix creates files of 8 MiB plus 37 bytes with exactly 1, 2, 8,
32 and 128 physical extents, at 4 KiB and 32 KiB allocation units, in forward
and reverse physical order. It uses the Windows defragmentation API on its own
fresh VHDX, then checks the actual VCN/LCN map with
[FSCTL_GET_RETRIEVAL_POINTERS](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_retrieval_pointers).
It verifies the bytes again after moving, deletes the file, and checks recovery
against SHA-256 and the reported quality. Write interleaving alone is not proof
of fragmentation.

The generator selects destinations in one bitmap sweep, using separate free
runs when needed. Every invocation keeps its layout maps, original/recovered
hashes and logs in a separate ignored `tests/fragmentation-results/` subfolder.
Failures retain the guest work folder and detached VHDX for investigation;
`-Keep` also leaves the disk attached. The runner never replaces an existing
work folder automatically.

For the NTFS 256/1024-extent fixtures, Windows cleared the extension-record
allocation metadata during deletion. MFT scanning could no longer reconstruct
the file. `-ExpectedOutcome MetadataOnly` explicitly tests that this is reported
as metadata only, with no empty output file and a failure exit code for recovery.
It is not counted as successful file recovery. A separate full-recovery run
still fails those cases. Full recovery needs another source of the lost map,
such as NTFS `$LogFile` history, which is not implemented. Fragment count alone
does not determine metadata retention for every possible NTFS layout.

## ext

```powershell
pwsh -File tests/ext-vm.ps1 -Media -Modes mft
pwsh -File tests/ext-vm.ps1 -Media -Modes carving
pwsh -File tests/ext-vm.ps1 -Media -Modes mft -Driver
```

WSL builds the separate ext test VHDX using Linux file operations. The image contains ext3/ext4 recovery scenarios and an ext2 partition; ext2 does not yet have its own recovery scenario. The disk selector requires exactly one matching disk before formatting anything. The raw mode temporarily stops the guest ext driver and restores its initial state. `-Driver` tests with the existing guest `ext4.sys` loaded and restores its initial state; it does not replace or sign the driver. Loading failures are test failures, not successful interoperability results.

## Recorded limitations

One FAT32 AVI carving case was absent in a five-system run and passed in a targeted rerun. The causes remain unproven; retain the image on recurrence and inspect the allocation/layout and recovered bytes before changing expectations.

The matrices do not yet cover quick-format NTFS, damaged boot records, `$MFTMirr` recovery, damaged FAT copies, full ZIP64 directories/end records or arbitrary fragmented media without a surviving map.

## Validation on 2026-10-13

| Test | Byte-exact recoveries / passes |
| --- | --- |
| FAT12/16/32, exFAT, NTFS metadata with codec media | 403/403 |
| ext3/ext4 metadata with codec media, raw volumes | 160/160 |
| FAT12/16/32, exFAT, NTFS carving with codec media | 55/55 |
| ext3/ext4 carving with codec media and recovered block maps | 22/22 |
| Parser regressions on Win11 | 22/22 |
| GUI bounds/font scenarios in the interactive Win11 session | 15/15 |

The GUI also passed incremental-result and asynchronous-progress checks. The
installed guest ext4.sys was unsigned and Windows rejected loading it with
error 577. Driver-active interoperability was therefore not verified.

### Measured fragmentation follow-up

| Test | Result |
| --- | --- |
| NTFS/exFAT, 4/32 KiB clusters, 1/2/8/32/128 measured extents, forward/reverse | 36/36 recovered byte-exact |
| exFAT, 4 KiB clusters, 256/1024 measured extents, forward/reverse | 4/4 recovered byte-exact |
| NTFS cleared extension maps, 256/1024 extents | 4/4 correctly reported MetadataOnly; 0 files recovered |
| Ordinary NTFS/exFAT media/metadata regression after the fix | 163/163 recovered byte-exact |

The previous binary reported the four cleared-map cases as Full and saved
zero-byte files. The fixed scanner also checks extension and base-record
sequence numbers before accepting an attribute-list reference.

### Source organization and RAW follow-up

| Test | Result |
| --- | --- |
| FAT12/16/32, exFAT, NTFS metadata after reorganization/RAW changes | 403/403 byte-exact |
| ext3/ext4 metadata after reorganization/RAW changes | 160/160 byte-exact |
| FAT12/16/32, exFAT, NTFS carving with actual codec media | 40/40 byte-exact |
| ext3/ext4 carving with actual codec media and journal maps | 16/16 byte-exact |
| RAW exact-length flat image | 8/8 byte-exact |
| RAW whole physical device backed by isolated VHDX | 8/8 byte-exact |
| RAW negative CLI cases | 9/9 |
| Parser regressions | 35/35 |
| Measured NTFS/exFAT fragmentation after reorganization | 36/36 byte-exact |
| GUI DPI/font/bounds | 15/15, plus RAW mode exclusivity and scan-worker/shared-engine recovery |

The whole-device matrix verifies physical destination checks across two
partitions. The original false-positive JPEG test disk is retained separately
as diagnostic evidence. This is not a benchmark of an actual NVMe SSD, a
physical TRIM test, or recovery of arbitrary fragmented media.

### Document/archive and menu follow-up

| Test | Result |
| --- | --- |
| Parser regressions, including archive/PDF boundaries | 50/50 |
| Mixed RAW archive/document image | 13/13 byte-exact, including DOCX extension |
| Directly adjacent RAW PDFs | 2/2 byte-exact |
| Incomplete incremental PDF | Earlier revision byte-exact, correctly Partial |
| Rejected corrupt/truncated archive/PDF inputs | 7/7, no output files |
| NTFS/exFAT archive/document metadata | 42/42 byte-exact, including 16 eight-extent cases |
| Menu text and alpha | Light/dark/high-contrast palettes, bar and popup states passed |
| GUI DPI/font/bounds | 15/15, plus result batching/progress and shared-engine RAW recovery |
| Existing codec-media carving on five file systems | 40/40 byte-exact, including MP4 |
| Existing RAW flat/physical media and negative CLI cases | 8/8 + 8/8 byte-exact; 9/9 negative cases |

PDF xref-stream entry semantics, indirect stream lengths, arbitrary damaged
documents, full ZIP64 and fragmented RAW archives remain outside this coverage.
