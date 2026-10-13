#Requires -Version 5.1
# End-to-end RAW tests through the production CLI on an exact-length flat image.
param([Parameter(Mandatory)][string]$Frt, [Parameter(Mandatory)][string]$Fixtures,
    [string]$Work = 'C:\frt-raw-qa', [switch]$Keep)
$ErrorActionPreference = 'Stop'
$workFull = [IO.Path]::GetFullPath($Work).TrimEnd('\')
if ($workFull -ne 'C:\frt-raw-qa') { throw 'The isolated work folder must be C:\frt-raw-qa.' }
$results = [Collections.Generic.List[object]]::new()
$image = Join-Path $workFull 'unaligned.img'
if (Test-Path -LiteralPath $image) { throw 'An earlier RAW image exists. Preserve or remove it deliberately.' }
function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function SaveResults {
    @{ cases=$results; media=$expected; imageBytes=(Get-Item $image).Length; imageSha256=$originalHash;
        flatMediaVerified=$flatVerified; physicalMediaVerified=$physicalPassed } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$workFull\raw-results.json" -Encoding UTF8
}
function Run([string]$Case, [string[]]$Arguments, [int]$ExpectedExit) {
    $log = Join-Path $workFull "$Case.log"
    $process = Start-Process -FilePath $Frt -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    if ($process.ExitCode -ne $ExpectedExit) { throw "$Case exit=$($process.ExitCode), expected=$ExpectedExit; see $log" }
    $results.Add([pscustomobject]@{case=$Case; exit=$process.ExitCode; expectedExit=$ExpectedExit; exitMatched=$true})
    SaveResults
}
$expected = @()
$file = [IO.File]::Open($image, 'CreateNew')
try {
    $position = 57L
    foreach ($extension in 'jpg','png','gif','bmp','zip','mp4','avi','wav') {
        if ($extension -eq 'mp4') { $position = 64L * 1024 * 1024 - 5 }
        $path = Join-Path $Fixtures "codec.$extension"
        $bytes = [IO.File]::ReadAllBytes($path)
        $file.Position = $position
        $file.Write($bytes, 0, $bytes.Length)
        $expected += [pscustomobject]@{extension=$extension; offset=$position; bytes=$bytes.Length; sha256=(Sha $path)}
        $position += $bytes.Length + 29
    }
    # The last WAV ends at the exact EOF, not at a sector/cluster boundary.
    $file.SetLength($position - 29)
} finally { $file.Dispose() }
$originalHash = Sha $image
$flatVerified = $false
$physicalPassed = $false
SaveResults
$timer = [Diagnostics.Stopwatch]::StartNew()
Run 'raw-media' @('--cli','--image',$image,'--raw','--diagnostics','--csv',"$workFull\raw.csv",'--recover','--output',"$workFull\recovered") 0
$timer.Stop()
$outputs = @(Get-ChildItem -LiteralPath "$workFull\recovered" -Recurse -File)
$rows = @(Import-Csv -LiteralPath "$workFull\raw.csv" -Encoding UTF8)
if ($outputs.Count -ne $expected.Count -or $rows.Count -ne $expected.Count) { throw 'RAW candidate/output count mismatch' }
foreach ($sample in $expected) {
    $match = @($outputs | Where-Object { (Sha $_.FullName) -eq $sample.sha256 })
    if ($match.Count -ne 1) { throw "RAW byte mismatch or missing sample: $($sample.extension)" }
}
if (@($rows | Where-Object { $_.Quality -ne 'Full' -or $_.FileSystem -ne 'RAW' }).Count) { throw 'Unexpected RAW quality or source label' }
$flatVerified = $true
SaveResults
$diagnostics = Get-Content -LiteralPath "$workFull\raw-media.log" -Raw
if ($diagnostics -notmatch 'Boundaries parsed:\s+8' -or $diagnostics -notmatch 'Read-error batches:\s+0') { throw 'RAW diagnostics do not reflect the real scan' }
Run 'metadata-refuses-unknown' @('--cli','--image',$image,'--mft') 3
Run 'mixed-modes-rejected' @('--cli','--image',$image,'--raw','--carving') 2
Run 'missing-source' @('--cli','--image',"$workFull\missing.img",'--raw') 3
Run 'csv-cannot-overwrite-image' @('--cli','--image',$image,'--raw','--csv',$image) 4
$link = Join-Path $workFull 'source-alias.img'
New-Item -ItemType HardLink -Path $link -Target $image | Out-Null
Run 'csv-cannot-overwrite-image-alias' @('--cli','--image',$image,'--raw','--csv',$link) 4
if ((Sha $image) -ne $originalHash) { throw 'RAW test modified its source image' }
$discarded = Join-Path $workFull 'discarded.img'
[IO.File]::WriteAllBytes($discarded, (New-Object byte[] (1024 * 1024 + 31)))
Run 'discarded-zero-data' @('--cli','--image',$discarded,'--raw','--csv',"$workFull\discarded.csv") 1
if (@(Import-Csv -LiteralPath "$workFull\discarded.csv").Count) { throw 'Zeroed data produced invented files' }
$container = Join-Path $workFull 'container.vhdx'
$bytes = New-Object byte[] 4096
[Text.Encoding]::ASCII.GetBytes('vhdxfile').CopyTo($bytes, 0)
[IO.File]::WriteAllBytes($container, $bytes)
Run 'vhdx-container-rejected' @('--cli','--image',$container,'--raw') 3
$vhd = Join-Path $workFull 'raw-source.vhdx'
if (Test-Path -LiteralPath $vhd) { throw 'An earlier physical RAW test disk exists' }
$letters = @((Get-PSDrive -PSProvider FileSystem).Name)
$free = @([char[]]'RSTUVWXYQP' | ForEach-Object { [string]$_ } | Where-Object { $_ -notin $letters })
if ($free.Count -lt 2) { throw 'Two free letters are required for the isolated RAW test disk' }
$diskpartFile = Join-Path $workFull 'raw-diskpart.txt'
function DiskPart([string[]]$Lines) {
    Set-Content -LiteralPath $diskpartFile -Value $Lines -Encoding ASCII
    $output = & diskpart.exe /s $diskpartFile
    if ($LASTEXITCODE) { throw "diskpart failed: $($output -join ' | ')" }
}
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class RawFixtureWriter {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFilePointerEx(SafeFileHandle handle, long offset, out long position, uint method);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool WriteFile(SafeFileHandle handle, byte[] data, uint count, out uint written, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FlushFileBuffers(SafeFileHandle handle);
    public static void Write(string disk, string image, long offset) {
        using (var handle = CreateFile(disk, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero))
        using (var input = File.OpenRead(image)) {
            long position;
            if (handle.IsInvalid || !SetFilePointerEx(handle, offset, out position, 0) || position != offset) throw new IOException("Test disk open/seek failed");
            byte[] buffer = new byte[131072];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) != 0) {
                int aligned = (read + 511) / 512 * 512;
                Array.Clear(buffer, read, aligned - read);
                uint written;
                if (!WriteFile(handle, buffer, (uint)aligned, out written, IntPtr.Zero) || written != aligned) throw new IOException("Test disk write failed");
            }
            if (!FlushFileBuffers(handle)) throw new IOException("Test disk flush failed");
        }
    }
}
'@
$attached = $false
$physicalPassed = $false
try {
    DiskPart @("create vdisk file=`"$vhd`" maximum=160 type=expandable", 'attach vdisk',
        'create partition primary size=16', 'format fs=ntfs unit=4096 quick label=FRTRawA', "assign letter=$($free[0])",
        'create partition primary size=16', 'format fs=ntfs unit=4096 quick label=FRTRawB', "assign letter=$($free[1])")
    $attached = $true
    $disks = @(Get-DiskImage -ImagePath $vhd | Get-Disk)
    if ($disks.Count -ne 1 -or $disks[0].Size -ne 160L * 1024 * 1024 -or $disks[0].LogicalSectorSize -ne 512) { throw 'Isolated test disk identity/size/sector mismatch' }
    $disk = $disks[0]
    $offset = 48L * 1024 * 1024
    $partitions = @(Get-Partition -DiskNumber $disk.Number)
    if (@($partitions | Where-Object { $_.Offset + $_.Size -gt $offset }).Count -or $offset + (Get-Item $image).Length -gt $disk.Size) { throw 'Fixture range overlaps a test partition or disk end' }
    $device = "\\.\PhysicalDrive$($disk.Number)"
    [RawFixtureWriter]::Write($device, $image, $offset)
    Run 'physical-raw-media' @('--cli','--volume',$device,'--raw','--diagnostics','--csv',"$workFull\physical.csv",'--recover','--output',"$workFull\physical-recovered") 0
    $physicalOutputs = @(Get-ChildItem -LiteralPath "$workFull\physical-recovered" -Recurse -File)
    if ($physicalOutputs.Count -ne $expected.Count) { throw 'Physical RAW output count mismatch' }
    foreach ($sample in $expected) {
        if (@($physicalOutputs | Where-Object { (Sha $_.FullName) -eq $sample.sha256 }).Count -ne 1) { throw "Physical RAW mismatch: $($sample.extension)" }
    }
    Run 'physical-source-destination-blocked' @('--cli','--volume',$device,'--raw','--csv',"$($free[0]):\blocked.csv") 4
    Run 'same-disk-second-partition-blocked' @('--cli','--drive',$free[0],'--mft','--csv',"$($free[1]):\blocked.csv") 4
    if ((Test-Path "$($free[0]):\blocked.csv") -or (Test-Path "$($free[1]):\blocked.csv")) { throw 'Report written to source disk' }
    $physicalPassed = $true
} finally {
    if ($attached) { DiskPart @("select vdisk file=`"$vhd`"", 'detach vdisk') }
    if ($physicalPassed -and -not $Keep) { Remove-Item -LiteralPath $vhd -Force }
}
@{ cases=$results; media=$expected; imageBytes=(Get-Item $image).Length; imageSha256=$originalHash; milliseconds=$timer.ElapsedMilliseconds; flatMediaVerified=$flatVerified; physicalMediaVerified=$physicalPassed; physicalBaseOffset=$offset; physicalDevice=$device } |
    ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$workFull\raw-results.json" -Encoding UTF8
Write-Output "RAW flat/physical media: 8/8 + 8/8 byte-exact; negative cases: $($results.Count - 2); $($timer.ElapsedMilliseconds)ms flat scan"
Write-Output 'SUMMARY raw=8/8 physical=8/8 source=unchanged'
