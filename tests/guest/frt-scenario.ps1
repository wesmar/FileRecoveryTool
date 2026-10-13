#Requires -Version 5.1
# frt-scenario.ps1 - runs in the test guest as Administrator. Builds a fresh
# virtual disk with one file system, writes files with known contents, deletes
# them in the ways people lose files, lets FRT_x64 recover them and checks
# every recovered byte against the manifest. Leaves nothing behind.
#
#   frt-scenario.ps1 -Fs NTFS -Frt C:\frt\FRT_x64.exe -Work C:\frt
#
# Prints one line per expected file and a final JSON summary line.
param(
    [Parameter(Mandatory)][ValidateSet('FAT12', 'FAT16', 'FAT32', 'exFAT', 'NTFS')][string]$Fs,
    [Parameter(Mandatory)][string]$Frt,
    [string]$Work = 'C:\frt',
    [string]$Modes = 'mft',            # FRT scan modes: mft,usn,carving
    [switch]$Keep                      # keep the disk and outputs for a look afterwards
)
$ErrorActionPreference = 'Stop'
$sizeMB = @{ FAT12 = 15; FAT16 = 96; FAT32 = 512; exFAT = 256; NTFS = 256 }[$Fs]
$diskFs = @{ FAT12 = 'FAT'; FAT16 = 'FAT'; FAT32 = 'FAT32'; exFAT = 'EXFAT'; NTFS = 'NTFS' }[$Fs]
$unit   = @{ FAT12 = 'unit=4096'; FAT16 = 'unit=2048'; FAT32 = 'unit=4096'; exFAT = 'unit=32K'; NTFS = 'unit=4096' }[$Fs]
$vhd    = Join-Path $Work "vol-$Fs.vhdx"
$out    = Join-Path $Work "rec-$Fs"
$csv    = Join-Path $Work "found-$Fs.csv"
$log    = Join-Path $Work "frt-$Fs.log"
$small  = $Fs -eq 'FAT12'                 # 15 MB: the large files are scaled down

function DiskPart([string[]]$Lines) {
    $script = Join-Path $Work 'diskpart.txt'
    Set-Content -Path $script -Value $Lines -Encoding ASCII
    $r = & diskpart.exe /s $script 2>&1
    if ($LASTEXITCODE) { throw "diskpart failed: $($r -join ' | ')" }
    $r
}
function FreeLetter {
    $used = (Get-PSDrive -PSProvider FileSystem).Name
    foreach ($c in [char[]]'RSTUVWXYQP') { if ($used -notcontains [string]$c) { return [string]$c } }
    throw 'No free drive letter.'
}
function Content([int]$Seed, [long]$Length, [string]$Kind = 'bin') {
    $bytes = New-Object byte[] $Length
    if ($Length -gt 0) { [Random]::new($Seed).NextBytes($bytes) }
    switch ($Kind) {
        'jpg' { if ($Length -ge 16) { $hdr = [byte[]](0xFF,0xD8,0xFF,0xE0,0,16,0x4A,0x46,0x49,0x46,0); [Array]::Copy($hdr, $bytes, $hdr.Length)
                  for ($k = 11; $k -lt $Length - 2; $k++) { if ($bytes[$k] -eq 0xFF) { $bytes[$k] = 0xFE } }
                  $bytes[$Length - 2] = 0xFF; $bytes[$Length - 1] = 0xD9 } }
        'txt' { for ($k = 0; $k -lt $Length; $k++) { $bytes[$k] = [byte](0x41 + ($bytes[$k] % 26)) } }
    }
    , $bytes
}
$manifest = [Collections.Generic.List[object]]::new()
function Put([string]$Rel, [byte[]]$Bytes, [string]$Case) {
    $path = Join-Path $root $Rel
    [void][IO.Directory]::CreateDirectory((Split-Path $path))
    [IO.File]::WriteAllBytes($path, $Bytes)
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)).Replace('-', '')
    $manifest.Add([pscustomobject]@{ Case = $Case; Rel = $Rel; Name = Split-Path $Rel -Leaf; Size = $Bytes.Length; Sha = $sha })
}
function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }

New-Item -ItemType Directory -Force -Path $Work | Out-Null
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $out, $csv, $log
if (Test-Path $vhd) {                     # left by an interrupted run
    try { DiskPart @("select vdisk file=`"$vhd`"", "detach vdisk") | Out-Null } catch { }
    Remove-Item -Force $vhd
}
$letter = FreeLetter
$root = "${letter}:\"
DiskPart @("create vdisk file=`"$vhd`" maximum=$sizeMB type=expandable", "attach vdisk",
           "create partition primary", "format fs=$diskFs $unit quick label=FRT$Fs", "assign letter=$letter") | Out-Null
try {
    # ---------------------------------------------------------------- write
    $fixtures = Join-Path $Work 'fixtures'
    if (Test-Path $fixtures) {
        foreach ($fixture in Get-ChildItem -LiteralPath $fixtures -File) {
            Put $fixture.Name ([IO.File]::ReadAllBytes($fixture.FullName)) ("media-" + $fixture.Extension.TrimStart('.'))
        }
    }
    Put 'tiny.txt'        (Content 1 120 'txt')      'tiny'          # NTFS: resident in the MFT
    Put 'empty.dat'       (Content 2 0)              'empty'
    Put 'photo.jpg'       (Content 3 300000 'jpg')   'contiguous'
    Put 'archive.bin'     (Content 4 $(if ($small) { 1048576 } else { 6291456 })) 'large'
    Put 'Zażółć gęślą jaźń Ελληνικά 日本語.txt' (Content 5 5000 'txt') 'unicode-name'
    Put 'a very long file name that does not fit in eight dot three at all.pdf' (Content 6 70000) 'long-name'
    Put 'deep\level two\level three\nested.jpg' (Content 7 150000 'jpg') 'nested'
    Put 'gone\one.bin'    (Content 8 40000)          'deleted-dir'
    Put 'gone\two.jpg'    (Content 9 90000 'jpg')    'deleted-dir'
    Put 'gone\inner\three.txt' (Content 10 3000 'txt') 'deleted-dir'
    for ($n = 0; $n -lt 120; $n++) {        # a directory larger than one cluster
        Put ("many\file{0:D3}.txt" -f $n) (Content (100 + $n) (500 + 37 * $n) 'txt') 'many'
    }
    # two files written in turns: on every file system they end up interleaved
    $a = [IO.File]::Open((Join-Path $root 'frag-a.bin'), 'Create'); $b = [IO.File]::Open((Join-Path $root 'frag-keep.bin'), 'Create')
    $fa = [IO.MemoryStream]::new(); $fb = [IO.MemoryStream]::new()
    $chunk = if ($small) { 16384 } else { 65536 }
    for ($k = 0; $k -lt 24; $k++) {
        $ca = Content (1000 + $k) $chunk; $cb = Content (2000 + $k) $chunk
        $a.Write($ca, 0, $ca.Length); $a.Flush($true); $fa.Write($ca, 0, $ca.Length)
        $b.Write($cb, 0, $cb.Length); $b.Flush($true); $fb.Write($cb, 0, $cb.Length)
    }
    $a.Close(); $b.Close()
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($fa.ToArray())).Replace('-', '')
    $manifest.Add([pscustomobject]@{ Case = 'fragmented'; Rel = 'frag-a.bin'; Name = 'frag-a.bin'; Size = $fa.Length; Sha = $sha })

    if ($Fs -eq 'NTFS') {
        # sparse: 4 MB of nothing with data at both ends
        $p = Join-Path $root 'sparse.bin'
        $f = [IO.File]::Create($p); $f.Close(); & fsutil sparse setflag $p | Out-Null
        $head = Content 20 65536; $tail = Content 21 65536
        $f = [IO.File]::Open($p, 'Open', 'Write'); $f.Write($head, 0, $head.Length); $f.SetLength(4194304)
        $f.Position = 4194304 - $tail.Length; $f.Write($tail, 0, $tail.Length); $f.Close()
        & fsutil sparse setrange $p 65536 (4194304 - 131072) | Out-Null
        $full = New-Object byte[] 4194304; [Array]::Copy($head, 0, $full, 0, 65536); [Array]::Copy($tail, 0, $full, 4194304 - 65536, 65536)
        $manifest.Add([pscustomobject]@{ Case = 'sparse'; Rel = 'sparse.bin'; Name = 'sparse.bin'; Size = $full.Length
                       Sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($full)).Replace('-', '') })
        # compressed (LZNT1): text compresses, so the clusters hold compressed units
        Put 'compressed.txt' (Content 22 400000 'txt') 'compressed'
        & compact.exe /c (Join-Path $root 'compressed.txt') | Out-Null
        # an alternate data stream must not be taken for the file's data
        Put 'with-stream.bin' (Content 23 20000) 'ads'
        Set-Content -LiteralPath (Join-Path $root 'with-stream.bin') -Stream 'Zone.Identifier' -Value "[ZoneTransfer]`r`nZoneId=3"
    }

    # ---------------------------------------------------------------- reuse
    # all but a little free space taken: a file written after a delete must
    # land on the deleted file's clusters. The newer one comes back whole;
    # the older one may not be called whole.
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'olddir'))      # before the space goes:
    [void][IO.Directory]::CreateDirectory((Join-Path $root 'newdir'))      # no folder takes a freed cluster
    Write-VolumeCache -DriveLetter $letter
    $room = 320 * 1024
    $free = (Get-Volume -DriveLetter $letter).SizeRemaining
    if ($free -gt $room) {
        $fill = [IO.File]::Open((Join-Path $root 'filler.bin'), 'Create'); $fill.SetLength($free - $room); $fill.Close()
    }
    Put 'olddir\reused-old.bin' (Content 30 196608) 'reused-older'
    Write-VolumeCache -DriveLetter $letter
    Remove-Item -LiteralPath (Join-Path $root 'olddir\reused-old.bin') -Force
    Write-VolumeCache -DriveLetter $letter
    Put 'newdir\reused-new.bin' (Content 31 196608) 'reused-newer'
    Write-VolumeCache -DriveLetter $letter
    Remove-Item -LiteralPath (Join-Path $root 'newdir\reused-new.bin') -Force
    # ---------------------------------------------------------------- delete
    Write-VolumeCache -DriveLetter $letter
    $deleted = $manifest | Where-Object { $_.Case -ne 'reused-older' -and ($_.Case -ne 'many' -or ([int]($_.Name -replace '\D', '') % 2) -eq 0) }
    foreach ($m in $deleted) {
        if ($m.Case -eq 'deleted-dir' -or $m.Case -like 'reused-*') { continue }
        Remove-Item -LiteralPath (Join-Path $root $m.Rel) -Force
    }
    Remove-Item -LiteralPath (Join-Path $root 'gone') -Recurse -Force
    Write-VolumeCache -DriveLetter $letter

    if (($Modes -split ',') -notcontains 'mft') {
        # Random text and arbitrary bytes have no supported file signature.
        # The old synthetic JPG fixtures are random bytes between markers,
        # not images. Strict carving must reject them; metadata still tests them.
        $deleted = @($deleted | Where-Object { $_.Case -like 'media-*' })
    }

    # ---------------------------------------------------------------- recover
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $frtArgs = @('--cli', '--drive', $letter) + ($Modes -split ',' | ForEach-Object { '--' + $_.Trim() }) + @('--csv', $csv, '--recover', '--output', $out)
    $t0 = Get-Date
    $p = Start-Process -FilePath $Frt -ArgumentList $frtArgs -Wait -PassThru -WindowStyle Hidden `
                       -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    $seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)

    # ---------------------------------------------------------------- verify
    $recovered = @{}
    if (Test-Path $out) {
        Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object { $recovered[(Sha $_.FullName)] = $_.FullName }
    }
    $rows = if (Test-Path $csv) { @(Import-Csv -LiteralPath $csv -Encoding UTF8) } else { @() }
    $results = foreach ($m in $deleted) {
        $state = if ($recovered.ContainsKey($m.Sha)) { 'OK' } else { 'MISSING' }
        # not recovered, but reported as not whole: the data is gone and the tool says so
        if ($state -eq 'MISSING' -and $rows) {
            $row = $rows | Where-Object { $_.Name -eq $m.Name -or $_.Name -eq (Split-Path $m.Rel -Leaf) } | Select-Object -First 1
            if ($row -and $row.Quality -ne 'Full') { $state = 'LOST' }
        }
        [Console]::WriteLine(("{0,-8} {1,-14} {2,10} {3}" -f $state, $m.Case, $m.Size, $m.Rel))
        [pscustomobject]@{ Case = $m.Case; Rel = $m.Rel; State = $state }
    }
    $ok = @($results | Where-Object State -eq 'OK').Count
    # a file whose clusters a newer file took must not be offered as whole
    $honest = $true
    if (Test-Path $csv) {
        foreach ($row in (Import-Csv -LiteralPath $csv -Encoding UTF8 | Where-Object Name -eq 'reused-old.bin')) {
            if ($row.Quality -eq 'Full') { $honest = $false }
        }
    }
    [Console]::WriteLine(("{0,-8} {1,-14} {2,10} {3}" -f $(if ($honest) { 'OK' } else { 'CLAIMED' }), 'reused-older', 196608, 'olddir\reused-old.bin not offered as whole'))
    $summary = [ordered]@{
        fs = $Fs; exit = $p.ExitCode; seconds = $seconds; expected = @($results).Count; recovered = $ok; lost = @($results | Where-Object State -eq 'LOST').Count; honest = $honest
        byCase = [ordered]@{}
        csvRows = if (Test-Path $csv) { [math]::Max(0, (Get-Content $csv).Count - 1) } else { -1 }
    }
    foreach ($g in ($results | Group-Object Case)) {
        $summary.byCase[$g.Name] = "{0}/{1}" -f @($g.Group | Where-Object State -eq 'OK').Count, $g.Count
    }
    'SUMMARY ' + ($summary | ConvertTo-Json -Compress)
} finally {
    if (-not $Keep) {
        DiskPart @("select vdisk file=`"$vhd`"", "detach vdisk") | Out-Null
        Remove-Item -Force -ErrorAction SilentlyContinue $vhd, (Join-Path $Work 'diskpart.txt')
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $out, $csv, $log, "$log.err"
    }
}
