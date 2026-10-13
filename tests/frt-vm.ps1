#Requires -Version 7.0
# frt-vm.ps1 - the recovery matrix on the Hyper-V test guest: copies
# bin\FRT_x64.exe and the guest scripts over ssh, runs frt-scenario.ps1 once
# per file system and prints what was recovered byte for byte. The guest is
# left as it was found: the work folder goes at the end.
#
#   pwsh tests\frt-vm.ps1                       # all file systems
#   pwsh tests\frt-vm.ps1 -Fs NTFS,FAT32 -Build # rebuild FRT_x64 first
#   pwsh tests\frt-vm.ps1 -Exe other.exe        # another image, e.g. a baseline
param(
    [string[]]$Fs = @('FAT12', 'FAT16', 'FAT32', 'exFAT', 'NTFS'),
    [string]$Exe = (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\FRT_x64.exe'),
    [string]$Modes = 'mft',            # mft,usn,carving
    [switch]$Build,
    [switch]$Media,
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$Fs = @($Fs | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
. (Join-Path $PSScriptRoot 'testenv.ps1')
if ($Build) { & (Join-Path $PSScriptRoot 'build-x64.ps1') | Write-Host }

$ip = Get-TestVmIp
$ssh = Get-SshOptions
$dest = "$($TestEnv.User)@$ip"
$work = 'C:\frt'
function Guest([string]$Command) {
    $output = & ssh @ssh $dest $Command
    if ($LASTEXITCODE) { throw "Guest command failed ($LASTEXITCODE): $Command" }
    $output
}

Guest "powershell -NoProfile -Command `"New-Item -ItemType Directory -Force $work | Out-Null`"" | Out-Null
& scp @ssh -q $Exe "${dest}:$work/FRT_x64.exe"
& scp @ssh -q (Join-Path $PSScriptRoot 'guest\frt-scenario.ps1') "${dest}:$work/frt-scenario.ps1"
if ($LASTEXITCODE) { throw 'Copy to the guest failed.' }
if ($Media) {
    & (Join-Path $PSScriptRoot 'media-fixtures.ps1') | Out-Host
    & scp @ssh -q -r (Join-Path $PSScriptRoot 'fixtures') "${dest}:$work/fixtures"
    if ($LASTEXITCODE) { throw 'Media copy to the guest failed.' }
}

$all = @()
try {
    foreach ($f in $Fs) {
        Write-Host "== $f" -ForegroundColor Cyan
        $keepArg = if ($Keep) { ' -Keep' } else { '' }
        $lines = Guest "powershell -NoProfile -ExecutionPolicy Bypass -File $work\frt-scenario.ps1 -Fs $f -Frt $work\FRT_x64.exe -Work $work -Modes $Modes$keepArg"
        foreach ($l in $lines) {
            if ($l -like 'SUMMARY *') { $all += ($l.Substring(8) | ConvertFrom-Json) }
            elseif ($l -like 'OK *') { Write-Host "   $l" -ForegroundColor DarkGray }
            else { Write-Host "   $l" }
        }
    }
} finally {
    if (-not $Keep) { Guest "powershell -NoProfile -Command `"Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue`"" | Out-Null }
}

Write-Host ''
foreach ($s in $all) {
    $cases = ($s.byCase.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' '
    $honest = if ($s.PSObject.Properties.Name -contains 'honest') { if ($s.honest) { 'honest' } else { 'CLAIMS-OVERWRITTEN' } } else { '' }
    $lost = if ($s.lost) { "lost=$($s.lost)" } else { '' }
    Write-Host ("{0,-6} {1,3}/{2,-3} exit={3} {4,5}s csv={5} {6} {7} {8}" -f $s.fs, $s.recovered, $s.expected, $s.exit, $s.seconds, $s.csvRows, $honest, $lost, $cases)
}
$total = ($all | Measure-Object recovered -Sum).Sum; $expected = ($all | Measure-Object expected -Sum).Sum
Write-Host ("== {0}/{1} files recovered byte-exact" -f $total, $expected)
if ($all.Count -ne $Fs.Count -or @($all | Where-Object { $_.exit -ne 0 -or -not $_.honest -or $_.recovered -ne $_.expected }).Count) {
    throw 'Recovery matrix failed. Inspect the per-file results above.'
}
