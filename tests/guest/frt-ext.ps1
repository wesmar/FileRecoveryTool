#Requires -Version 5.1
# frt-ext.ps1 - runs in the test guest as Administrator. The ext test disk
# (ext-image.sh) is attached and no ext driver mounts it: its partitions
# have no drive letter. FRT_x64 finds them with --list, recovers each one by
# device path and every recovered file is checked against the manifest the
# image script printed.
#
#   frt-ext.ps1 -Frt C:\frt\FRT_x64.exe -Manifest C:\frt\manifest.txt -Work C:\frt
param(
    [Parameter(Mandatory)][string]$Frt,
    [Parameter(Mandatory)][string]$Manifest,
    [string]$Work = 'C:\frt',
    [string]$Modes = 'mft'
)
$ErrorActionPreference = 'Stop'

function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
function RunFrt([string[]]$FrtArgs, [string]$Log) {
    $p = Start-Process -FilePath $Frt -ArgumentList $FrtArgs -Wait -PassThru -WindowStyle Hidden `
                       -RedirectStandardOutput $Log -RedirectStandardError "$Log.err"
    $p.ExitCode
}

$entries = Get-Content -LiteralPath $Manifest -Encoding UTF8 | Where-Object { $_ } | ForEach-Object {
    $f = $_ -split '\|'
    [pscustomobject]@{ Fs = $f[0]; Case = $f[1]; Rel = $f[2]; Size = [int64]$f[3]; Sha = $f[4].ToUpper() }
}

# the volumes: "\\.\HarddiskVolumeN  -  ext4  160 MB"
$listLog = Join-Path $Work 'list.log'
RunFrt @('--cli', '--list') $listLog | Out-Null
$volumes = @{}
foreach ($line in Get-Content -LiteralPath $listLog -Encoding UTF8) {
    if ($line -match '^(\\\\\.\\\S+)\s+(\S+)\s+(ext[234])\s') { $volumes[$Matches[3]] = $Matches[1] }
}

foreach ($fs in ($entries.Fs | Sort-Object -Unique)) {
    $expected = @($entries | Where-Object Fs -eq $fs)
    if (($Modes -split ',') -notcontains 'mft') {
        # Marker-wrapped random bytes are not JPEG images. Metadata recovery
        # still tests them, while carving expects only actual codec media.
        $expected = @($expected | Where-Object { $_.Case -like 'media-*' })
    }
    if (-not $volumes.ContainsKey($fs)) {
        [Console]::WriteLine("NOVOLUME $fs")
        'SUMMARY ' + (@{ fs = $fs; exit = -1; seconds = 0; expected = $expected.Count; recovered = 0; csvRows = -1; byCase = @{} } | ConvertTo-Json -Compress)
        continue
    }
    $out = Join-Path $Work "rec-$fs"
    $csv = Join-Path $Work "found-$fs.csv"
    $log = Join-Path $Work "frt-$fs.log"
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $out, $csv
    New-Item -ItemType Directory -Force -Path $out | Out-Null

    $t0 = Get-Date
    $frtArgs = @('--cli', '--volume', $volumes[$fs]) + ($Modes -split ',' | ForEach-Object { '--' + $_.Trim() }) +
               @('--csv', $csv, '--recover', '--output', $out)
    $exit = RunFrt $frtArgs $log
    $seconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)

    $recovered = @{}
    Get-ChildItem -LiteralPath $out -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { $recovered[(Sha $_.FullName)] = $_.FullName }
    $rows = if (Test-Path $csv) { @(Import-Csv -LiteralPath $csv -Encoding UTF8) } else { @() }
    $results = foreach ($m in $expected) {
        $state = if ($recovered.ContainsKey($m.Sha)) { 'OK' } else { 'MISSING' }
        # not recovered, but reported as not whole: the data is gone and the tool says so
        if ($state -eq 'MISSING' -and $rows) {
            $row = $rows | Where-Object { $_.Name -eq $m.Name -or $_.Name -eq (Split-Path $m.Rel -Leaf) } | Select-Object -First 1
            if ($row -and $row.Quality -ne 'Full') { $state = 'LOST' }
        }
        [Console]::WriteLine(("{0,-8} {1,-14} {2,10} {3}" -f $state, $m.Case, $m.Size, $m.Rel))
        [pscustomobject]@{ Case = $m.Case; State = $state }
    }
    # a file whose blocks a newer file took must not be offered as whole
    $honest = $true
    if (Test-Path $csv) {
        foreach ($row in (Import-Csv -LiteralPath $csv -Encoding UTF8 | Where-Object Name -eq 'reused-old.bin')) {
            if ($row.Quality -eq 'Full') { $honest = $false }
        }
    }
    [Console]::WriteLine(("{0,-8} {1,-14} {2,10} {3}" -f $(if ($honest) { 'OK' } else { 'CLAIMED' }), 'reused-older', 196608, 'olddir/reused-old.bin not offered as whole'))
    $summary = [ordered]@{
        fs = $fs; exit = $exit; seconds = $seconds; expected = $expected.Count; honest = $honest
        recovered = @($results | Where-Object State -eq 'OK').Count; lost = @($results | Where-Object State -eq 'LOST').Count
        csvRows = if (Test-Path $csv) { [math]::Max(0, (Get-Content $csv).Count - 1) } else { -1 }
        byCase = [ordered]@{}
    }
    foreach ($g in ($results | Group-Object Case)) {
        $summary.byCase[$g.Name] = "{0}/{1}" -f @($g.Group | Where-Object State -eq 'OK').Count, $g.Count
    }
    'SUMMARY ' + ($summary | ConvertTo-Json -Compress)
}
