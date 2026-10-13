#Requires -Version 7.0
param([string[]]$Fs=@('NTFS','exFAT'), [int[]]$ClusterSizes=@(4096,32768), [string]$Counts='1,2,8,32,128',
    [ValidateSet('Full','MetadataOnly')][string]$ExpectedOutcome='Full', [switch]$Keep)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'testenv.ps1')
$ip = Get-TestVmIp; $ssh = Get-SshOptions; $dest = "$($TestEnv.User)@$ip"
$work = 'C:\frt-fragmentation'
$runName = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$resultsDir = Join-Path (Join-Path $PSScriptRoot 'fragmentation-results') $runName
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
function Guest([string]$Command) {
    $output = & ssh @ssh $dest $Command
    if ($LASTEXITCODE) { throw "Guest command failed ($LASTEXITCODE): $Command`n$($output -join "`n")" }
    $output
}
Guest "powershell -NoProfile -Command `"if (Test-Path '$work') { throw 'Test work folder already exists' }; New-Item -ItemType Directory '$work' | Out-Null`"" | Out-Null
$all = @(); $failed = $false
try {
    foreach ($file in (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\FRT_x64.exe'),
        (Join-Path $PSScriptRoot 'guest\fragment-layout.cs'), (Join-Path $PSScriptRoot 'guest\frt-fragmentation.ps1')) {
        & scp @ssh -q $file "${dest}:$work/"
        if ($LASTEXITCODE) { throw 'Test file copy failed' }
    }
    foreach ($fileSystem in $Fs) { foreach ($unit in $ClusterSizes) {
        $keepArg = if ($Keep) { ' -Keep' } else { '' }
        $lines = Guest "powershell -NoProfile -ExecutionPolicy Bypass -File $work\frt-fragmentation.ps1 -Fs $fileSystem -ClusterSize $unit -Counts $Counts -ExpectedOutcome $ExpectedOutcome -Frt $work\FRT_x64.exe -Work $work$keepArg"
        $lines | Set-Content -LiteralPath (Join-Path $resultsDir "$fileSystem-$unit.log") -Encoding UTF8
        $lines | ForEach-Object { if ($_ -like 'SUMMARY *') { $all += $_.Substring(8) | ConvertFrom-Json } else { Write-Host $_ } }
        & scp @ssh -q "${dest}:$work/layouts-$fileSystem-$unit.json" $resultsDir
        if ($LASTEXITCODE) { throw 'Layout manifest copy failed' }
    } }
    $all | Format-Table fs,clusterSize,cases,recovered,metadataOnly,failed
    Write-Host "Measured layouts and hashes: $resultsDir"
    if ($all.Count -ne $Fs.Count * $ClusterSizes.Count -or @($all | Where-Object failed -ne 0).Count) { throw 'Measured fragmentation matrix failed' }
} catch {
    $failed = $true
    & scp @ssh -q "${dest}:$work/layouts-*.json" $resultsDir
    throw
}
finally {
    if (-not $Keep -and -not $failed) { Guest "powershell -NoProfile -Command `"Remove-Item -LiteralPath '$work' -Recurse -Force`"" | Out-Null }
    elseif ($failed) { Write-Host "Evidence retained in guest $work (the scenario detaches its own disk unless -Keep)." }
}
