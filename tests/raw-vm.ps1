#Requires -Version 7.0
param([switch]$Keep)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'testenv.ps1')
$ip = Get-TestVmIp; $ssh = Get-SshOptions; $dest = "$($TestEnv.User)@$ip"
$work = 'C:\frt-raw-qa'
$runName = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$resultsDir = Join-Path (Join-Path $PSScriptRoot 'raw-results') $runName
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
function Guest([string]$Command) {
    $output = & ssh @ssh $dest $Command
    if ($LASTEXITCODE) { throw "Guest command failed ($LASTEXITCODE): $Command`n$($output -join "`n")" }
    $output
}
Guest "powershell -NoProfile -Command `"if (Test-Path '$work') { throw 'Test work folder already exists' }; New-Item -ItemType Directory '$work\fixtures' | Out-Null`"" | Out-Null
$failed = $false
try {
    foreach ($file in (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\FRT_x64.exe'), (Join-Path $PSScriptRoot 'guest\frt-raw.ps1')) {
        & scp @ssh -q $file "${dest}:$work/"
        if ($LASTEXITCODE) { throw 'RAW test file copy failed' }
    }
    & scp @ssh -q (Join-Path $PSScriptRoot 'fixtures\codec.*') "${dest}:$work/fixtures/"
    if ($LASTEXITCODE) { throw 'Codec fixture copy failed; generate them with media-fixtures.ps1 first' }
    $keepArg = if ($Keep) { ' -Keep' } else { '' }
    $output = Guest "powershell -NoProfile -ExecutionPolicy Bypass -File $work\frt-raw.ps1 -Frt $work\FRT_x64.exe -Fixtures $work\fixtures -Work $work$keepArg"
    $output | Tee-Object -FilePath (Join-Path $resultsDir 'summary.log')
    if ($output -notcontains 'SUMMARY raw=8/8 physical=8/8 source=unchanged') { throw 'RAW summary missing' }
} catch {
    $failed = $true
    throw
} finally {
    & scp @ssh -q "${dest}:$work/*.log" "${dest}:$work/*.csv" "${dest}:$work/*.json" $resultsDir
    if ($LASTEXITCODE) { Write-Warning 'Some RAW diagnostic files could not be collected' }
    if (-not $Keep -and -not $failed) {
        Guest "powershell -NoProfile -Command `"Remove-Item -LiteralPath '$work' -Recurse -Force`"" | Out-Null
    } else { Write-Host "RAW evidence retained in guest $work" }
    Write-Host "RAW logs and hashes: $resultsDir"
}
