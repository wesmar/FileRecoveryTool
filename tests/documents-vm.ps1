#Requires -Version 7.0
# Actual document/archive fixtures on separate VHDX volumes in the test guest.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'testenv.ps1')
$ip = Get-TestVmIp; $ssh = Get-SshOptions; $dest = "$($TestEnv.User)@$ip"
$work = 'C:\frt-documents-qa'
$fixtures = Join-Path $PSScriptRoot 'fixtures\documents'
$manifest = @(Get-Content (Join-Path $fixtures 'manifest.json') -Raw | ConvertFrom-Json)
$runName = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$resultsDir = Join-Path (Join-Path $PSScriptRoot 'document-results') $runName
New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
function Guest([string]$Command) {
    $output = & ssh @ssh $dest $Command
    if ($LASTEXITCODE) { throw "Guest command failed ($LASTEXITCODE): $Command" }
    $output
}
function GuestScript([string]$Script) {
    Guest ('powershell -NoProfile -OutputFormat Text -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('$ProgressPreference = ''SilentlyContinue''; ' + $Script)))
}
GuestScript "if (Test-Path '$work') { throw 'Earlier document test folder exists.' }; New-Item -ItemType Directory '$work\fixtures\cases' | Out-Null" | Out-Null
$failed = $false
try {
    foreach ($file in (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\FRT_x64.exe'),
        (Join-Path $PSScriptRoot 'guest\fragment-layout.cs'), (Join-Path $PSScriptRoot 'guest\frt-documents.ps1')) {
        & scp @ssh -q $file ($dest + ':' + $work + '/')
        if ($LASTEXITCODE) { throw 'Document test copy failed.' }
    }
    foreach ($entry in $manifest) {
        if ($entry.name -notmatch '^[a-z0-9-]+\.(zip|7z|docx|pdf)$') { throw 'Unsafe fixture filename.' }
        & scp @ssh -q (Join-Path $fixtures $entry.name) ($dest + ':' + $work + '/fixtures/')
        if ($LASTEXITCODE) { throw 'Fixture copy failed.' }
    }
    & scp @ssh -q (Join-Path $fixtures 'manifest.json') ($dest + ':' + $work + '/fixtures/')
    if ($LASTEXITCODE) { throw 'Manifest copy failed.' }
    & scp @ssh -q (Join-Path $fixtures 'cases\*') ($dest + ':' + $work + '/fixtures/cases/')
    if ($LASTEXITCODE) { throw 'RAW case copy failed.' }
    $output = Guest "powershell -NoProfile -ExecutionPolicy Bypass -File $work\frt-documents.ps1"
    $output | Tee-Object -FilePath (Join-Path $resultsDir 'summary.log')
    $summary = @($output | Where-Object { $_ -like 'SUMMARY *' })
    if ($summary.Count -ne 1) { throw 'Document test summary missing.' }
    $result = $summary[0].Substring(8) | ConvertFrom-Json
    if ($result.failed -ne 0 -or $result.rawCases -ne 10 -or $result.metadataCases -ne 42) { throw 'Document recovery matrix failed.' }
} catch {
    $failed = $true
    throw
} finally {
    & scp @ssh -q ($dest + ':' + $work + '/*.log') ($dest + ':' + $work + '/*.csv') ($dest + ':' + $work + '/results.json') $resultsDir
    if ($LASTEXITCODE) { Write-Warning 'Some diagnostic files could not be collected.' }
    if (-not $failed) {
        GuestScript "if ([IO.Path]::GetFullPath('$work') -ne 'C:\frt-documents-qa') { throw 'Unexpected cleanup path' }; Remove-Item -LiteralPath '$work' -Recurse -Force" | Out-Null
    } else { Write-Host "Evidence retained in guest $work" }
    Write-Host "Document recovery logs and physical maps: $resultsDir"
}
