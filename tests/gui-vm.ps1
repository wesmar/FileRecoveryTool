#Requires -Version 7.0
param([switch]$Build)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'testenv.ps1')
if ($Build) { & (Join-Path $PSScriptRoot 'build-x64.ps1') -TestGui }
$ip = Get-TestVmIp
$ssh = Get-SshOptions
$dest = "$($TestEnv.User)@$ip"
$work = 'C:\frt-gui-qa'
function Guest([string]$Command) {
    $output = & ssh @ssh $dest $Command
    if ($LASTEXITCODE) { throw "Guest command failed ($LASTEXITCODE): $Command" }
    $output
}
# This dedicated test folder must not contain somebody else's work.
Guest "powershell -NoProfile -Command `"if (Test-Path '$work') { throw 'Test folder already exists' }; New-Item -ItemType Directory '$work' | Out-Null`"" | Out-Null
try {
    & scp @ssh -q (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\gui-smoke.exe') "${dest}:$work/gui-smoke.exe"
    if ($LASTEXITCODE) { throw 'GUI test executable copy failed.' }
    & scp @ssh -q (Join-Path $PSScriptRoot 'guest\gui-smoke.ps1') "${dest}:$work/gui-smoke.ps1"
    if ($LASTEXITCODE) { throw 'GUI test runner copy failed.' }
    Guest "powershell -NoProfile -ExecutionPolicy Bypass -File $work\gui-smoke.ps1 -User $($TestEnv.User)"
} finally {
    Guest "powershell -NoProfile -Command `"Remove-Item -LiteralPath '$work' -Recurse -Force`"" | Out-Null
}
