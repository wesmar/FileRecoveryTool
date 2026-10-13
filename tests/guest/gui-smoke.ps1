# Runs GUI self-tests in the logged-in VM session. SSH's session 0 reports
# PerMonitor V1, so it cannot validate the interactive V2 process context.
param([string]$User = 'Administrator')
$ErrorActionPreference = 'Stop'
$work = $PSScriptRoot
$taskName = 'FRT-GUI-Smoke-' + [Guid]::NewGuid().ToString('N')
$runner = Join-Path $work 'run-gui-smoke.ps1'
$exe = Join-Path $work 'gui-smoke.exe'
$exitFile = Join-Path $work 'gui.exit'
$log = Join-Path $work 'gui.log'
$err = Join-Path $work 'gui.err'
@"
`$p = Start-Process -FilePath '$exe' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput '$log' -RedirectStandardError '$err'
[IO.File]::WriteAllText('$exitFile', [string]`$p.ExitCode)
"@ | Set-Content -LiteralPath $runner -Encoding UTF8
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -File $runner"
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
    Start-ScheduledTask -TaskName $taskName
    $deadline = [DateTime]::UtcNow.AddSeconds(40)
    while (-not (Test-Path $exitFile) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
    Get-Content -LiteralPath $log, $err -ErrorAction SilentlyContinue
    if (-not (Test-Path $exitFile)) { throw 'GUI test timed out: the test user must be logged in.' }
    $code = [int](Get-Content -LiteralPath $exitFile)
    if ($code) { throw "Interactive GUI test failed ($code)" }
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}
