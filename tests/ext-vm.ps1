#Requires -Version 7.0
# ext-vm.ps1 - ext2/3/4 recovery on the Hyper-V test guest. WSL builds the
# test disk with the Linux kernel (ext-image.sh), the disk is attached to the
# guest with no ext driver running there - its partitions get no drive
# letter, as on any Windows machine - and frt-ext.ps1 recovers every file
# through the volume's device path and checks it against the manifest.
#
#   pwsh tests\ext-vm.ps1 [-Build] [-Keep]
param([switch]$Build, [switch]$Keep, [string]$Modes = 'mft', [switch]$Media, [switch]$Driver)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'testenv.ps1')
if ($Build) { & (Join-Path $PSScriptRoot 'build-x64.ps1') | Write-Host }
if ($Media) { & (Join-Path $PSScriptRoot 'media-fixtures.ps1') | Out-Host }

$vhd = Join-Path $PSScriptRoot 'ext-test.vhdx'
$size = 335544320                       # identifies the disk inside WSL
$exe = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\FRT_x64.exe'
$manifest = Join-Path $PSScriptRoot 'ext-manifest.txt'

# the disk: this test's own, rebuilt every run
Get-VMHardDiskDrive -VMName $TestEnv.Vm | Where-Object Path -eq $vhd | Remove-VMHardDiskDrive
if (Test-Path $vhd) { [IO.File]::Delete($vhd) }
New-VHD -Path $vhd -SizeBytes $size -Dynamic | Out-Null
wsl --mount --vhd $vhd --bare | Out-Null
try {
    $wsh = (wsl wslpath -a ($PSScriptRoot -replace '\\', '/') ) + '/ext-image.sh'
    $fixtures = if ($Media) { (wsl wslpath -a ((Join-Path $PSScriptRoot 'fixtures') -replace '\\', '/')).Trim() } else { '' }
    $lines = wsl -u root -- bash -c "sed 's/\r`$//' '$wsh' > /tmp/ext-image.sh && bash /tmp/ext-image.sh $size '$fixtures'"
    if ($LASTEXITCODE) { throw "ext-image.sh failed ($LASTEXITCODE)" }
} finally {
    wsl --unmount "\\?\$vhd" | Out-Null
}
if (-not ($lines -contains 'IMAGE READY')) { $lines | Write-Host; throw 'ext-image.sh failed' }
$entries = $lines | Where-Object { $_ -like 'MANIFEST *' } | ForEach-Object { $_.Substring(9) }
[IO.File]::WriteAllLines($manifest, [string[]]$entries, [Text.UTF8Encoding]::new($false))
Write-Host "== image: $($entries.Count) deleted files"

$ip = Get-TestVmIp
$ssh = Get-SshOptions
$dest = "$($TestEnv.User)@$ip"
$work = 'C:\frt'
function Guest([string]$Command) {
    $output = & ssh @ssh $dest $Command
    if ($LASTEXITCODE) { throw "Guest command failed ($LASTEXITCODE): $Command`n$($output -join "`n")" }
    $output
}

# no ext driver may mount the partitions: they are read as Windows sees them
$driverWasRunning = [bool]((Guest 'sc query ext4') -match 'RUNNING')
$all = @()
$driverChanged = $false
try {
    if ($driverWasRunning -and -not $Driver) { Guest 'sc stop ext4' | Out-Null; $driverChanged = $true }
    if ($Driver -and -not $driverWasRunning) { Guest 'sc start ext4' | Out-Null; $driverChanged = $true }
    Write-Host $(if ($Driver) { '== ext4.sys active: driver interoperability' } else { '== raw volumes: ext4.sys stopped' })

    $slot = (0..63 | Where-Object { $_ -notin (Get-VMHardDiskDrive -VMName $TestEnv.Vm -ControllerType SCSI).ControllerLocation })[0]
    Add-VMHardDiskDrive -VMName $TestEnv.Vm -ControllerType SCSI -ControllerNumber 0 -ControllerLocation $slot -Path $vhd
    Guest "powershell -NoProfile -Command `"New-Item -ItemType Directory -Force $work | Out-Null; Get-Disk | Where-Object { `$_.Size -eq $size -and `$_.IsOffline } | Set-Disk -IsOffline `$false`"" | Out-Null
    & scp @ssh -q $exe "${dest}:$work/FRT_x64.exe"
    if ($LASTEXITCODE) { throw 'Executable copy failed.' }
    & scp @ssh -q (Join-Path $PSScriptRoot 'guest\frt-ext.ps1') "${dest}:$work/frt-ext.ps1"
    if ($LASTEXITCODE) { throw 'Guest script copy failed.' }
    & scp @ssh -q $manifest "${dest}:$work/manifest.txt"
    if ($LASTEXITCODE) { throw 'Manifest copy failed.' }
    Start-Sleep -Seconds 2               # the partitions' volumes arrive
    $lines = Guest "powershell -NoProfile -ExecutionPolicy Bypass -File $work\frt-ext.ps1 -Frt $work\FRT_x64.exe -Manifest $work\manifest.txt -Work $work -Modes $Modes"
    foreach ($l in $lines) {
        if ($l -like 'SUMMARY *') { $all += ($l.Substring(8) | ConvertFrom-Json) }
        elseif ($l -like 'OK *') { Write-Host "   $l" -ForegroundColor DarkGray }
        else { Write-Host "   $l" }
    }
} finally {
    if (-not $Keep) { Guest "powershell -NoProfile -Command `"Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue`"" | Out-Null }
    Get-VMHardDiskDrive -VMName $TestEnv.Vm | Where-Object Path -eq $vhd | Remove-VMHardDiskDrive
    if ($driverChanged -and $driverWasRunning) { Guest 'sc start ext4' | Out-Null }
    if ($driverChanged -and -not $driverWasRunning) { Guest 'sc stop ext4' | Out-Null }
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
if ($all.Count -ne 2 -or @($all | Where-Object { $_.exit -ne 0 -or -not $_.honest -or $_.recovered -ne $_.expected }).Count) {
    throw 'ext recovery matrix failed. Inspect the per-file results above.'
}
