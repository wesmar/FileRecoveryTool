# testenv.ps1 - the test guest: a Hyper-V Windows VM reachable over ssh.
# Machine-specific values go into testenv.local.psd1 next to this file (not
# tracked), e.g.  @{ Vm = 'Win11'; SshKey = 'C:\Users\me\.ssh\id_vm' }
$TestEnv = @{
    Vm     = 'Win11'
    User   = 'Administrator'
    SshKey = Join-Path $HOME '.ssh\id_ed25519'
}
$local = Join-Path $PSScriptRoot 'testenv.local.psd1'
if (Test-Path $local) {
    $over = Import-PowerShellDataFile $local
    foreach ($k in $over.Keys) { $TestEnv[$k] = $over[$k] }
}

function Get-TestVmIp {
    $ip = (Get-VM $TestEnv.Vm | Get-VMNetworkAdapter).IPAddresses |
          Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
    if (-not $ip) { throw "VM $($TestEnv.Vm) has no IPv4 address yet" }
    $ip
}

function Get-SshOptions {
    @('-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes',
      '-o', 'ServerAliveInterval=15', '-i', $TestEnv.SshKey)
}
