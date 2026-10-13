#Requires -Version 5.1
# Measures the real physical layout before deletion, not a write-pattern guess.
param(
    [Parameter(Mandatory)][ValidateSet('NTFS','exFAT')][string]$Fs,
    [Parameter(Mandatory)][string]$Frt,
    [ValidateSet(4096,32768)][int]$ClusterSize = 4096,
    [string]$Work = 'C:\frt-fragmentation',
    [string]$Counts = '1,2,8,32,128',
    [ValidateSet('Full','MetadataOnly')][string]$ExpectedOutcome = 'Full',
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$workFull = [IO.Path]::GetFullPath($Work).TrimEnd('\')
if ($workFull -ne 'C:\frt-fragmentation') { throw 'The isolated test work folder must be C:\frt-fragmentation.' }
$vhd = Join-Path $workFull "frag-$Fs-$ClusterSize.vhdx"
$diskpartFile = Join-Path $workFull 'diskpart.txt'
$layoutFile = Join-Path $workFull "layouts-$Fs-$ClusterSize.json"
function DiskPart([string[]]$Lines) {
    Set-Content -LiteralPath $diskpartFile -Value $Lines -Encoding ASCII
    $output = & diskpart.exe /s $diskpartFile
    if ($LASTEXITCODE) { throw "diskpart failed ($LASTEXITCODE): $($output -join ' | ')" }
}
function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash }
New-Item -ItemType Directory -Path $workFull -Force | Out-Null
if (Test-Path $vhd) { throw "An earlier test disk exists: $vhd" }
$letters = @((Get-PSDrive -PSProvider FileSystem).Name)
$letter = @([char[]]'RSTUVWXYQP' | ForEach-Object { [string]$_ } | Where-Object { $_ -notin $letters })[0]
if (-not $letter) { throw 'No free test drive letter' }
$root = "${letter}:\"
Add-Type -Path (Join-Path $PSScriptRoot 'fragment-layout.cs')
$attached = $false
$scenarioFailed = $false
$results = [Collections.Generic.List[object]]::new()
try {
    DiskPart @("create vdisk file=`"$vhd`" maximum=128 type=expandable", 'attach vdisk', 'create partition primary',
        "format fs=$Fs unit=$ClusterSize quick label=FRTFragment", "assign letter=$letter")
    $attached = $true
    $actualUnit = (Get-Volume -DriveLetter $letter).AllocationUnitSize
    if ($actualUnit -ne $ClusterSize) { throw "Unexpected allocation unit: $actualUnit" }
    foreach ($count in ($Counts.Split(',') | ForEach-Object { [int]$_ })) {
        foreach ($direction in $(if ($count -eq 1) { @('forward') } else { @('forward','reverse') })) {
            $case = "$Fs-$ClusterSize-$count-$direction"
            $name = "$case.bin"
            $source = Join-Path $root $name
            $data = New-Object byte[] (8 * 1024 * 1024 + 37)
            [Random]::new(1000 + $count).NextBytes($data)
            [IO.File]::WriteAllBytes($source, $data)
            $expectedSha = Sha $source
            $clusters = [long][math]::Ceiling($data.Length / [double]$ClusterSize)
            $plan = [FragmentLayout]::Create($source, "\\.\${letter}:", $clusters, $count, $direction -eq 'reverse')
            Write-VolumeCache -DriveLetter $letter
            $actual = @([FragmentLayout]::Read($source))
            if ($actual.Count -ne $count) { throw "$case created $($actual.Count) physical extents, expected $count" }
            for ($i = 0; $i -lt $actual.Count; ++$i) {
                if ($actual[$i].Vcn -ne $plan[$i].Vcn -or $actual[$i].Lcn -ne $plan[$i].Lcn -or $actual[$i].Clusters -ne $plan[$i].Clusters) {
                    throw "$case layout differs from the requested physical map"
                }
            }
            if ((Sha $source) -ne $expectedSha) { throw "$case movement changed the fixture bytes" }
            Remove-Item -LiteralPath $source -Force
            Write-VolumeCache -DriveLetter $letter
            $out = Join-Path $workFull "rec-$case"
            $csv = Join-Path $workFull "$case.csv"
            $log = Join-Path $workFull "$case.log"
            New-Item -ItemType Directory -Path $out | Out-Null
            $args = @('--cli','--drive',$letter,'--mft','--filename',$name,'--csv',$csv,'--recover','--output',$out)
            $timer = [Diagnostics.Stopwatch]::StartNew()
            $process = Start-Process -FilePath $Frt -ArgumentList $args -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError "$log.err"
            $timer.Stop()
            $recovered = @(Get-ChildItem -LiteralPath $out -File -Recurse | Where-Object { (Sha $_.FullName) -eq $expectedSha })
            $rows = @(Import-Csv -LiteralPath $csv -Encoding UTF8)
            $allOutputs = @(Get-ChildItem -LiteralPath $out -File -Recurse)
            $passed = if ($ExpectedOutcome -eq 'Full') {
                $recovered.Count -eq 1 -and $process.ExitCode -eq 0 -and $rows.Count -eq 1 -and $rows[0].Quality -eq 'Full'
            } else {
                $allOutputs.Count -eq 0 -and $process.ExitCode -eq 4 -and $rows.Count -eq 1 -and
                    $rows[0].Name -eq $name -and $rows[0].Quality -eq 'MetadataOnly' -and $rows[0].Recoverable -eq 'No'
            }
            $result = [pscustomobject]@{
                fs=$Fs; clusterSize=$ClusterSize; case=$case; requestedExtents=$count; measuredExtents=$actual.Count;
                direction=$direction; bytes=$data.Length; sha256=$expectedSha; map=$actual;
                recovered=($recovered.Count -eq 1); exit=$process.ExitCode; quality=($rows.Quality -join ',');
                expectedOutcome=$ExpectedOutcome; passed=$passed;
                outputFiles=@($allOutputs | ForEach-Object { @{bytes=$_.Length; sha256=(Sha $_.FullName)} });
                milliseconds=$timer.ElapsedMilliseconds
            }
            $results.Add($result)
            if (-not $result.passed) { $scenarioFailed = $true }
            $state = if (-not $passed) { 'FAILED' } elseif ($ExpectedOutcome -eq 'MetadataOnly') { 'METADATA-ONLY' } else { 'OK' }
            [Console]::WriteLine(("{0} {1} actual-extents={2} quality={3} {4}ms" -f $state,$case,$actual.Count,$result.quality,$result.milliseconds))
            $results | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $layoutFile -Encoding UTF8
        }
    }
    'SUMMARY ' + (@{ fs=$Fs; clusterSize=$ClusterSize; cases=$results.Count; recovered=@($results | Where-Object recovered).Count;
        metadataOnly=@($results | Where-Object { $_.quality -eq 'MetadataOnly' -and $_.passed }).Count;
        failed=@($results | Where-Object { -not $_.passed }).Count } | ConvertTo-Json -Compress)
} catch {
    $scenarioFailed = $true
    throw
} finally {
    if ($attached -and -not $Keep) {
        DiskPart @("select vdisk file=`"$vhd`"", 'detach vdisk')
        if (-not $scenarioFailed) { Remove-Item -LiteralPath $vhd -Force }
    }
}
