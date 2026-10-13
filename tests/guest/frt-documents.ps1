#Requires -Version 5.1
# Isolated archive/document recovery with explicitly flushed source files.
# Never operate on the guest system disk.
param([string]$Work = 'C:\frt-documents-qa')
$ErrorActionPreference = 'Stop'
$workFull = [IO.Path]::GetFullPath($Work).TrimEnd('\')
if ($workFull -ne 'C:\frt-documents-qa') { throw 'Unexpected document test directory.' }
$frt = Join-Path $workFull 'FRT_x64.exe'
$fixtures = Join-Path $workFull 'fixtures'
$manifest = Get-Content (Join-Path $fixtures 'manifest.json') -Raw | ConvertFrom-Json
$cases = Get-Content (Join-Path $fixtures 'cases\expectations.json') -Raw | ConvertFrom-Json
$results = [Collections.Generic.List[object]]::new()
$resultFile = Join-Path $workFull 'results.json'
function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Record($Result) {
    $results.Add($Result)
    $results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultFile -Encoding UTF8
    Write-Host ($(if ($Result.passed) { 'PASS ' } else { 'FAILED ' }) + $Result.case)
}
function Recover([string]$Name, [string[]]$Arguments) {
    $out = Join-Path $workFull ('out-' + $Name)
    if (Test-Path -LiteralPath $out) { throw 'Earlier output exists.' }
    New-Item -ItemType Directory -Path $out | Out-Null
    $csv = Join-Path $workFull ($Name + '.csv')
    $log = Join-Path $workFull ($Name + '.log')
    $cli = @('--cli') + $Arguments + @('--csv',$csv,'--recover','--output',$out,'--diagnostics')
    $process = Start-Process -FilePath $frt -ArgumentList $cli -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $log -RedirectStandardError ($log + '.err')
    $rows = if (Test-Path -LiteralPath $csv) { @(Import-Csv -LiteralPath $csv -Encoding UTF8) } else { @() }
    [pscustomobject]@{ exit=$process.ExitCode; rows=@($rows); outputs=@(Get-ChildItem -LiteralPath $out -File -Recurse); directory=$out }
}
foreach ($fixture in $manifest) {
    if ($fixture.name -notmatch '^[a-z0-9-]+\.(zip|7z|docx|pdf)$') { throw 'Unsafe fixture filename.' }
    if ((Sha (Join-Path $fixtures $fixture.name)) -ne $fixture.sha256) { throw 'Fixture hash mismatch.' }
}
foreach ($test in $cases) {
    if ($test.name -notmatch '^[a-z0-9-]+$') { throw 'Unsafe case filename.' }
    $source = Join-Path $fixtures ('cases\' + $test.name + '.img')
    if ((Sha $source) -ne $test.sourceSha256) { throw 'RAW source hash mismatch.' }
    $run = Recover ('raw-' + $test.name) @('--image',$source,'--raw')
    $expected = @($test.outputs)
    $passed = $run.outputs.Count -eq $expected.Count -and $run.rows.Count -eq $expected.Count -and
        $run.exit -eq $(if ($expected.Count) { 0 } else { 1 }) -and (Sha $source) -eq $test.sourceSha256
    $outputHashes = @($run.outputs | ForEach-Object { @{ sha256=(Sha $_.FullName); extension=$_.Extension } })
    foreach ($want in $expected) {
        $matching = @($run.outputs | Where-Object { (Sha $_.FullName) -eq $want.sha256 -and $_.Extension -eq $want.extension })
        if ($matching.Count -ne 1) { $passed = $false; continue }
        $row = @($run.rows | Where-Object Name -eq $matching[0].Name)
        if ($row.Count -ne 1 -or $row[0].Quality -ne $want.quality) { $passed = $false }
    }
    Record ([pscustomobject]@{ case=('raw-' + $test.name); passed=$passed; exit=$run.exit; recovered=$run.outputs.Count;
        quality=@($run.rows.Quality); expected=$expected; outputs=$outputHashes; sourceUnchanged=((Sha $source) -eq $test.sourceSha256) })
}
Add-Type -Path (Join-Path $PSScriptRoot 'fragment-layout.cs')
$diskpartFile = Join-Path $workFull 'diskpart.txt'
function DiskPart([string[]]$Lines) {
    Set-Content -LiteralPath $diskpartFile -Value $Lines -Encoding ASCII
    $output = & diskpart.exe /s $diskpartFile
    if ($LASTEXITCODE) { throw ('diskpart failed: ' + ($output -join ' | ')) }
}
foreach ($fs in @('NTFS','exFAT')) {
    $vhd = Join-Path $workFull ($fs + '.vhdx')
    if (Test-Path -LiteralPath $vhd) { throw 'An earlier test disk exists.' }
    $letters = @((Get-PSDrive -PSProvider FileSystem).Name)
    $letter = @([char[]]'RSTUVWXYQP' | ForEach-Object { [string]$_ } | Where-Object { $_ -notin $letters })[0]
    if (-not $letter) { throw 'No free test drive letter.' }
    $root = $letter + ':\'
    $passedFs = $false
    try {
        DiskPart @(('create vdisk file="{0}" maximum=128 type=expandable' -f $vhd), 'attach vdisk', 'create partition primary',
            ('format fs={0} unit=4096 quick label=FRTDocs' -f $fs), ('assign letter=' + $letter))
        if ((Get-Volume -DriveLetter $letter).AllocationUnitSize -ne 4096) { throw 'Unexpected allocation unit.' }
        $scenarios = @($manifest | ForEach-Object { @{ fixture=$_; extents=0; reverse=$false; suffix='ordinary' } })
        foreach ($fixture in @($manifest | Where-Object name -in 'word.docx','word.pdf','sample.7z','stored.zip')) {
            foreach ($reverse in @($false,$true)) {
                $scenarios += @{ fixture=$fixture; extents=8; reverse=$reverse; suffix=$(if ($reverse) { '8-reverse' } else { '8-forward' }) }
            }
        }
        foreach ($scenario in $scenarios) {
            $fixture = $scenario.fixture
            $case = $fs + '-' + $scenario.suffix + '-' + $fixture.name.Replace('.','-')
            $name = $scenario.suffix + '-' + $fixture.name
            $source = Join-Path $root $name
            Copy-Item -LiteralPath (Join-Path $fixtures $fixture.name) -Destination $source
            $map = @()
            if ($scenario.extents) {
                $clusters = [long][math]::Ceiling($fixture.bytes / 4096.0)
                $plan = [FragmentLayout]::Create($source, ('\\.\' + $letter + ':'), $clusters, 8, $scenario.reverse)
                Write-VolumeCache -DriveLetter $letter
                $map = @([FragmentLayout]::Read($source))
                if ($map.Count -ne 8) { throw 'Physical fragment count mismatch.' }
                for ($i=0; $i -lt 8; ++$i) {
                    if ($map[$i].Vcn -ne $plan[$i].Vcn -or $map[$i].Lcn -ne $plan[$i].Lcn -or $map[$i].Clusters -ne $plan[$i].Clusters) {
                        throw 'Physical fragment map mismatch.'
                    }
                }
            }
            # CopyFile can leave data only in cache; flushing after deletion is
            # too late. Persist both file data and allocation metadata first.
            Write-VolumeCache -DriveLetter $letter
            if ((Sha $source) -ne $fixture.sha256) { throw 'File movement altered the fixture.' }
            Remove-Item -LiteralPath $source -Force
            Write-VolumeCache -DriveLetter $letter
            $run = Recover $case @('--drive',$letter,'--mft','--filename',$name)
            $hashes = @($run.outputs | ForEach-Object { Sha $_.FullName })
            $passed = $run.exit -eq 0 -and $run.rows.Count -eq 1 -and $run.rows[0].Name -eq $name -and
                $run.rows[0].Quality -eq 'Full' -and $hashes.Count -eq 1 -and $hashes[0] -eq $fixture.sha256
            Record ([pscustomobject]@{ case=$case; fs=$fs; passed=$passed; exit=$run.exit; recovered=$run.outputs.Count;
                quality=@($run.rows.Quality); bytes=$fixture.bytes; expectedSha256=$fixture.sha256; hashes=$hashes;
                requestedExtents=$scenario.extents; map=$map; reverse=$scenario.reverse })
        }
        $passedFs = @($results | Where-Object { $_.fs -eq $fs -and -not $_.passed }).Count -eq 0
    } finally {
        if ((Test-Path -LiteralPath $vhd) -and (Get-DiskImage -ImagePath $vhd).Attached) {
            DiskPart @(('select vdisk file="{0}"' -f $vhd), 'detach vdisk')
            if ($passedFs) { Remove-Item -LiteralPath $vhd -Force }
        }
    }
}
'SUMMARY ' + (@{ rawCases=$cases.Count; metadataCases=@($results | Where-Object fs).Count;
    failed=@($results | Where-Object { -not $_.passed }).Count } | ConvertTo-Json -Compress)
