#Requires -Version 7.0
# Build all release variants using toolchain and SDK files found on disk.
param([switch]$Rebuild)
$ErrorActionPreference = 'Stop'
function Inputs {
    $paths = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Recurse -File | Select-Object -ExpandProperty FullName)
    $paths += (Join-Path $PSScriptRoot 'build.ps1'), (Join-Path $PSScriptRoot 'kvc_recovery.vcxproj')
    @($paths | Sort-Object | ForEach-Object {
        [pscustomobject]@{ path=[IO.Path]::GetRelativePath($PSScriptRoot,$_); sha256=(Get-FileHash -LiteralPath $_).Hash }
    })
}
$inputSnapshot = Inputs
$project = Join-Path $PSScriptRoot 'kvc_recovery.vcxproj'
$toolset = ([xml](Get-Content -LiteralPath $project)).Project.PropertyGroup.PlatformToolset | Select-Object -First 1
$programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
$candidates = @()
$vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere) {
    $candidates += & $vswhere -products '*' -prerelease -format value -property installationPath
    if ($LASTEXITCODE) { throw 'Visual Studio discovery failed.' }
}
foreach ($base in $env:ProgramFiles, $programFilesX86) {
    $vsBase = Join-Path $base 'Microsoft Visual Studio'
    if (Test-Path -LiteralPath $vsBase) {
        $candidates += Get-ChildItem -LiteralPath $vsBase -Directory |
            ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Directory } | Select-Object -ExpandProperty FullName
    }
}
$selected = $null
foreach ($vs in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
    $mb = Join-Path $vs 'MSBuild\Current\Bin\amd64\MSBuild.exe'
    $cpp = Get-ChildItem -LiteralPath (Join-Path $vs 'VC\Tools\MSVC') -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path -LiteralPath (Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe')) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName 'bin\Hostx64\x86\cl.exe')) } |
        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    $ts = Get-ChildItem -LiteralPath (Join-Path $vs 'MSBuild\Microsoft\VC') -Directory -ErrorAction SilentlyContinue |
        Where-Object { (Test-Path -LiteralPath (Join-Path $_.FullName "Platforms\x64\PlatformToolsets\$toolset")) -and
            (Test-Path -LiteralPath (Join-Path $_.FullName "Platforms\Win32\PlatformToolsets\$toolset")) } | Select-Object -First 1
    if ($cpp -and $ts -and (Test-Path -LiteralPath $mb)) {
        $selected = @{ msbuild=$mb; version=$cpp.Name }; break
    }
}
if (-not $selected) { throw "No usable x64/x86 compiler and MSBuild for $toolset found." }
$kits = Join-Path $programFilesX86 'Windows Kits\10'
$sdk = Get-ChildItem -LiteralPath (Join-Path $kits 'bin') -Directory |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'x64\rc.exe')) -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'x86\rc.exe')) -and
        (Test-Path -LiteralPath (Join-Path $kits "Include\$($_.Name)\um\Windows.h")) -and
        (Test-Path -LiteralPath (Join-Path $kits "Lib\$($_.Name)\um\x64\kernel32.lib")) -and
        (Test-Path -LiteralPath (Join-Path $kits "Lib\$($_.Name)\um\x86\kernel32.lib")) } |
    Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $sdk) { throw 'No complete x64/x86 Windows SDK with resource compilers found.' }
Write-Host "Compiler $($selected.version); SDK $($sdk.Name); platform toolset $toolset"
$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }
foreach ($configuration in @('Release','Release_MinSize')) {
    foreach ($platform in @('x64','Win32')) {
        $arguments = @($project, "/p:Configuration=$configuration", "/p:Platform=$platform", "/p:PlatformToolset=$toolset",
            "/p:VCToolsVersion=$($selected.version)", "/p:WindowsTargetPlatformVersion=$($sdk.Name)",
            "/p:SolutionDir=$PSScriptRoot\", '/p:GuiSmokeTest=false', "/t:$target", '/m', '/nologo', '/v:minimal', '/clp:Summary')
        & ($selected.msbuild) @arguments
        if ($LASTEXITCODE) { throw "Build failed: $configuration / $platform ($LASTEXITCODE)." }
    }
}
if (($inputSnapshot | ConvertTo-Json -Compress) -ne ((Inputs) | ConvertTo-Json -Compress)) {
    throw 'Build inputs changed during compilation; rebuild all variants.'
}
$binaries = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'bin') -File -Filter 'FRT*.exe' |
    Select-Object Name,Length,@{Name='SHA256';Expression={(Get-FileHash -LiteralPath $_.FullName).Hash}})
if ($binaries.Count -ne 4) { throw 'Expected exactly four release binaries.' }
[pscustomobject]@{ compiler=$selected.version; sdk=$sdk.Name; toolset=$toolset; inputs=$inputSnapshot; binaries=$binaries } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'bin\build-receipt.json') -Encoding utf8
$binaries | Format-Table -AutoSize
