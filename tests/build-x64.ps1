#Requires -Version 7.0
# build-x64.ps1 - builds bin\FRT_x64.exe only (Release|x64), the image the
# tests run. Visual Studio is found from evidence on disk, not from version
# numbers: an installation is taken only when it holds Hostx64\x64\cl.exe and
# MSBuild, and the platform toolset the project names.
param([switch]$Rebuild, [switch]$TestCarver, [switch]$TestGui)
$ErrorActionPreference = 'Stop'
if ($TestCarver -and $TestGui) { throw 'Choose one test target at a time.' }
$root    = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root 'kvc_recovery.vcxproj'
$toolset = ([xml](Get-Content $project)).Project.PropertyGroup.PlatformToolset | Select-Object -First 1
if ($TestCarver) { $project = Join-Path $PSScriptRoot 'carver-tests.vcxproj' }

$candidates = @()
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
    $candidates += & $vswhere -products '*' -prerelease -format value -property installationPath 2>$null
}
foreach ($base in $env:ProgramFiles, ${env:ProgramFiles(x86)}) {
    $vsBase = Join-Path $base 'Microsoft Visual Studio'
    if (Test-Path $vsBase) {
        $candidates += Get-ChildItem $vsBase -Directory | ForEach-Object { Get-ChildItem $_.FullName -Directory } |
                       Select-Object -ExpandProperty FullName
    }
}
$msbuild = $null
foreach ($vs in ($candidates | Where-Object { $_ } | Select-Object -Unique)) {
    $cl = Get-ChildItem (Join-Path $vs 'VC\Tools\MSVC') -Directory -ErrorAction SilentlyContinue |
          Where-Object { Test-Path (Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe') } |
          Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    $ts = Get-ChildItem (Join-Path $vs 'MSBuild\Microsoft\VC') -Directory -ErrorAction SilentlyContinue |
          Where-Object { Test-Path (Join-Path $_.FullName "Platforms\x64\PlatformToolsets\$toolset") } | Select-Object -First 1
    $mb = Join-Path $vs 'MSBuild\Current\Bin\amd64\MSBuild.exe'
    if ($cl -and $ts -and (Test-Path $mb)) { $msbuild = $mb; break }
}
if (-not $msbuild) { throw "No Visual Studio with cl.exe and the $toolset toolset was found." }

$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }
& $msbuild $project /p:Configuration=Release /p:Platform=x64 "/p:GuiSmokeTest=$($TestGui.IsPresent.ToString().ToLowerInvariant())" "/p:PlatformToolset=$toolset" "/p:SolutionDir=$root\" /t:$target /m /nologo /v:minimal /clp:Summary
if ($LASTEXITCODE) { throw "Build failed ($LASTEXITCODE)." }
$name = if ($TestCarver) { 'carver-tests.exe' } elseif ($TestGui) { 'gui-smoke.exe' } else { 'FRT_x64.exe' }
$exe = Join-Path $root "bin\$name"
"$name  $((Get-Item $exe).Length) bytes  $((Get-FileHash $exe).Hash.Substring(0,16))"
