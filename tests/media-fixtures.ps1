#Requires -Version 7.0
# Real, deterministic media for metadata and carving recovery tests.
# Uses Windows image codecs and an already installed FFmpeg. Installs nothing.
param([string]$Output = (Join-Path $PSScriptRoot 'fixtures'))
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Output -Force | Out-Null
Add-Type -AssemblyName System.Drawing
$bitmap = [Drawing.Bitmap]::new(256, 192, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
try {
    $bits = $bitmap.LockBits([Drawing.Rectangle]::new(0, 0, 256, 192), [Drawing.Imaging.ImageLockMode]::WriteOnly, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
    try {
        $pixels = [byte[]]::new($bits.Stride * 192)
        [Random]::new(83647).NextBytes($pixels)
        [Runtime.InteropServices.Marshal]::Copy($pixels, 0, $bits.Scan0, $pixels.Length)
    } finally { $bitmap.UnlockBits($bits) }
    foreach ($format in 'Jpeg', 'Png', 'Gif', 'Bmp') {
        $extension = if ($format -eq 'Jpeg') { 'jpg' } else { $format.ToLowerInvariant() }
        $bitmap.Save((Join-Path $Output "codec.$extension"), [Drawing.Imaging.ImageFormat]::$format)
    }
} finally { $bitmap.Dispose() }
$zipPath = Join-Path $Output 'codec.zip'
$zipFile = [IO.File]::Open($zipPath, 'Create')
$zip = [IO.Compression.ZipArchive]::new($zipFile, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($name in 'first.bin', 'second.bin') {
        $entry = $zip.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
        $entry.LastWriteTime = [DateTimeOffset]::new(2026, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        $stream = $entry.Open()
        try { $data = [byte[]]::new(70000); [Random]::new($name.Length).NextBytes($data); $stream.Write($data) }
        finally { $stream.Dispose() }
    }
} finally { $zip.Dispose(); $zipFile.Dispose() }
$ffmpeg = Get-Command ffmpeg -ErrorAction SilentlyContinue
if (-not $ffmpeg) { throw 'An existing FFmpeg is required for video fixtures. No installation was attempted.' }
foreach ($kind in 'mp4', 'avi', 'wav') {
    $args = @('-hide_banner', '-loglevel', 'error', '-y', '-f', 'lavfi')
    if ($kind -eq 'wav') { $args += @('-i', 'sine=frequency=440:sample_rate=44100', '-t', '1', '-c:a', 'pcm_s16le') }
    else { $args += @('-i', 'testsrc2=size=128x96:rate=12', '-t', '1', '-c:v', $(if ($kind -eq 'mp4') { 'mpeg4' } else { 'mjpeg' }), '-threads', '1') }
    & $ffmpeg.Source @args (Join-Path $Output "codec.$kind")
    if ($LASTEXITCODE) { throw "FFmpeg failed to create $kind ($LASTEXITCODE)." }
}
Get-ChildItem -LiteralPath $Output -File | Select-Object Name,Length
