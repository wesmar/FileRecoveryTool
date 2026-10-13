#Requires -Version 7.0
# Creates actual Office packages/PDFs with an already installed Word.
param([string]$Output = (Join-Path $PSScriptRoot 'fixtures\documents'))
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
$document = $null
try {
    $document = $word.Documents.Add()
    $document.Content.Text = [string]::Join([char]13, @('Recovery document validation', 'Expected recovery token: FRT-DOCX-2026.', ''))
    $range = $document.Content; $range.Collapse(0)
    $table = $document.Tables.Add($range, 3, 2)
    $table.Cell(1,1).Range.Text = 'Format'; $table.Cell(1,2).Range.Text = 'Expected'
    $table.Cell(2,1).Range.Text = 'DOCX'; $table.Cell(2,2).Range.Text = 'Byte exact'
    $table.Cell(3,1).Range.Text = 'PDF'; $table.Cell(3,2).Range.Text = 'Readable text'
    $range = $document.Content; $range.Collapse(0)
    $image = Join-Path $PSScriptRoot 'fixtures\codec.png'
    if (-not (Test-Path -LiteralPath $image)) { throw 'Generate media-fixtures.ps1 first.' }
    $document.InlineShapes.AddPicture($image, $false, $true, $range) | Out-Null
    $document.SaveAs2((Join-Path $Output 'word.docx'), 16)
    $document.ExportAsFixedFormat((Join-Path $Output 'word.pdf'), 17)
} finally {
    if ($document) { $document.Close(0) }
    $word.Quit()
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($word) | Out-Null
}
Get-ChildItem -LiteralPath $Output -File | Where-Object Name -in 'word.docx','word.pdf' | Select-Object Name,Length
