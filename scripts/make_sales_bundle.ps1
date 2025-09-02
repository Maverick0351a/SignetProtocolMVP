param(
  [string]$CompliancePackPath = "./dist/compliance_pack.zip",
  [string]$Out = "./dist/sales_bundle.zip"
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $CompliancePackPath)) {
  Write-Host "Compliance pack not found at $CompliancePackPath. Build it first (python -m signet_cli build-compliance-pack)." -ForegroundColor Red
  exit 1
}

if (-not (Test-Path ./docs/ONEPAGER.md)) {
  Write-Host "docs/ONEPAGER.md missing" -ForegroundColor Red
  exit 1
}

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null

$zipTemp = Join-Path ([System.IO.Path]::GetTempPath()) ("sales_bundle_" + [System.Guid]::NewGuid().ToString() + ".zip")
if (Test-Path $zipTemp) { Remove-Item $zipTemp -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem

# Create new zip
[System.IO.Compression.ZipFile]::Open($zipTemp, 'Create').Dispose()

# Helper to add file
function Add-ToZip($zipPath, $filePath, $entryName) {
  $mode = [System.IO.Compression.ZipArchiveMode]::Update
  $zip = [System.IO.Compression.ZipFile]::Open($zipPath, $mode)
  try {
    $entry = $zip.CreateEntry($entryName)
    $stream = $entry.Open()
    try {
      [byte[]]$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $filePath))
      $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
  } finally { $zip.Dispose() }
}

Add-ToZip $zipTemp ./docs/ONEPAGER.md ONEPAGER.md
Add-ToZip $zipTemp $CompliancePackPath compliance_pack.zip

Move-Item -Force $zipTemp $Out
Write-Host "Wrote sales bundle to $Out" -ForegroundColor Green
