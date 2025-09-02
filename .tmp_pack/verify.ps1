Param()
$ErrorActionPreference = 'Stop'
Write-Host 'Verifying sample receipts...'
$receipts = Get-ChildItem -Recurse -Filter *.json receipts | Where-Object { $_.Name -ne 'sth.json' }
$sample = $receipts | Get-Random -Count ([Math]::Min(5, $receipts.Count))
$fails = 0
foreach ($r in $sample) {
  $out = python -m signet_cli verify-receipt $r.FullName | Out-String
  if ($out -match 'True') { Write-Host "[OK] $($r.Name)" } else { Write-Host "[FAIL] $($r.Name)"; $fails++ }
}
$sth = Join-Path 'receipts' (Get-Date -Format 'yyyy-MM-dd') 'sth.json'
if (Test-Path $sth) { Write-Host "STH present: $sth" }
Write-Host "Failures: $fails"; if ($fails -eq 0) { Write-Host PASS } else { Write-Host FAIL; exit 1 }
