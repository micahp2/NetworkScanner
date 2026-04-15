param(
  [string]$RepoRoot = "."
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $RepoRoot

Write-Host "[info] RepoRoot: $(Get-Location)"

$checks = @(
  @{ Name = "ScanResult has FirstSeen"; Path = "models/ScanResult.cs"; Pattern = "FirstSeen" },
  @{ Name = "ScanResult has LastSeen"; Path = "models/ScanResult.cs"; Pattern = "LastSeen" },
  @{ Name = "NetworkScannerService sets FirstSeen"; Path = "services/NetworkScannerService.cs"; Pattern = "FirstSeen\s*=\s*now" },
  @{ Name = "NetworkScannerService sets LastSeen"; Path = "services/NetworkScannerService.cs"; Pattern = "LastSeen\s*=\s*now" },
  @{ Name = "BuildCandidateList exists"; Path = "services/NetworkScannerService.cs"; Pattern = "BuildCandidateList\(" },
  @{ Name = "MainWindow AddResultToGrid exists"; Path = "MainWindow.xaml.cs"; Pattern = "AddResultToGrid\(" },
  @{ Name = "MainWindow updates LastSeen"; Path = "MainWindow.xaml.cs"; Pattern = "LastSeen\s*=\s*now" },
  @{ Name = "MainWindow preserves FirstSeen"; Path = "MainWindow.xaml.cs"; Pattern = "FirstSeen\s*\?\?=" },
  @{ Name = "MainWindow persists device"; Path = "MainWindow.xaml.cs"; Pattern = "UpsertDeviceAsync\(" },
  @{ Name = "Ports default only when blank"; Path = "MainWindow.xaml.cs"; Pattern = "IsNullOrWhiteSpace\(PortsText\.Text\)" },
  @{ Name = "DB upsert exists"; Path = "services/DatabaseService.cs"; Pattern = "UpsertDeviceAsync\(" },
  @{ Name = "DB MAC normalization"; Path = "services/DatabaseService.cs"; Pattern = "Replace\(':', '-'\)" },
  @{ Name = "DB conflict update on MAC"; Path = "services/DatabaseService.cs"; Pattern = "ON CONFLICT\(MacAddress\)" },
  @{ Name = "DB preserves FirstSeen"; Path = "services/DatabaseService.cs"; Pattern = "COALESCE\(Devices\.FirstSeen, excluded\.FirstSeen\)" }
)

$failed = @()
foreach ($c in $checks) {
  if (-not (Test-Path -LiteralPath $c.Path)) {
    Write-Host "[FAIL] $($c.Name) -> file not found: $($c.Path)"
    $failed += $c.Name
    continue
  }

  $hit = Select-String -Path $c.Path -Pattern $c.Pattern -AllMatches -ErrorAction SilentlyContinue
  if ($hit) {
    Write-Host "[PASS] $($c.Name)"
  } else {
    Write-Host "[FAIL] $($c.Name)"
    $failed += $c.Name
  }
}

Write-Host ""
Write-Host "[info] Running dotnet build..."
$buildOutput = dotnet build
$buildOk = $LASTEXITCODE -eq 0
if ($buildOk) { Write-Host "[PASS] dotnet build" } else { Write-Host "[FAIL] dotnet build" }

Write-Host ""
Write-Host "========== SUMMARY =========="
Write-Host "Checks failed: $($failed.Count)"
if ($failed.Count -gt 0) { $failed | ForEach-Object { Write-Host " - $_" } }
Write-Host "Build passed: $buildOk"

if ($failed.Count -gt 0 -or -not $buildOk) { exit 1 }
exit 0
