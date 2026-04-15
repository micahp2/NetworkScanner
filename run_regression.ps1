param(
  [string]$RepoRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$verifyScript = Join-Path $RepoRoot 'verify_regression_fixes.ps1'
$checklist = Join-Path $RepoRoot 'BUG_REGRESSION_CHECKLIST.md'
$outDir = Join-Path $RepoRoot 'artifacts\qa'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath = Join-Path $outDir ("regression_" + $ts + ".log")

"=== NetworkScanner Regression Runner ===" | Tee-Object -FilePath $logPath
("Timestamp: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) | Tee-Object -FilePath $logPath -Append
("RepoRoot: " + $RepoRoot) | Tee-Object -FilePath $logPath -Append
("Checklist: " + $checklist) | Tee-Object -FilePath $logPath -Append
("Verifier: " + $verifyScript) | Tee-Object -FilePath $logPath -Append
"" | Tee-Object -FilePath $logPath -Append

if (-not (Test-Path -LiteralPath $checklist)) {
  "[WARN] Checklist file not found: $checklist" | Tee-Object -FilePath $logPath -Append
}

if (-not (Test-Path -LiteralPath $verifyScript)) {
  "[FAIL] Verifier script not found: $verifyScript" | Tee-Object -FilePath $logPath -Append
  Write-Host "Regression log: $logPath"
  exit 1
}

"[info] Running verifier..." | Tee-Object -FilePath $logPath -Append
$verifyOutput = powershell -NoProfile -ExecutionPolicy Bypass -File $verifyScript -RepoRoot $RepoRoot 2>&1
$verifyOutput | Tee-Object -FilePath $logPath -Append
$verifyExit = $LASTEXITCODE

"" | Tee-Object -FilePath $logPath -Append
if ($verifyExit -eq 0) {
  "[PASS] Verification succeeded." | Tee-Object -FilePath $logPath -Append
} else {
  "[FAIL] Verification failed with exit code $verifyExit." | Tee-Object -FilePath $logPath -Append
}

("Manual QA checklist: " + $checklist) | Tee-Object -FilePath $logPath -Append
("Regression log: " + $logPath) | Tee-Object -FilePath $logPath -Append

Write-Host "Regression log: $logPath"
exit $verifyExit
