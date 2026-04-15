param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $RepoRoot
Write-Host "[info] RepoRoot: $(Get-Location)"

if (Get-Command python -ErrorAction SilentlyContinue) {
  & python scripts/check_encoding.py
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
  & py -3 scripts/check_encoding.py
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
  throw 'Python not found (python/py)'
}

exit 0
