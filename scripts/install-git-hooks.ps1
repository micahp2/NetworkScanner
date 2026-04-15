param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $RepoRoot

git config core.hooksPath .githooks
Write-Host "[PASS] Git hooks path set to .githooks"
Write-Host "[info] Hook file: .githooks/pre-commit"
