param(
  [switch]$SkipWinUi,
  [switch]$RequireWinUi,
  [switch]$NoRestore
)

$ErrorActionPreference = 'Stop'

function Resolve-RepoRoot {
  param([string]$scriptRoot)

  try {
    $top = (& git -C $scriptRoot rev-parse --show-toplevel 2>$null)
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($top)) {
      return $top.Trim()
    }
  }
  catch {}

  return (Split-Path -Parent $scriptRoot)
}

$repo = Resolve-RepoRoot -scriptRoot $PSScriptRoot

function Step([string]$msg) {
  Write-Host ""
  Write-Host ("==> " + $msg) -ForegroundColor Cyan
}

Push-Location $repo
try {
  Step "SDK"
  & dotnet --version

  Step "Build WPF (stable release path)"
  $wpfProj = Join-Path $repo 'NetworkScanner.csproj'
  if ($NoRestore) { & dotnet build $wpfProj --no-restore } else { & dotnet build $wpfProj }
  $wpfCode = [int]$LASTEXITCODE
  if ($wpfCode -ne 0) {
    Write-Host "WPF build failed. Stopping release-safe script." -ForegroundColor Red
    exit $wpfCode
  }
  Write-Host "WPF build passed." -ForegroundColor Green

  if (-not $SkipWinUi) {
    Step "Build WinUI (preview path)"
    $winuiProj = Join-Path $repo 'NetworkScanner.WinUIPrototype\NetworkScanner.WinUIPrototype.csproj'
    if ($NoRestore) { & dotnet build $winuiProj --no-restore } else { & dotnet build $winuiProj }
    $winuiCode = [int]$LASTEXITCODE

    if ($winuiCode -ne 0) {
      if ($RequireWinUi) {
        Write-Host "WinUI build failed and -RequireWinUi was set. Failing script." -ForegroundColor Red
        exit $winuiCode
      }

      Write-Host "WinUI build failed, but stable WPF build succeeded." -ForegroundColor Yellow
      Write-Host "Release-safe policy: do NOT block stable release on WinUI preview failures." -ForegroundColor Yellow
      exit 0
    }

    Write-Host "WinUI build passed." -ForegroundColor Green
  }
  else {
    Step "Skipping WinUI build by request (-SkipWinUi)"
  }

  Step "Release-safe build complete"
  Write-Host "Stable path (WPF) is healthy." -ForegroundColor Green
  exit 0
}
finally {
  Pop-Location
}
