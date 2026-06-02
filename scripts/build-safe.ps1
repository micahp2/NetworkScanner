param(
  [switch]$WpfOnly,
  [switch]$WinUiOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Step([string]$msg) {
  Write-Host ""
  Write-Host "==> $msg" -ForegroundColor Cyan
}

function Run([string]$cmd) {
  Write-Host "   $cmd" -ForegroundColor DarkGray
  Invoke-Expression $cmd
}

Step "SDK check"
dotnet --version

if (-not $WinUiOnly) {
  Step "Build WPF (stable path)"
  Run ('dotnet build "' + (Join-Path $repo 'NetworkScanner.csproj') + '"')
}

if (-not $WpfOnly) {
  Step "Build WinUI (preview path)"
  Run ('dotnet build "' + (Join-Path $repo 'NetworkScanner.WinUIPrototype\NetworkScanner.WinUIPrototype.csproj') + '"')
}

if (-not $WpfOnly -and -not $WinUiOnly) {
  Step "Build full solution"
  Run ('dotnet build "' + (Join-Path $repo 'networkscanner.sln') + '"')
}

Step "Done"
Write-Host "Both UI paths are preserved. If WinUI fails, WPF remains shippable." -ForegroundColor Green
