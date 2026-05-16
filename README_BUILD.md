# Build & Safety Runbook (PM-Friendly)

This repo supports **two UI paths** on purpose:

- **WPF (stable release path):** `NetworkScanner.csproj`
- **WinUI (preview/migration path):** `NetworkScanner.WinUIPrototype/NetworkScanner.WinUIPrototype.csproj`

## Quick usage

From repo root:

- Build everything safely:
  - `./scripts/build-safe.ps1`
- Build only stable WPF:
  - `./scripts/build-safe.ps1 -WpfOnly`
- Build only WinUI preview:
  - `./scripts/build-safe.ps1 -WinUiOnly`

## If WinUI fails

1. Continue shipping WPF builds:
   - `dotnet build ./NetworkScanner.csproj`
2. Log the WinUI issue and continue migration in preview branch.
3. Do not block releases on WinUI until parity is approved.

## If both fail

1. Verify SDK:
   - `dotnet --version` (expected .NET 8.x)
2. Re-run safe script:
   - `./scripts/build-safe.ps1`
3. If you see Appx/Pri task errors, verify Visual Studio Build Tools WinUI/MSIX components are installed.

## Release policy

- Stable channel: **WPF**
- Preview channel: **WinUI**
- Migration completes only after explicit parity signoff.

## Release-safe script

Use this when you want to protect the stable release path:

- Default (WPF required, WinUI non-blocking):
  - `./scripts/release-safe.ps1`
- Skip WinUI entirely:
  - `./scripts/release-safe.ps1 -SkipWinUi`
- Require WinUI pass (strict mode):
  - `./scripts/release-safe.ps1 -RequireWinUi`

Behavior:
- If WPF fails: script fails.
- If WinUI fails: script still succeeds unless `-RequireWinUi` is set.

## WinUI quality-of-life

- Window placement persistence: WinUI now restores last size/position between launches.
