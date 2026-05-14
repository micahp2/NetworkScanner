# WinUI Prototype Local Stability Notes

This repository includes a WinUI 3 prototype project (`NetworkScanner.WinUIPrototype`) that has a compatibility mode for this machine.

## Why compatibility mode is enabled

On this environment, several page/window XAML files throw runtime `XamlParseException` despite successful compilation. To keep the prototype usable, startup shell and pages are constructed in C# code-behind instead of loading page/window XAML.

## What was changed

- `MainWindow.xaml` is excluded from page compilation and `MainWindow` UI is built in `MainWindow.xaml.cs`.
- `ScannerPage.xaml`, `SettingsPage.xaml`, and `FeatureMapPage.xaml` are excluded from page compilation.
- `ScannerPage.xaml.cs`, `SettingsPage.xaml.cs`, and `FeatureMapPage.xaml.cs` build UI trees directly in C#.
- Project uses self-contained defaults to avoid Windows App Runtime install prompts:
  - `SelfContained=true`
  - `WindowsAppSDKSelfContained=true`

## Recommended run command (local)

```powershell
$repo = "C:\Users\mstro\OneDrive\Documents\GitHub\NetworkScanner"
$proj = "$repo\NetworkScanner.WinUIPrototype\NetworkScanner.WinUIPrototype.csproj"
$out  = "C:\Temp\NetworkScannerWinUI"

Get-Process NetworkScanner.WinUIPrototype -ErrorAction SilentlyContinue | Stop-Process -Force

dotnet publish $proj -c Release -r win-x64 `
  /p:SelfContained=true `
  /p:WindowsAppSDKSelfContained=true `
  /p:WindowsPackageType=None `
  -o $out

& "$out\NetworkScanner.WinUIPrototype.exe"
```

## Future cleanup (optional)

When running on a machine where WinUI XAML parses reliably, these exclusions can be removed and pages can be restored to normal XAML-backed UI.
