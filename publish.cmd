@echo off
setlocal

set VERSION=1.0.0
set OUTDIR=publish
set REPO=micahp2/NetworkScanner
set CSPROJ=NetworkScanner.csproj

echo.
echo ============================================================
echo  Network Scanner v%VERSION% — Release Build
echo ============================================================
echo.

:: ── Commit and push source ──────────────────────────────────────────────────
echo [1/5] Committing and pushing source...
git add -A
git commit -m "v%VERSION%"
git push origin main
echo.

:: ── Framework-dependent build ────────────────────────────────────────────────
echo [2/5] Building framework-dependent (requires .NET 8 runtime)...
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained false ^
  -p:PublishSingleFile=true ^
  -p:DebugType=none ^
  -o %OUTDIR%\framework-dependent
echo.

:: ── Self-contained build ─────────────────────────────────────────────────────
echo [3/5] Building self-contained single file (no prerequisites)...
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o %OUTDIR%\self-contained
echo.

:: ── Zip ──────────────────────────────────────────────────────────────────────
echo [4/5] Zipping...
powershell -NoProfile -Command ^
  "Compress-Archive -Force -Path '%OUTDIR%\framework-dependent\NetworkScanner.exe' -DestinationPath '%OUTDIR%\NetworkScanner-v%VERSION%-win-x64-requires-dotnet8.zip'"

powershell -NoProfile -Command ^
  "Compress-Archive -Force -Path '%OUTDIR%\self-contained\NetworkScanner.exe' -DestinationPath '%OUTDIR%\NetworkScanner-v%VERSION%-win-x64-standalone.zip'"
echo.

:: ── Open GitHub new-release page ─────────────────────────────────────────────
echo [5/5] Opening GitHub releases page...
echo.
echo   Upload these two files:
echo     %CD%\%OUTDIR%\NetworkScanner-v%VERSION%-win-x64-standalone.zip
echo     %CD%\%OUTDIR%\NetworkScanner-v%VERSION%-win-x64-requires-dotnet8.zip
echo.
echo   Tag:   v%VERSION%
echo   Title: v%VERSION%
echo.
start https://github.com/%REPO%/releases/new?tag=v%VERSION%^&title=v%VERSION%

echo ============================================================
echo  Done. Attach the zip files on the GitHub page that just opened.
echo ============================================================
echo.
