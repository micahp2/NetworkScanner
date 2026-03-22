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
echo [1/4] Committing and pushing source...
git add -A
git commit -m "v%VERSION%"
git push origin main
echo.

:: ── Self-contained build ─────────────────────────────────────────────────────
:: WPF apps always require several native DLLs alongside the exe
:: (wpfgfx_cor3.dll, PresentationNative_cor3.dll, D3DCompiler_47_cor3.dll,
::  PenImc_cor3.dll, vcruntime140_cor3.dll) — PublishSingleFile cannot bundle
:: unmanaged DLLs, so we zip the entire output folder instead of just the exe.
:: Self-contained means no .NET runtime installation required on the target PC.
echo [2/4] Building self-contained release...
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o %OUTDIR%\NetworkScanner-v%VERSION%
echo.

:: ── Zip the whole folder ─────────────────────────────────────────────────────
echo [3/4] Zipping output folder...
set ZIPFILE=%OUTDIR%\NetworkScanner-v%VERSION%-win-x64.zip

:: Remove previous zip if it exists
if exist "%ZIPFILE%" del "%ZIPFILE%"

powershell -NoProfile -Command ^
  "Compress-Archive -Path '%OUTDIR%\NetworkScanner-v%VERSION%\*' -DestinationPath '%ZIPFILE%'"

echo.
echo   Created: %CD%\%ZIPFILE%
echo.

:: ── Open GitHub new-release page ─────────────────────────────────────────────
echo [4/4] Opening GitHub releases page...
echo.
echo   Upload this file on the page that opens:
echo     %CD%\%ZIPFILE%
echo.
echo   Tag:   v%VERSION%
echo   Title: v%VERSION%
echo   Note:  "Extract the zip and run NetworkScanner.exe. No installation required."
echo.
start https://github.com/%REPO%/releases/new?tag=v%VERSION%^&title=v%VERSION%

echo ============================================================
echo  Done.
echo ============================================================
echo.
