@echo off
setlocal

set CSPROJ=NetworkScanner.csproj
set WINUI_CSPROJ=NetworkScanner.WinUIPrototype\NetworkScanner.WinUIPrototype.csproj
set OUTROOT=publish
set REPO=micahp2/NetworkScanner

for /f "usebackq delims=" %%V in (`powershell -NoProfile -Command "(Select-Xml -Path '%CSPROJ%' -XPath '//Project/PropertyGroup/Version/text()').Node.Value"`) do set VERSION=%%V

if not defined VERSION (
  echo [ERROR] Could not read Version from %CSPROJ%
  exit /b 1
)

set WPF_OUTDIR=%OUTROOT%\NetworkScanner-v%VERSION%
set WPF_ZIPFILE=%OUTROOT%\NetworkScanner-v%VERSION%-win-x64.zip

set WINUI_OUTDIR=%OUTROOT%\NetworkScanner.WinUIPrototype-v%VERSION%-win-x64
set WINUI_ZIPFILE=%OUTROOT%\NetworkScanner.WinUIPrototype-v%VERSION%-win-x64.zip

echo.
echo ============================================================
echo  NetworkScanner v%VERSION% - Release Build (WPF and WinUI)
echo ============================================================
echo.

:: Clean previous build dirs and zips to avoid stale files
if exist "%WPF_OUTDIR%" rd /s /q "%WPF_OUTDIR%"
if exist "%WINUI_OUTDIR%" rd /s /q "%WINUI_OUTDIR%"
if exist "%WPF_ZIPFILE%" del "%WPF_ZIPFILE%"
if exist "%WINUI_ZIPFILE%" del "%WINUI_ZIPFILE%"

echo [1/4] Publishing self-contained WPF win-x64...
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o "%WPF_OUTDIR%"
if errorlevel 1 exit /b 1

echo.
echo [2/4] Publishing self-contained WinUI 3 win-x64...
dotnet publish %WINUI_CSPROJ% -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o "%WINUI_OUTDIR%"
if errorlevel 1 exit /b 1

echo.
echo [3/4] Packaging single-executable ZIP files...
powershell -NoProfile -Command "Compress-Archive -Path '%WPF_OUTDIR%\NetworkScanner.exe' -DestinationPath '%WPF_ZIPFILE%'"
if errorlevel 1 exit /b 1

powershell -NoProfile -Command "Compress-Archive -Path '%WINUI_OUTDIR%\NetworkScanner.WinUIPrototype.exe' -DestinationPath '%WINUI_ZIPFILE%'"
if errorlevel 1 exit /b 1

echo.
echo [4/4] Done.
echo   WPF Release:   %CD%\%WPF_ZIPFILE%
echo   WinUI Release: %CD%\%WINUI_ZIPFILE%
echo.
echo Optional: open GitHub release page for tag v%VERSION%
start https://github.com/%REPO%/releases/new?tag=v%VERSION%^&title=v%VERSION%

echo.
echo ============================================================
echo  Complete
echo ============================================================
echo.