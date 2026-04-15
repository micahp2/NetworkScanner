@echo off
setlocal

set CSPROJ=NetworkScanner.csproj
set OUTROOT=publish
set REPO=micahp2/NetworkScanner

for /f "usebackq delims=" %%V in (`powershell -NoProfile -Command "(Select-Xml -Path '%CSPROJ%' -XPath '//Project/PropertyGroup/Version/text()').Node.Value"`) do set VERSION=%%V

if not defined VERSION (
  echo [ERROR] Could not read Version from %CSPROJ%
  exit /b 1
)

set FD_DIR=%OUTROOT%\framework-dependent-v%VERSION%
set SC_DIR=%OUTROOT%\self-contained-v%VERSION%
set FD_ZIP=%OUTROOT%\NetworkScanner-v%VERSION%-win-x64-requires-dotnet8.zip
set SC_ZIP=%OUTROOT%\NetworkScanner-v%VERSION%-win-x64-standalone.zip

echo === Version: v%VERSION% ===

echo === Building framework-dependent ===
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained false ^
  -p:PublishSingleFile=true ^
  -p:DebugType=none ^
  -o "%FD_DIR%"
if errorlevel 1 exit /b 1

echo === Building self-contained ===
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o "%SC_DIR%"
if errorlevel 1 exit /b 1

echo === Zipping output folders ===
if exist "%FD_ZIP%" del "%FD_ZIP%"
if exist "%SC_ZIP%" del "%SC_ZIP%"

powershell -NoProfile -Command "Compress-Archive -Path '%FD_DIR%\*' -DestinationPath '%FD_ZIP%'"
if errorlevel 1 exit /b 1

powershell -NoProfile -Command "Compress-Archive -Path '%SC_DIR%\*' -DestinationPath '%SC_ZIP%'"
if errorlevel 1 exit /b 1

echo === Artifacts ===
echo   %CD%\%FD_ZIP%
echo   %CD%\%SC_ZIP%

echo === Creating GitHub release via gh (if available) ===
where gh >nul 2>nul
if errorlevel 1 (
  echo [WARN] gh not found in PATH. Create release manually:
  echo        https://github.com/%REPO%/releases/new?tag=v%VERSION%^&title=v%VERSION%
  exit /b 0
)

gh release create v%VERSION% ^
  "%SC_ZIP%" ^
  "%FD_ZIP%" ^
  --title "v%VERSION%" ^
  --notes "See README and changelog for release notes." ^
  --repo %REPO%

if errorlevel 1 (
  echo [ERROR] gh release create failed.
  exit /b 1
)

echo === Done ===