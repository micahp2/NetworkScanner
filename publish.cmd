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

set OUTDIR=%OUTROOT%\NetworkScanner-v%VERSION%
set ZIPFILE=%OUTROOT%\NetworkScanner-v%VERSION%-win-x64.zip

echo.
echo ============================================================
echo  NetworkScanner v%VERSION% - Release Build
echo ============================================================
echo.

echo [1/3] Publishing self-contained win-x64...
dotnet publish %CSPROJ% -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true ^
  -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o "%OUTDIR%"
if errorlevel 1 exit /b 1

echo.
echo [2/3] Zipping publish folder...
if exist "%ZIPFILE%" del "%ZIPFILE%"
powershell -NoProfile -Command "Compress-Archive -Path '%OUTDIR%\*' -DestinationPath '%ZIPFILE%'"
if errorlevel 1 exit /b 1

echo.
echo [3/3] Done.
echo   Artifact: %CD%\%ZIPFILE%
echo.
echo Optional: open GitHub release page for tag v%VERSION%
start https://github.com/%REPO%/releases/new?tag=v%VERSION%^&title=v%VERSION%

echo.
echo ============================================================
echo  Complete
echo ============================================================
echo.