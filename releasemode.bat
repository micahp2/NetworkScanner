@echo off
setlocal

set VERSION=1.0.1
set OUTDIR=publish

echo === Committing source ===
git add -A
git commit -m "v%VERSION%"
git push origin main

echo === Building framework-dependent ===
dotnet publish -c Release -r win-x64 --self-contained false ^
  -p:PublishSingleFile=true -p:DebugType=none ^
  -o %OUTDIR%\framework-dependent

echo === Building self-contained ===
dotnet publish -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true ^
  -p:DebugType=none ^
  -o %OUTDIR%\self-contained

echo === Zipping ===
powershell Compress-Archive -Force ^
  -Path %OUTDIR%\framework-dependent\NetworkScanner.exe ^
  -DestinationPath %OUTDIR%\NetworkScanner-v%VERSION%-win-x64-requires-dotnet8.zip

powershell Compress-Archive -Force ^
  -Path %OUTDIR%\self-contained\NetworkScanner.exe ^
  -DestinationPath %OUTDIR%\NetworkScanner-v%VERSION%-win-x64-standalone.zip

echo === Creating GitHub release ===
gh release create v%VERSION% ^
  "%OUTDIR%\NetworkScanner-v%VERSION%-win-x64-standalone.zip" ^
  "%OUTDIR%\NetworkScanner-v%VERSION%-win-x64-requires-dotnet8.zip" ^
  --title "v%VERSION%" ^
  --notes "See README for full changelog." ^
  --repo micahp2/NetworkScanner

echo === Done ===