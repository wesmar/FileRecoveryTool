@echo off
setlocal enabledelayedexpansion

:: Find the latest VS installation (e.g. 2022, 2025, 2026)
set "vswhere=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%vswhere%" -latest -property installationPath`) do set "VS_PATH=%%i"

if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo [ERROR] Could not find vcvarsall.bat
    exit /b
)

:: Initialize build environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64

:: Clean old exe files before starting
if exist bin del /q bin\*.exe

:: Sequential build of all 4 configurations
echo Building: FRT_x64 (Static CRT)...
msbuild kvc_recovery.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild /m /nologo
echo Building: FRT_x86 (Static CRT)...
msbuild kvc_recovery.vcxproj /p:Configuration=Release /p:Platform=Win32 /t:Rebuild /m /nologo
echo Building: FRT_x64_minSize (Dynamic CRT)...
msbuild kvc_recovery.vcxproj /p:Configuration=Release_MinSize /p:Platform=x64 /t:Rebuild /m /nologo
echo Building: FRT_x86_minSize (Dynamic CRT)...
msbuild kvc_recovery.vcxproj /p:Configuration=Release_MinSize /p:Platform=Win32 /t:Rebuild /m /nologo

:: Clean up temporary files (obj)
echo.
echo Cleaning temporary obj folder...
if exist obj rd /s /q obj

echo.
echo Success! Files are in the bin folder:
dir /b bin\*.exe
