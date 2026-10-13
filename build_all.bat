@echo off
setlocal
where pwsh >nul 2>nul
if errorlevel 1 (
    echo [ERROR] PowerShell 7 is required.
    exit /b 1
)
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0build.ps1" -Rebuild
exit /b %errorlevel%
