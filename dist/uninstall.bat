@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
set "RC=%errorlevel%"
if %RC% neq 0 (
    echo Uninstall failed with exit code %RC%.
    pause
)
exit /b %RC%
