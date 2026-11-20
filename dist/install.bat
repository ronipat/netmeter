@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "RC=%errorlevel%"
if %RC% neq 0 (
    echo Install failed with exit code %RC%.
    pause
)
exit /b %RC%
