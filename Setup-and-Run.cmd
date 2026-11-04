@echo off
setlocal
cd /d "%~dp0"
echo Sentinel Lab - automatic local setup and launch
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\bootstrap-client.ps1"
set "sentinelExit=%ERRORLEVEL%"
if "%sentinelExit%"=="3010" echo Restart Windows, then double-click this file again.
if not "%sentinelExit%"=="0" echo Setup stopped. Read the message above; completed steps are retained.
pause
exit /b %sentinelExit%
