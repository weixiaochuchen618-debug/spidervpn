@echo off
setlocal
set "HERE=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%install\install.ps1" -SourceDir "%HERE%" %*
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo   Install failed, exit code %RC%. Read the messages above.
pause
exit /b %RC%
