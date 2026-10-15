@echo off
rem Double-click to start Sift. Builds dist\sift.exe first if it's missing (needs Go).
cd /d "%~dp0"
if not exist "dist\sift.exe" call "scripts\build.cmd" || goto :failed
"dist\sift.exe" %*
exit /b %errorlevel%

:failed
echo.
echo Build failed. Install Go from https://go.dev/dl and try again.
pause
exit /b 1
