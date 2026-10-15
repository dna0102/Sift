@echo off
rem Builds dist\sift.exe (a single ~11 MB file; the web dashboard is embedded in it).
cd /d "%~dp0\.."

rem If sift.exe is in use (Sift is running), build to a temp name and swap it in when possible.
go build -ldflags "-s -w" -o dist\sift.exe .\cmd\sift 2>nul
if %errorlevel% == 0 goto :done

go build -ldflags "-s -w" -o dist\sift-new.exe .\cmd\sift || goto :failed
move /y dist\sift-new.exe dist\sift.exe >nul 2>nul
if exist dist\sift-new.exe (
  echo.
  echo Sift is currently running, so the exe couldn't be replaced yet.
  echo Close Sift and run this again, or the new build will be used next launch.
)

:done
exit /b 0

:failed
echo Build failed.
exit /b 1
