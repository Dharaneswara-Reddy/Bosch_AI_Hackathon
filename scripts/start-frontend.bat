@echo off
rem Starts the Guardian UI on http://127.0.0.1:5173 (start the backend first).
cd /d "%~dp0..\Bosch_Guardian_Clean\frontend"

where npm >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Install the LTS version from https://nodejs.org/ and run this again.
  pause
  exit /b 1
)
if not exist "node_modules" (
  echo Installing UI packages, first run only ...
  call npm install
  if errorlevel 1 (
    echo npm install failed, see the messages above.
    pause
    exit /b 1
  )
)
echo UI starting: open http://127.0.0.1:5173 in your browser  (close this window to stop it)
call npm run dev
pause
