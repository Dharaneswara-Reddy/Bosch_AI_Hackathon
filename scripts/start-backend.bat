@echo off
rem Starts the Guardian API on http://127.0.0.1:8000 (double-click, or run from any folder).
cd /d "%~dp0.."

docker info >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop is not running. Start Docker Desktop, wait until it says "running", then run this again.
  pause
  exit /b 1
)
if not exist ".env" (
  echo Missing .env in %CD%. Create it with GUARDIAN_LLM_PROVIDER, GUARDIAN_LLM_API_KEY and GITHUB_TOKEN.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment .venv ...
  py -3.11 -m venv .venv 2>nul || python -m venv .venv
)
call ".venv\Scripts\activate.bat"
python -c "import sys; sys.exit(sys.version_info < (3, 11))"
if errorlevel 1 (
  echo Python 3.11 or newer is required. Install it from https://www.python.org/downloads/ and delete the .venv folder.
  pause
  exit /b 1
)
echo Installing Python packages (first run takes a few minutes) ...
python -m pip install --quiet -e ".[dev]" -r Bosch_Guardian_Clean\backend\requirements.txt
if errorlevel 1 (
  echo Package installation failed, see the messages above.
  pause
  exit /b 1
)
cd Bosch_Guardian_Clean\backend
echo Backend starting on http://127.0.0.1:8000  (close this window to stop it)
python -m uvicorn app.main:app --port 8000
pause
