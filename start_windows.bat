@echo off
setlocal
cd /d "%~dp0"
echo.
echo Global AI Mission Community - Local MVP
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  set "PY=py -3"
) else (
  set "PY=python"
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating Python virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 goto :failed
)
echo Installing dependencies (first run may need internet)...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed
echo.
echo Open your browser: http://127.0.0.1:8000
echo Press Ctrl+C to stop.
".venv\Scripts\python.exe" app.py
pause
exit /b 0
:failed
echo Could not start the application. Check Python 3.11+ and internet access.
pause
exit /b 1
