@echo off
REM MalGuard — Fileless Malware Detection Dashboard
REM Run this once to set up and launch. Works on Windows 10/11.

cd /d "%~dp0"

REM ── Python check ──────────────────────────────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.9+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM ── Virtual environment ───────────────────────────────────────────────────
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

REM ── Dependencies ──────────────────────────────────────────────────────────
echo Installing dependencies...
pip install -q -r requirements.txt

REM ── Model check ───────────────────────────────────────────────────────────
if not exist models\fileless_detector.pkl (
    echo No trained model found. Training now, please wait...
    python main.py
)

REM ── Launch ────────────────────────────────────────────────────────────────
echo.
echo   ==========================================
echo    MalGuard SOC Dashboard
echo    Open http://localhost:5000 in your browser
echo    Press Ctrl+C to stop
echo   ==========================================
echo.

start "" "http://localhost:5000"
python app.py
pause
