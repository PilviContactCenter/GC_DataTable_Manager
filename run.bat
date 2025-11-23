@echo off
TITLE Genesys Cloud Data Table Manager
echo ========================================================
echo   Genesys Cloud Data Table Manager - Startup Script
echo ========================================================

cd /d "%~dp0"

REM 1. Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found. Please install Python 3.x and add it to your PATH.
    pause
    exit /b 1
)

REM 2. Create Virtual Environment if missing
if not exist "venv" (
    echo [INFO] First time setup: Creating virtual environment...
    python -m venv venv
)

REM 3. Activate Virtual Environment
call venv\Scripts\activate

REM 4. Install Dependencies
echo [INFO] Checking and installing dependencies...
pip install -r requirements.txt >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Failed to install dependencies silently. Retrying with output...
    pip install -r requirements.txt
)

REM 5. Start Application
echo.
echo [INFO] Starting Application...
echo [INFO] The browser will open automatically.
echo.
echo Press Ctrl+C to stop the server.
echo.

REM Open Browser in a separate process after 2 seconds
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000

REM Run Flask App
python app.py

pause
