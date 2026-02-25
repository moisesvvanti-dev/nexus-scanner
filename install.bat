@echo off
echo ===================================================
echo     PentestGPT Auto-Installer Options Builder
echo ===================================================
echo.
echo [*] Checking for Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH!
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

echo [*] Upgrading pip...
python -m pip install --upgrade pip

echo [*] Installing dependencies from requirements.txt...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [!] Failed to install dependencies! Please check requirements.txt
    pause
    exit /b 1
)

echo [*] Installing Playwright browsers...
playwright install
if %errorlevel% neq 0 (
    echo [!] Failed to install Playwright internal browsers!
)

echo.
echo ===================================================
echo   Installation Completed Successfully!
echo ===================================================
echo You can now start the application by running main.py
pause
