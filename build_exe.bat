@echo off
cd /d "%~dp0"

echo.
echo [1/3] Checking Python...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not on PATH.
    echo Install from https://www.python.org/downloads/ and tick
    echo "Add python.exe to PATH" during setup.
    pause
    exit /b 1
)

echo.
echo [2/3] Installing PyInstaller (needs internet the first time)...
python -m pip install --upgrade pip
python -m pip install pyinstaller
if errorlevel 1 (
    echo ERROR: Could not install PyInstaller.
    pause
    exit /b 1
)

echo.
echo [3/3] Building the GUI .exe with the snake icon...
REM  --windowed   = no black console window (GUI app)
REM  --icon       = snake icon on the .exe file itself
REM  --add-data   = bundle the icons so the title bar/taskbar show the snake
python -m PyInstaller --onefile --windowed --name Parseltongue --icon snake.ico --add-data "snake.ico;." --add-data "snake.png;." Parseltongue.py
if errorlevel 1 (
    echo ERROR: Build failed.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  DONE! Your GUI program is here:
echo     dist\Parseltongue.exe
echo ============================================================
echo.
pause
