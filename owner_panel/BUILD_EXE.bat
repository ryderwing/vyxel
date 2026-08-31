@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
if errorlevel 1 pause & exit /b 1
python -m PyInstaller --noconfirm --clean --windowed --onefile --name PentestHubOwner main.py
if errorlevel 1 pause & exit /b 1
echo Built: dist\PentestHubOwner.exe
pause
