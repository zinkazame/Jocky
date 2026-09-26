@echo off
REM build_agent.bat -- Package JOCKY agent into standalone .exe
REM Run from D:\Dinku\projects\JOCKY\
REM Requires: pip install pyinstaller cryptography

echo [*] JOCKY Agent Builder
echo [*] Packaging agent\main.py into standalone .exe
echo.

set ROOT=%~dp0
if not exist "%ROOT%agent\main.py" (
    echo [-] agent\main.py not found -- run from project root
    exit /b 1
)

REM install deps if needed
pip install pyinstaller cryptography pywin32 --break-system-packages --quiet

echo [*] Running PyInstaller...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name jocky_agent ^
    --add-data "agent\collector.py;." ^
    --hidden-import winreg ^
    --hidden-import win32evtlog ^
    --hidden-import win32evtlogutil ^
    --hidden-import pywintypes ^
    --hidden-import cryptography ^
    --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
    agent\main.py

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] BUILD SUCCESS
    echo [+] Output: dist\jocky_agent.exe
    echo.
    echo [+] Deploy to target:
    echo     1. Copy dist\jocky_agent.exe to target machine
    echo     2. Run as Admin:
    echo        jocky_agent.exe --c2 http://^<INVESTIGATOR_IP^>:8000 --interval 60
    echo     3. Or install as service:
    echo        sc create JockyAgent binPath= "jocky_agent.exe --c2 http://^<IP^>:8000" start= auto
    echo        sc start JockyAgent
) else (
    echo [-] BUILD FAILED
)
